use fstool::{
    block::MemoryBackend,
    fs::hfs_plus::{FormatOpts, HfsPlus},
};
use hfs_bridge::{
    volume,
    windows::{Adapter, Status},
};
use std::io::{Read, Write};
#[path = "support/fault_disk.rs"]
mod fault;
use fault::Disk;

fn fixture(journaled: bool, hfsx: bool) -> Vec<u8> {
    let mut disk = MemoryBackend::new(8 * 1024 * 1024);
    let mut fs = HfsPlus::format(
        &mut disk,
        &FormatOpts {
            journaled,
            volume_name: "Original Label".into(),
            ..Default::default()
        },
    )
    .unwrap();
    if hfsx {
        drop(fs);
        let mut bytes = disk.into_bytes();
        let alternate = bytes.len() - 1024;
        for offset in [1024, alternate] {
            bytes[offset..offset + 2].copy_from_slice(b"HX");
            bytes[offset + 2..offset + 4].copy_from_slice(&5u16.to_be_bytes());
        }
        let catalog = volume::be32(&bytes, 1312) as usize * 4096;
        bytes[catalog + 51] = 0xbc;
        disk = MemoryBackend::from_bytes(bytes);
        fs = HfsPlus::open(&mut disk).unwrap();
    }
    fs.create_file(
        &mut disk,
        "/payload.txt",
        &mut &b"Volume label payload\n"[..],
        21,
        0o640,
        501,
        20,
        1_700_000_000,
    )
    .unwrap();
    fs.flush(&mut disk).unwrap();
    disk.into_bytes()
}

fn contents(fs: &HfsPlus, disk: &mut MemoryBackend) -> Vec<u8> {
    let mut data = Vec::new();
    fs.open_file_reader(disk, "/payload.txt")
        .unwrap()
        .read_to_end(&mut data)
        .unwrap();
    data
}

#[test]
fn labels_persist_on_all_three_formats_without_changing_root_metadata_or_files() {
    for (journaled, hfsx, kind) in [
        (false, false, "plain"),
        (true, false, "journaled"),
        (true, true, "hfsx"),
    ] {
        let mut disk = MemoryBackend::from_bytes(fixture(journaled, hfsx));
        let fs = HfsPlus::open(&mut disk).unwrap();
        let root = fs.catalog_record_cnid(2).unwrap();
        let file = fs.catalog_record("/payload.txt").unwrap();
        let data = contents(&fs, &mut disk);
        drop(fs);
        let mut adapter = Adapter::from_device(disk).unwrap();
        adapter.set_volume_label("Bridge Café").unwrap();
        assert_eq!(adapter.volume_info().unwrap().label, "Bridge Cafe\u{301}");
        let mut disk = adapter.shutdown().unwrap();
        let fs = HfsPlus::open(&mut disk).unwrap();
        assert_eq!(fs.volume_name(), "Bridge Cafe\u{301}");
        assert_eq!(fs.catalog_path(2).unwrap(), "/");
        let mut expected_root = root.clone();
        expected_root[3] |= 4; // Label publication adds the root generation attribute.
        assert_eq!(fs.catalog_record_cnid(2).unwrap(), expected_root);
        assert_eq!(fs.catalog_record("/payload.txt").unwrap(), file);
        assert_eq!(contents(&fs, &mut disk), data);
        drop(fs);
        let before = disk.as_slice().to_vec();
        let mut adapter = Adapter::from_device(disk).unwrap();
        adapter.set_volume_label("Bridge Café").unwrap();
        let disk = adapter.shutdown().unwrap();
        assert_eq!(disk.as_slice(), before, "unchanged label rewrote {kind}");
        if let Some(directory) = std::env::var_os("HFS_LABEL_ARTIFACT_DIR") {
            let path = std::path::Path::new(&directory).join(format!("label-{kind}.img"));
            let mut out = std::fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(path)
                .unwrap();
            out.write_all(disk.as_slice()).unwrap();
            out.sync_all().unwrap();
        }
    }
}

#[test]
fn invalid_labels_never_modify_disk_and_leave_adapter_usable() {
    let original = fixture(true, false);
    let mut adapter = Adapter::from_device(MemoryBackend::from_bytes(original.clone())).unwrap();
    for label in [
        "",
        "a/b",
        "a:b",
        "a\\b",
        "bad*name",
        "bad?name",
        "bad\"name",
        "bad<name",
        "bad>name",
        "bad|name",
        "bad\nname",
        "\u{ffff}",
        &"x".repeat(33),
        &"é".repeat(17),
        &"🚢".repeat(17),
    ] {
        assert!(
            adapter.set_volume_label(label).is_err(),
            "accepted {label:?}"
        );
        assert_eq!(adapter.volume_info().unwrap().label, "Original Label");
        assert!(adapter.failure().is_none());
    }
    assert_eq!(adapter.shutdown().unwrap().as_slice(), original);
}

#[test]
fn maximum_label_and_case_only_change_preserve_exact_unicode() {
    let mut adapter =
        Adapter::from_device(MemoryBackend::from_bytes(fixture(true, false))).unwrap();
    let label = "🚢".repeat(16);
    adapter.set_volume_label(&label).unwrap();
    assert_eq!(adapter.volume_info().unwrap().label, label);
    adapter.set_volume_label("bridge").unwrap();
    adapter.set_volume_label("BRIDGE").unwrap();
    let mut disk = adapter.shutdown().unwrap();
    assert_eq!(HfsPlus::open(&mut disk).unwrap().volume_name(), "BRIDGE");
}

fn attempt(bytes: &[u8], fail: Option<usize>) -> (bool, Disk) {
    let disk = Disk::new(bytes);
    let mut adapter = Adapter::from_device(disk.clone()).unwrap();
    disk.arm(fail);
    let ok = adapter.set_volume_label("Renamed Volume").is_ok();
    if !ok {
        let calls = disk.0.lock().unwrap().calls;
        assert_eq!(
            adapter.volume_info().unwrap_err().status,
            Status::FailedVolume
        );
        assert_eq!(
            adapter.set_volume_label("Retry").unwrap_err().status,
            Status::FailedVolume
        );
        assert_eq!(disk.0.lock().unwrap().calls, calls);
    }
    drop(adapter);
    (ok, disk)
}

#[test]
fn interrupted_label_publication_recovers_one_consistent_root_and_thread() {
    let bytes = fixture(true, false);
    let jib = volume::be32(&bytes, 1036) as usize * volume::be32(&bytes, 1064) as usize;
    let journal = volume::be64(&bytes, jib + 36) as usize;
    let (ok, disk) = attempt(&bytes, None);
    assert!(ok);
    let boundaries = disk.0.lock().unwrap().calls;
    let mut snapshots = 0;
    for fail in 0..boundaries {
        let (ok, interrupted) = attempt(&bytes, Some(fail));
        assert!(!ok);
        for policy in 0..6 {
            let mut disk = MemoryBackend::from_bytes(interrupted.snapshot(policy, journal));
            let fs = HfsPlus::open(&mut disk).unwrap();
            assert!(matches!(
                fs.volume_name(),
                "Original Label" | "Renamed Volume"
            ));
            assert_eq!(
                fs.catalog_record_cnid(2).unwrap()[8..12],
                2u32.to_be_bytes()
            );
            assert_eq!(contents(&fs, &mut disk), b"Volume label payload\n");
            snapshots += 1;
        }
    }
    println!(
        "LABEL_RECOVERY: {boundaries} failure boundaries; {snapshots} replay snapshots passed"
    );
}
