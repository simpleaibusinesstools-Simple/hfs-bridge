use fstool::{
    block::MemoryBackend,
    fs::{
        Filesystem, OpenFlags,
        hfs_plus::{FormatOpts, HfsPlus},
    },
};
use hfs_bridge::volume;
use std::io::{Read, Write};
#[path = "support/fault_disk.rs"]
mod fault;
use fault::Disk;

fn fixture(journaled: bool, count: u32) -> Vec<u8> {
    let mut d = MemoryBackend::new(8 * 1024 * 1024);
    let mut fs = HfsPlus::format(
        &mut d,
        &FormatOpts {
            journaled,
            ..Default::default()
        },
    )
    .unwrap();
    fs.create_file(
        &mut d,
        "/original",
        &mut &b"payload"[..],
        7,
        0o644,
        501,
        20,
        1_700_000_000,
    )
    .unwrap();
    fs.flush(&mut d).unwrap();
    let mut bytes = d.into_bytes();
    let end = bytes.len() - 1024;
    for header in [1024, end] {
        bytes[header + 8..header + 12].copy_from_slice(b"HFSJ");
        bytes[header + 68..header + 72].copy_from_slice(&count.to_be_bytes());
        bytes[header + 104..header + 112].copy_from_slice(b"vol-uuid");
    }
    bytes
}
fn count(bytes: &[u8]) -> u32 {
    volume::be32(bytes, 1092)
}
fn rename(fs: &mut HfsPlus, d: &mut dyn fstool::block::BlockDevice) -> fstool::Result<()> {
    fs.rename(d, "/original", "/renamed")?;
    fs.flush(d)
}
#[test]
fn read_only_and_unchanged_writable_flush_preserve_generation_and_bytes() {
    for journaled in [false, true] {
        let bytes = fixture(journaled, 711);
        let mut d = MemoryBackend::from_bytes(bytes.clone());
        let mut fs = HfsPlus::open(&mut d).unwrap();
        let mut payload = Vec::new();
        fs.open_file_reader(&mut d, "/original")
            .unwrap()
            .read_to_end(&mut payload)
            .unwrap();
        assert_eq!(payload, b"payload");
        fs.flush(&mut d).unwrap();
        assert!(
            d.as_slice() == bytes,
            "read/flush changed bytes: {:?}",
            d.as_slice()
                .iter()
                .zip(&bytes)
                .enumerate()
                .filter(|(_, (a, b))| a != b)
                .take(24)
                .map(|(i, (a, b))| (i, *a, *b))
                .collect::<Vec<_>>()
        );
        let mut fs = HfsPlus::open(&mut d).unwrap();
        fs.flush(&mut d).unwrap();
        fs.flush(&mut d).unwrap();
        assert!(d.as_slice() == bytes, "unchanged flush changed bytes");
    }
}
#[test]
fn each_metadata_publication_updates_both_headers_preserves_uuid_and_wraps() {
    for journaled in [false, true] {
        for initial in [41, u32::MAX] {
            let bytes = fixture(journaled, initial);
            let mut d = MemoryBackend::from_bytes(bytes.clone());
            let mut fs = HfsPlus::open(&mut d).unwrap();
            rename(&mut fs, &mut d).unwrap();
            assert_eq!(count(d.as_slice()), initial.wrapping_add(1));
            assert_eq!(
                &d.as_slice()[1032..1036],
                if journaled { b"HFSJ" } else { b"HB39" }
            );
            assert_eq!(&d.as_slice()[1128..1136], b"vol-uuid");
            let alt = d.as_slice().len() - 1024;
            assert_eq!(&d.as_slice()[1024..1536], &d.as_slice()[alt..alt + 512]);
            let after = d.as_slice().to_vec();
            fs.flush(&mut d).unwrap();
            assert!(d.as_slice() == after, "second flush changed bytes");
            let cnid = volume::be32(&fs.catalog_record("/renamed").unwrap(), 8);
            fs.set_inline_attribute(
                &mut d,
                cnid,
                "org.hfsbridge.generation-test",
                Some(b"metadata"),
            )
            .unwrap();
            fs.flush(&mut d).unwrap();
            assert_eq!(count(d.as_slice()), initial.wrapping_add(2));
            if let Some(dir) = std::env::var_os("HFS_GENERATION_ARTIFACT_DIR") {
                let name = format!(
                    "generation-{}-{}.img",
                    if journaled { "journaled" } else { "plain" },
                    initial
                );
                let mut f = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(std::path::Path::new(&dir).join(name))
                    .unwrap();
                f.write_all(d.as_slice()).unwrap();
                f.sync_all().unwrap();
            }
        }
    }
}
fn attempt(bytes: &[u8], fail: Option<usize>) -> (bool, Disk) {
    let mut d = Disk::new(bytes);
    let mut fs = HfsPlus::open(&mut d).unwrap();
    d.arm(fail);
    let ok = rename(&mut fs, &mut d).is_ok();
    if !ok {
        let calls = d.0.lock().unwrap().calls;
        assert!(fs.flush(&mut d).is_err());
        assert_eq!(calls, d.0.lock().unwrap().calls);
    }
    (ok, d)
}
#[test]
fn journal_replay_keeps_generation_atomic_with_the_catalog_change() {
    verify_replay(fixture(true, 711), false);
}

#[test]
fn foreign_writer_marker_is_synchronized_before_new_journal_publication() {
    let mut bytes = fixture(true, 711);
    let alternate = bytes.len() - 1024;
    for header in [1024, alternate] {
        bytes[header + 8..header + 12].copy_from_slice(b"10.0");
    }
    verify_replay(bytes, true);
}

fn verify_replay(bytes: Vec<u8>, foreign: bool) {
    let jib = volume::be32(&bytes, 1036) as usize * volume::be32(&bytes, 1064) as usize;
    let journal = volume::be64(&bytes, jib + 36) as usize;
    let (ok, completed) = attempt(&bytes, None);
    assert!(ok);
    let boundaries = completed.0.lock().unwrap().calls;
    let mut snapshots = 0;
    let mut exported = [false; 2];
    for fail in 0..boundaries {
        let (ok, interrupted) = attempt(&bytes, Some(fail));
        assert!(!ok);
        for policy in 0..6 {
            let image = interrupted.snapshot(policy, journal);
            let pending = volume::be64(&image, journal + 8) != volume::be64(&image, journal + 16);
            if pending {
                assert_eq!(&image[1032..1036], b"HFSJ");
                let index = usize::from(count(&image) != 711);
                if !exported[index]
                    && let Some(dir) = std::env::var_os("HFS_GENERATION_ARTIFACT_DIR")
                {
                    let kind = if foreign { "foreign-" } else { "" };
                    let path = std::path::Path::new(&dir)
                        .join(format!("pending-generation-{kind}{index}.img"));
                    let mut f = std::fs::OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .open(path)
                        .unwrap();
                    f.write_all(&image).unwrap();
                    f.sync_all().unwrap();
                    exported[index] = true;
                    println!(
                        "PENDING_GENERATION_IMAGE: {kind}{index}; failure {fail}; policy {policy}"
                    );
                }
            }
            let mut d = MemoryBackend::from_bytes(image);
            let fs = HfsPlus::open(&mut d).unwrap();
            let renamed = fs.catalog_record("/renamed").is_ok();
            assert_ne!(renamed, fs.catalog_record("/original").is_ok());
            assert_eq!(count(d.as_slice()), if renamed { 712 } else { 711 });
            if renamed || pending || !foreign {
                assert_eq!(&d.as_slice()[1032..1036], b"HFSJ");
            } else {
                assert!(matches!(&d.as_slice()[1032..1036], b"HFSJ" | b"10.0"));
            }
            assert_eq!(&d.as_slice()[1128..1136], b"vol-uuid");
            let mut payload = Vec::new();
            fs.open_file_reader(&mut d, if renamed { "/renamed" } else { "/original" })
                .unwrap()
                .read_to_end(&mut payload)
                .unwrap();
            assert_eq!(payload, b"payload");
            snapshots += 1;
        }
    }
    println!(
        "GENERATION_RECOVERY: foreign={foreign}; {boundaries} failure boundaries; {snapshots} replay snapshots passed"
    );
}

#[test]
fn same_size_data_edit_advances_generation_without_allocating_storage() {
    for journaled in [false, true] {
        let mut d = MemoryBackend::from_bytes(fixture(journaled, 91));
        let mut fs = HfsPlus::open(&mut d).unwrap();
        let free = volume::be32(d.as_slice(), 1072);
        {
            let mut handle = fs
                .open_file_rw(
                    &mut d,
                    std::path::Path::new("/original"),
                    OpenFlags::default(),
                    None,
                )
                .unwrap();
            handle.write_all(b"PAY").unwrap();
            handle.flush().unwrap();
        }
        fs.flush(&mut d).unwrap();
        assert_eq!(count(d.as_slice()), 92);
        assert_eq!(volume::be32(d.as_slice(), 1072), free);
        let mut payload = Vec::new();
        fs.open_file_reader(&mut d, "/original")
            .unwrap()
            .read_to_end(&mut payload)
            .unwrap();
        assert_eq!(payload, b"PAYload");
    }
}
