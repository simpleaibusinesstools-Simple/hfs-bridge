//! AFP backup/FinderInfo/catalog/private records must share one publication.
use fstool::{
    block::{BlockDevice, MemoryBackend},
    fs::hfs_plus::{FormatOpts, HfsPlus, PublicationMetadata},
};
use hfs_bridge::{
    volume,
    windows::{Access, Adapter, Kind, OpenRequest},
};
use std::{
    io::{Read, Write},
    path::Path,
};
#[path = "support/fault_disk.rs"]
mod fault;
const MARKER: &str = "org.hfsbridge.windows.time-generation";
const ENTRY: &str = "org.hfsbridge.windows.times";
fn all() -> OpenRequest {
    OpenRequest {
        access: Access::ALL,
        ..Default::default()
    }
}
fn finder(lock: bool) -> [u8; 32] {
    let mut bytes = [0; 32];
    bytes[..8].copy_from_slice(b"TEXTttxt");
    bytes[8] = if lock { 0x50 } else { 0x40 };
    bytes[26] = 17;
    bytes
}
fn fixture(journaled: bool, sensitive: bool) -> (Vec<u8>, u32) {
    let mut d = MemoryBackend::new(8 * 1024 * 1024);
    let mut fs = HfsPlus::format(
        &mut d,
        &FormatOpts {
            journaled,
            ..Default::default()
        },
    )
    .unwrap();
    let cnid = fs
        .create_file(
            &mut d,
            "/file",
            &mut &b"payload"[..],
            7,
            0o644,
            501,
            20,
            1_700_000_000,
        )
        .unwrap();
    fs.create_dir(&mut d, "/folder", 0o755, 501, 20, 1_700_000_000)
        .unwrap();
    fs.flush(&mut d).unwrap();
    let mut resource = fs
        .open_resource_fork_rw(&mut d, Path::new("/file"))
        .unwrap();
    resource.write_all(b"resource").unwrap();
    resource.sync().unwrap();
    drop(resource);
    fs.set_finder_info(cnid, &[0; 32], Some(3_700_000_000))
        .unwrap();
    fs.flush(&mut d).unwrap();
    let mut bytes = d.into_bytes();
    if sensitive {
        bytes[1024..1026].copy_from_slice(b"HX");
        bytes[1026..1028].copy_from_slice(&5u16.to_be_bytes());
        let cat = volume::be32(&bytes, 1312) as usize * 4096;
        bytes[cat + 51] = 0xbc;
        let header = bytes[1024..1536].to_vec();
        let alt = bytes.len() - 1024;
        bytes[alt..alt + 512].copy_from_slice(&header);
    }
    (bytes, cnid)
}
fn stage(
    fs: &mut HfsPlus,
    d: &mut dyn BlockDevice,
    cnid: u32,
    lock: bool,
    backup: Option<u32>,
) -> fstool::Result<()> {
    fs.set_finder_info_with_publication(
        d,
        cnid,
        &finder(lock),
        backup,
        [
            Some(3_800_000_000),
            Some(3_800_000_001),
            Some(3_800_000_002),
            Some(3_800_000_003),
        ],
        &[
            (2, MARKER, Some(b"new generation")),
            (cnid, ENTRY, Some(b"new precision")),
        ],
    )
}
fn export(name: &str, bytes: &[u8]) {
    if let Some(dir) = std::env::var_os("HFS_FINDER_IMAGES") {
        let dir = Path::new(&dir);
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(dir.join(name), bytes).unwrap();
    }
}
#[test]
fn finder_backup_dates_and_locks_publish_with_related_records_once() {
    let mut count = 0;
    for journaled in [false, true] {
        for sensitive in [false, true] {
            for backup in [None, Some(0), Some(3_900_000_000)] {
                for lock in [false, true] {
                    let (bytes, cnid) = fixture(journaled, sensitive);
                    let mut d = MemoryBackend::from_bytes(bytes.clone());
                    let mut fs = HfsPlus::open(&mut d).unwrap();
                    let old = fs.catalog_record_cnid(cnid).unwrap();
                    stage(&mut fs, &mut d, cnid, lock, backup).unwrap();
                    assert_eq!(d.as_slice(), bytes);
                    fs.flush(&mut d).unwrap();
                    let body = fs.catalog_record_cnid(cnid).unwrap();
                    assert_eq!(&body[88..], &old[88..]);
                    assert_eq!(&body[48..80], &finder(lock));
                    assert_eq!(volume::be32(&body, 28), backup.unwrap_or(3_700_000_000));
                    for (off, wanted) in [
                        (12, 3_800_000_000),
                        (24, 3_800_000_001),
                        (16, 3_800_000_002),
                        (20, 3_800_000_003),
                    ] {
                        assert_eq!(volume::be32(&body, off), wanted);
                    }
                    assert_eq!(
                        volume::be32(d.as_slice(), 1092),
                        volume::be32(&bytes, 1092) + 1
                    );
                    assert_eq!(
                        fs.inline_attribute(&mut d, 2, MARKER).unwrap(),
                        Some(b"new generation".to_vec())
                    );
                    assert_eq!(
                        fs.inline_attribute(&mut d, cnid, ENTRY).unwrap(),
                        Some(b"new precision".to_vec())
                    );
                    let saved = d.as_slice().to_vec();
                    fs.flush(&mut d).unwrap();
                    assert_eq!(d.as_slice(), saved);
                    if backup == Some(3_900_000_000) {
                        export(
                            &format!("finder-{journaled}-{sensitive}-{lock}.img"),
                            &saved,
                        );
                    }
                    count += 1;
                }
            }
        }
    }
    println!("FINDER_PUBLICATION_SUCCESS: {count} volume/backup/lock combinations");
}
#[test]
fn entry_metadata_preflight_keeps_root_lock_and_invalid_related_gates() {
    let (bytes, cnid) = fixture(true, false);
    for variant in 0..5 {
        let mut d = MemoryBackend::from_bytes(bytes.clone());
        let mut fs = HfsPlus::open(&mut d).unwrap();
        if variant == 4 {
            fs.set_catalog_windows_info(cnid, [None; 4], Some(1))
                .unwrap();
            fs.flush(&mut d).unwrap();
        }
        let before = d.as_slice().to_vec();
        let body = fs.catalog_record_cnid(cnid).unwrap();
        let mut value = finder(false);
        if variant == 1 {
            value[..8].copy_from_slice(b"hlnkhfs+");
        }
        let related = match variant {
            2 => vec![(0, MARKER, Some(&b"bad"[..]))],
            3 => vec![
                (2, MARKER, Some(&b"first"[..])),
                (2, MARKER, Some(&b"duplicate"[..])),
            ],
            _ => vec![],
        };
        assert!(
            fs.set_finder_info_with_publication(
                &mut d,
                if variant == 0 { 2 } else { cnid },
                &value,
                Some(3_900_000_000),
                [Some(3_800_000_000); 4],
                &related
            )
            .is_err()
        );
        assert_eq!(fs.catalog_record_cnid(cnid).unwrap(), body);
        assert!(!fs.requires_reopen());
        fs.flush(&mut d).unwrap();
        assert_eq!(d.as_slice(), before);
        if variant == 0 || variant == 4 {
            assert!(
                fs.set_entry_attributes_with_publication(
                    &mut d,
                    if variant == 0 { 2 } else { cnid },
                    PublicationMetadata {
                        attributes: &[("ordinary", Some(b"denied"))],
                        ..Default::default()
                    }
                )
                .is_err()
            );
            fs.flush(&mut d).unwrap();
            assert_eq!(d.as_slice(), before);
        }
    }
    // FinderInfo alone still uses catalog storage on a volume with no free blocks.
    let mut d = MemoryBackend::from_bytes(bytes);
    let mut fs = HfsPlus::open(&mut d).unwrap();
    let free = u64::from(volume::be32(d.as_slice(), 1072)) * 4096;
    fs.set_data_allocation(&mut d, Path::new("/file"), free + 4096, false)
        .unwrap();
    assert_eq!(volume::be32(d.as_slice(), 1072), 0);
    let before = d.as_slice().to_vec();
    let body = fs.catalog_record_cnid(cnid).unwrap();
    assert!(stage(&mut fs, &mut d, cnid, false, Some(3_900_000_000)).is_err());
    assert_eq!(fs.catalog_record_cnid(cnid).unwrap(), body);
    fs.flush(&mut d).unwrap();
    assert_eq!(d.as_slice(), before);
    fs.set_finder_info_with_publication(&mut d, cnid, &finder(false), Some(0), [None; 4], &[])
        .unwrap();
    fs.flush(&mut d).unwrap();
    assert_eq!(volume::be32(&fs.catalog_record_cnid(cnid).unwrap(), 28), 0);
}
#[derive(Debug, PartialEq, Eq)]
struct State {
    body: Vec<u8>,
    marker: Option<Vec<u8>>,
    entry: Option<Vec<u8>>,
    counter: u32,
    free: u32,
}
fn inspect(bytes: Vec<u8>, cnid: u32) -> State {
    let mut d = MemoryBackend::from_bytes(bytes);
    let fs = HfsPlus::open(&mut d).unwrap();
    let mut data = Vec::new();
    fs.open_file_reader(&mut d, "/file")
        .unwrap()
        .read_to_end(&mut data)
        .unwrap();
    assert_eq!(data, b"payload");
    data.clear();
    fs.open_resource_fork_reader(&mut d, "/file")
        .unwrap()
        .read_to_end(&mut data)
        .unwrap();
    assert_eq!(data, b"resource");
    State {
        body: fs.catalog_record_cnid(cnid).unwrap(),
        marker: fs.inline_attribute(&mut d, 2, MARKER).unwrap(),
        entry: fs.inline_attribute(&mut d, cnid, ENTRY).unwrap(),
        counter: volume::be32(d.as_slice(), 1092),
        free: volume::be32(d.as_slice(), 1072),
    }
}
#[test]
fn finder_backup_and_related_records_recover_all_old_or_all_new() {
    let mut snapshots = 0;
    let mut failures = 0;
    let mut pending_saved = 0;
    for sensitive in [false, true] {
        for lock in [false, true] {
            let (bytes, cnid) = fixture(true, sensitive);
            let old = inspect(bytes.clone(), cnid);
            let mut completed = fault::Disk::new(&bytes);
            let mut fs = HfsPlus::open(&mut completed).unwrap();
            completed.arm(None);
            stage(&mut fs, &mut completed, cnid, lock, Some(3_900_000_000)).unwrap();
            fs.flush(&mut completed).unwrap();
            let count = completed.0.lock().unwrap().calls;
            let new = inspect(completed.snapshot(0, 0), cnid);
            let jib = volume::be32(&bytes, 1036) as usize * 4096;
            let journal = volume::be64(&bytes, jib + 36) as usize;
            let mut retained = false;
            for fail in 0..count {
                let mut d = fault::Disk::new(&bytes);
                let mut fs = HfsPlus::open(&mut d).unwrap();
                d.arm(Some(fail));
                stage(&mut fs, &mut d, cnid, lock, Some(3_900_000_000)).unwrap();
                assert!(fs.flush(&mut d).is_err());
                assert!(fs.requires_reopen());
                let calls = d.0.lock().unwrap().calls;
                assert!(fs.flush(&mut d).is_err());
                assert_eq!(d.0.lock().unwrap().calls, calls);
                failures += 1;
                for policy in 0..6 {
                    let snapshot = d.snapshot(policy, journal);
                    if !retained
                        && snapshot[journal + 8..journal + 16]
                            != snapshot[journal + 16..journal + 24]
                    {
                        export(&format!("finder-pending-{sensitive}-{lock}.img"), &snapshot);
                        retained = true;
                        pending_saved += 1;
                    }
                    let got = inspect(snapshot, cnid);
                    assert!(got == old || got == new, "fail {fail} policy {policy}");
                    snapshots += 1;
                }
            }
            assert!(retained);
        }
    }
    println!(
        "FINDER_PUBLICATION_RECOVERY: {failures} failed boundaries; {snapshots} persistence snapshots; {pending_saved} pending-journal exports"
    );
}
#[test]
fn windows_finder_and_ea_updates_advance_one_counter_and_preserve_backup() {
    let (bytes, cnid) = fixture(true, false);
    let disk = fault::Disk::new(&bytes);
    let mut a = Adapter::from_device(disk.clone()).unwrap();
    let base = a.open("\\file", all()).unwrap();
    let stream = a.create("\\file:AFP_AfpInfo", Kind::File, all()).unwrap();
    let before = volume::be32(&disk.snapshot(0, 0), 1092);
    let wire = hfs_bridge::afp::encode(&finder(false), 3_900_000_000).unwrap();
    a.write(stream, 0, &wire, false, false).unwrap();
    assert_eq!(volume::be32(&disk.snapshot(0, 0), 1092), before + 1);
    a.close(stream).unwrap();
    let packet = hfs_bridge::ea::encode(
        &hfs_bridge::ea::records(&[("ordinary".into(), vec![9; 5001])]).unwrap(),
    )
    .unwrap();
    a.set_extended_attributes(base, &packet).unwrap();
    assert_eq!(volume::be32(&disk.snapshot(0, 0), 1092), before + 2);
    a.close(base).unwrap();
    a.shutdown().unwrap();
    let got = inspect(disk.snapshot(0, 0), cnid);
    assert_eq!(volume::be32(&got.body, 28), 3_900_000_000);
    assert_eq!(&got.body[48..80], &finder(false));
}
