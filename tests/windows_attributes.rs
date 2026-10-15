//! Windows-only flags must share publication with payload/basic metadata.
use fstool::{
    block::{BlockDevice, MemoryBackend},
    fs::hfs_plus::{FormatOpts, HfsPlus},
};
use hfs_bridge::{
    ea, engine, volume,
    windows::{Access, Adapter, BasicTimes, Kind, OpenRequest, Status, hfs_to_filetime},
};
#[path = "support/fault_disk.rs"]
mod fault;
use fault::Disk;
const MARKER: &str = "org.hfsbridge.windows.attributes";
fn all() -> OpenRequest {
    OpenRequest {
        access: Access::ALL,
        ..Default::default()
    }
}
fn fixture(journaled: bool, flagged: bool) -> Vec<u8> {
    let mut d = MemoryBackend::new(8 * 1024 * 1024);
    HfsPlus::format(
        &mut d,
        &FormatOpts {
            journaled,
            ..Default::default()
        },
    )
    .unwrap();
    let mut a = Adapter::from_device(d).unwrap();
    for (path, data) in [
        ("\\target", b"original".as_slice()),
        ("\\survivor", b"unchanged"),
    ] {
        let h = a.create(path, Kind::File, all()).unwrap();
        a.write(h, 0, data, false, false).unwrap();
        a.set_basic_info(
            h,
            BasicTimes {
                creation: Some(hfs_to_filetime(3_800_000_000)),
                ..Default::default()
            },
            Some(if flagged && path == "\\target" {
                0x104
            } else {
                0x80
            }),
        )
        .unwrap();
        a.close(h).unwrap();
    }
    a.shutdown().unwrap().into_bytes()
}
fn content<D: BlockDevice>(a: &mut Adapter<D>, h: hfs_bridge::windows::Handle) -> Vec<u8> {
    let mut v = vec![0; 32];
    let count = a.read(h, 0, &mut v).unwrap();
    v.truncate(count);
    v
}
#[test]
fn malformed_windows_metadata_is_refused_without_changes_or_poison() {
    let disk = Disk::new(&fixture(true, false));
    let mut a = Adapter::from_device(disk.clone()).unwrap();
    let h = a.open("\\target", all()).unwrap();
    disk.arm(None);
    for value in [
        vec![],
        b"HFSWA999\0\0\x01\x04".to_vec(),
        b"HFSWA001\0\0\0\x01".to_vec(),
        b"HFSWA001\0\0\x80\0".to_vec(),
    ] {
        let changes = [ea::Change {
            name: MARKER.into(),
            value: Some(value.clone()),
        }];
        assert!(
            a.create_initialized_with_ea("\\refused", Kind::File, all(), Some(0x104), 0, &changes)
                .is_err()
        );
        assert!(a.overwrite_with_ea(h, 0x80, true, 0, &changes).is_err());
        // An empty Windows EA means removal, so test malformed nonempty values.
        if !value.is_empty() {
            let packet = ea::encode(&ea::records(&[(MARKER.into(), value)]).unwrap()).unwrap();
            assert!(a.set_extended_attributes(h, &packet).is_err());
        }
    }
    assert_eq!(disk.0.lock().unwrap().calls, 0);
    assert_eq!(content(&mut a, h), b"original");
    assert!(a.failure().is_none());
    a.close(h).unwrap();
    a.shutdown().unwrap();
}
#[test]
fn windows_flags_preflight_disk_space_before_truncating_or_staging() {
    for reserve in [32768, 0] {
        // Seed a legacy volume without the timestamp tree that Windows creation
        // now allocates. Metadata must still reserve space before overwriting.
        let mut disk = MemoryBackend::new(8 * 1024 * 1024);
        let mut fs = HfsPlus::format(
            &mut disk,
            &FormatOpts {
                journaled: true,
                ..Default::default()
            },
        )
        .unwrap();
        fs.create_file(
            &mut disk,
            "/target",
            &mut &b"original"[..],
            8,
            0o644,
            501,
            20,
            1_700_000_000,
        )
        .unwrap();
        fs.create_file(
            &mut disk,
            "/filler",
            &mut std::io::empty(),
            0,
            0o644,
            501,
            20,
            1_700_000_000,
        )
        .unwrap();
        fs.flush(&mut disk).unwrap();
        let free = u64::from(volume::be32(disk.as_slice(), 1072)) * 4096;
        fs.edit_fork_with_publication(
            &mut disk,
            std::path::Path::new("/filler"),
            false,
            fstool::fs::hfs_plus::ForkEdit::Allocate {
                bytes: free - reserve,
                truncate: false,
            },
            Default::default(),
        )
        .unwrap();
        let mut a = Adapter::from_device(disk).unwrap();
        let h = a.open("\\target", all()).unwrap();
        assert_eq!(a.volume_info().unwrap().free_bytes, reserve);
        assert_eq!(
            a.overwrite(h, 0x104, true, 32768).unwrap_err().status,
            Status::DiskFull
        );
        assert_eq!(
            a.create_initialized("\\refused", Kind::File, all(), Some(0x104), 32768)
                .unwrap_err()
                .status,
            Status::DiskFull
        );
        if reserve == 0 {
            assert_eq!(
                a.set_basic_info(h, BasicTimes::default(), Some(0x104))
                    .unwrap_err()
                    .status,
                Status::DiskFull
            );
        }
        assert_eq!(content(&mut a, h), b"original");
        assert_eq!(a.file_info(h).unwrap().attributes & 0x104, 0);
        assert!(a.failure().is_none());
        a.close(h).unwrap();
        a.shutdown().unwrap();
    }
}
fn attempt(bytes: &[u8], op: u8, fail: Option<usize>) -> (bool, Disk) {
    let disk = Disk::new(bytes);
    let mut a = Adapter::from_device(disk.clone()).unwrap();
    let h = a.open("\\target", all()).unwrap();
    disk.arm(fail);
    let result = match op {
        0 | 2 => a.set_basic_info(
            h,
            BasicTimes {
                creation: Some(hfs_to_filetime(3_800_000_010)),
                ..Default::default()
            },
            Some(if op == 0 { 0x104 } else { 0x80 }),
        ),
        1 => a.overwrite(h, 0x104, true, 8192),
        3 => a
            .create_initialized("\\created", Kind::File, all(), Some(0x104), 8192)
            .map(|_| ()),
        _ => unreachable!(),
    };
    let success = result.is_ok();
    if !success {
        assert!(a.failure().is_some());
        let calls = disk.0.lock().unwrap().calls;
        assert!(a.flush(Some(h)).is_err());
        assert!(a.close(h).is_err());
        assert_eq!(disk.0.lock().unwrap().calls, calls);
    }
    (success, disk)
}
#[test]
fn windows_flags_survive_atomic_journal_replay_and_stop_on_persistence_failures() {
    let mut faults = 0;
    let mut snapshots = 0;
    for journaled in [false, true] {
        for op in 0..4 {
            let bytes = fixture(journaled, op == 2);
            let jib = volume::be32(&bytes, 1036) as usize * volume::be32(&bytes, 1064) as usize;
            let journal = if journaled {
                volume::be64(&bytes, jib + 36) as usize
            } else {
                0
            };
            let (ok, complete) = attempt(&bytes, op, None);
            assert!(ok);
            let count = complete.0.lock().unwrap().calls;
            assert!(count > 0);
            for fail in 0..count {
                let (ok, interrupted) = attempt(&bytes, op, Some(fail));
                assert!(!ok);
                faults += 1;
                if !journaled {
                    continue;
                }
                for policy in 0..6 {
                    let mut disk = MemoryBackend::from_bytes(interrupted.snapshot(policy, journal));
                    HfsPlus::open(&mut disk).unwrap();
                    let mut a = Adapter::from_device(disk).unwrap();
                    let h = a.open("\\target", all()).unwrap();
                    let info = a.file_info(h).unwrap();
                    let data = content(&mut a, h);
                    let bits = info.attributes & 0x104;
                    match op {
                        0 | 2 => {
                            assert_eq!(data, b"original");
                            let changed = info.creation_time == hfs_to_filetime(3_800_000_010);
                            assert!(
                                changed || info.creation_time == hfs_to_filetime(3_800_000_000)
                            );
                            assert_eq!(bits, if changed == (op == 0) { 0x104 } else { 0 });
                        }
                        1 => {
                            assert!(data == b"original" || data.is_empty());
                            assert_eq!(bits, if data.is_empty() { 0x104 } else { 0 });
                            if data.is_empty() {
                                assert_eq!(info.allocation_size, 8192);
                            }
                        }
                        3 => {
                            assert_eq!(data, b"original");
                            if let Ok(info) = a.path_info("\\created") {
                                assert_eq!(info.attributes & 0x104, 0x104);
                                assert_eq!(info.size, 0);
                                assert_eq!(info.allocation_size, 8192);
                            }
                        }
                        _ => unreachable!(),
                    }
                    a.close(h).unwrap();
                    let mut disk = a.shutdown().unwrap();
                    assert_eq!(
                        engine::snapshot_device(&mut disk, "/survivor", &[])
                            .unwrap()
                            .data_sha256,
                        engine::sha256(&mut &b"unchanged"[..]).unwrap()
                    );
                    snapshots += 1;
                }
            }
        }
    }
    println!(
        "WINDOWS_ATTRIBUTE_RECOVERY: {faults} failing write/sync boundaries; {snapshots} journal replay snapshots passed"
    );
}
