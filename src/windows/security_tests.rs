use super::*;
use fstool::{
    block::MemoryBackend,
    fs::hfs_plus::{FormatOpts, HfsPlus},
};
#[path = "../../tests/support/fault_disk.rs"]
mod fault;
use fault::Disk;
fn descriptor(mask: u32) -> Vec<u8> {
    let mut bytes = vec![1, 0, 4, 128];
    for v in [20u32, 20, 0, 32] {
        bytes.extend_from_slice(&v.to_le_bytes());
    }
    let sid = [1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0];
    bytes.extend_from_slice(&sid);
    bytes.extend_from_slice(&[2, 0, 28, 0, 1, 0, 0, 0, 0, 0, 20, 0]);
    bytes.extend_from_slice(&mask.to_le_bytes());
    bytes.extend_from_slice(&sid);
    sd::validate(&bytes).unwrap();
    bytes
}
fn all() -> OpenRequest {
    OpenRequest {
        access: Access::ALL,
        ..Default::default()
    }
}
fn fixture(journaled: bool) -> Vec<u8> {
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
    let h = a
        .create_with_security(
            "\\secured",
            Kind::File,
            all(),
            Some(0x80),
            0,
            &[],
            Some(&descriptor(0x1f01ff)),
        )
        .unwrap();
    a.write(h, 0, b"protected", false, false).unwrap();
    a.close(h).unwrap();
    let h = a.create("\\plain", Kind::File, all()).unwrap();
    a.write(h, 0, b"unchanged", false, false).unwrap();
    a.close(h).unwrap();
    a.shutdown().unwrap().into_bytes()
}
#[test]
fn native_metadata_transport_hides_and_protects_private_records() {
    let mut d = MemoryBackend::from_bytes(fixture(true));
    let mut fs = crate::engine::open_checked(&mut d).unwrap();
    let cnid = volume::be32(&fs.catalog_record("/secured").unwrap(), 8);
    let names = [
        crate::timestamps::TIMES_ATTRIBUTE,
        crate::timestamps::GENERATION_ATTRIBUTE,
        crate::named_streams::ATTRIBUTE,
    ];
    fs.set_inline_attributes(
        &mut d,
        cnid,
        &[
            (names[0], Some(&[4; 112])),
            (names[1], Some(&[5; 80])),
            (names[2], Some(b"malformed private store")),
        ],
    )
    .unwrap();
    fs.flush(&mut d).unwrap();
    let disk = Disk::new(d.as_slice());
    let mut a = Adapter::from_device(disk.clone()).unwrap();
    let h = a.open("\\secured", all()).unwrap();
    disk.arm(None);
    assert!(a.extended_attributes_native(h).unwrap().is_empty());
    assert_eq!(a.file_info_native(h).unwrap().ea_size, 0);
    for name in names {
        for value in [None, Some(vec![9; 112])] {
            let initial = [crate::ea::Change {
                name: name.into(),
                value,
            }];
            assert_eq!(
                a.create_with_security(
                    "\\forged",
                    Kind::File,
                    all(),
                    None,
                    0,
                    &initial,
                    Some(&descriptor(0x120089))
                )
                .unwrap_err()
                .status,
                Status::AccessDenied
            );
        }
    }
    assert_eq!(disk.0.lock().unwrap().calls, 0);
    let new = a
        .create_with_security(
            "\\legitimate",
            Kind::File,
            all(),
            None,
            0,
            &[],
            Some(&descriptor(0x120089)),
        )
        .unwrap();
    assert_eq!(a.native_security(new).unwrap(), Some(descriptor(0x120089)));
    a.close(new).unwrap();
    a.close(h).unwrap();
    a.shutdown().unwrap();
    let mut d = MemoryBackend::from_bytes(disk.snapshot(1, 0));
    let fs = crate::engine::open_checked(&mut d).unwrap();
    assert_eq!(
        fs.fixed_inline_attribute(&mut d, cnid, names[0], 112)
            .unwrap(),
        Some(vec![4; 112])
    );
    assert_eq!(
        fs.fixed_inline_attribute(&mut d, cnid, names[1], 80)
            .unwrap(),
        Some(vec![5; 80])
    );
    assert_eq!(
        fs.inline_attribute(&mut d, cnid, names[2]).unwrap(),
        Some(b"malformed private store".to_vec())
    );
}
#[test]
fn ea_creation_overwrite_and_archive_cannot_inject_or_remove_security() {
    let disk = Disk::new(&fixture(true));
    let mut a = Adapter::from_device(disk.clone()).unwrap();
    let h = a.open("\\secured", all()).unwrap();
    let original = a.native_security(h).unwrap().unwrap();
    assert!(a.extended_attributes(h).unwrap().is_empty());
    disk.arm(None);
    let forged = sd::encode(&descriptor(0)).unwrap();
    let changes = [crate::ea::Change {
        name: sd::ATTRIBUTE.into(),
        value: Some(forged.clone()),
    }];
    assert_eq!(
        a.create_initialized_with_ea("\\bad", Kind::File, all(), None, 0, &changes)
            .unwrap_err()
            .status,
        Status::AccessDenied
    );
    assert_eq!(
        a.overwrite_with_ea(h, 0x80, true, 0, &changes)
            .unwrap_err()
            .status,
        Status::AccessDenied
    );
    for value in [forged.clone(), vec![]] {
        let packet =
            crate::ea::encode(&crate::ea::records(&[(sd::ATTRIBUTE.into(), value)]).unwrap())
                .unwrap();
        assert_eq!(
            a.set_extended_attributes(h, &packet).unwrap_err().status,
            Status::AccessDenied
        );
    }
    let archive = a
        .create("\\secured:HFSB_Attributes", Kind::File, all())
        .unwrap();
    let packet = crate::attribute_archive::encode(&[(sd::ATTRIBUTE.into(), forged)]).unwrap();
    assert_eq!(
        a.write(archive, 0, &packet, false, false)
            .unwrap_err()
            .status,
        Status::AccessDenied
    );
    assert_eq!(disk.0.lock().unwrap().calls, 0);
    assert_eq!(a.native_security(h).unwrap().unwrap(), original);
    // A subsequent valid empty metadata replacement removes only public EAs.
    a.set_size(archive, 0).unwrap();
    let empty = crate::attribute_archive::encode(&[]).unwrap();
    a.write(archive, 0, &empty, false, false).unwrap();
    a.close(archive).unwrap();
    assert_eq!(a.native_security(h).unwrap().unwrap(), original);
    let mut payload = [0; 9];
    a.read(h, 0, &mut payload).unwrap();
    assert_eq!(&payload, b"protected");
    assert!(a.failure().is_none());
    a.close(h).unwrap();
    a.shutdown().unwrap();
}
#[test]
fn security_disk_full_and_malformed_records_are_refused_without_mutation() {
    // Use a volume without an existing attribute tree: the new descriptor
    // then requires allocation. An existing tree may have room at zero free
    // blocks, which is a legitimate successful metadata-only update.
    let mut disk = MemoryBackend::new(8 * 1024 * 1024);
    HfsPlus::format(
        &mut disk,
        &FormatOpts {
            journaled: true,
            ..Default::default()
        },
    )
    .unwrap();
    // Build this legacy no-attributes fixture through the engine. Windows
    // creation now intentionally reserves the timestamp attribute tree.
    let mut fs = HfsPlus::open(&mut disk).unwrap();
    for name in ["/plain", "/filler"] {
        fs.create_file(
            &mut disk,
            name,
            &mut std::io::empty(),
            0,
            0o644,
            501,
            20,
            1_700_000_000,
        )
        .unwrap();
    }
    fs.flush(&mut disk).unwrap();
    let free = u64::from(volume::be32(disk.as_slice(), 1072)) * 4096;
    fs.edit_fork_with_publication(
        &mut disk,
        Path::new("/filler"),
        false,
        fstool::fs::hfs_plus::ForkEdit::Allocate {
            bytes: free,
            truncate: false,
        },
        Default::default(),
    )
    .unwrap();
    let mut a = Adapter::from_device(disk).unwrap();
    let h = a.open("\\plain", all()).unwrap();
    assert_eq!(a.volume_info().unwrap().free_bytes, 0);
    assert_eq!(
        a.set_native_security(h, &descriptor(0)).unwrap_err().status,
        Status::DiskFull
    );
    assert!(a.native_security(h).unwrap().is_none());
    assert!(a.failure().is_none());
    a.close(h).unwrap();
    a.shutdown().unwrap();
    let mut corrupt = MemoryBackend::from_bytes(fixture(true));
    let mut fs = crate::engine::open_checked(&mut corrupt).unwrap();
    let id = volume::be32(&fs.catalog_record("/secured").unwrap(), 8);
    fs.set_inline_attribute(&mut corrupt, id, sd::ATTRIBUTE, Some(b"HFSSEC99bad"))
        .unwrap();
    fs.flush(&mut corrupt).unwrap();
    let observed = Disk::new(corrupt.as_slice());
    let mut a = Adapter::from_device(observed.clone()).unwrap();
    observed.arm(None);
    assert!(a.native_security_by_path("\\secured").is_err());
    assert_eq!(observed.0.lock().unwrap().calls, 0);
    assert!(a.failure().is_none());
}
fn attempt(bytes: &[u8], operation: u8, fail: Option<usize>) -> (bool, Disk) {
    let disk = Disk::new(bytes);
    let mut a = Adapter::from_device(disk.clone()).unwrap();
    let h = a
        .open(
            if operation == 0 {
                "\\plain"
            } else {
                "\\secured"
            },
            all(),
        )
        .unwrap();
    disk.arm(fail);
    let changed = descriptor(0x120089);
    let result = if operation == 2 {
        a.create_with_security(
            "\\new",
            Kind::File,
            all(),
            Some(0x104),
            4096,
            &[],
            Some(&changed),
        )
        .map(|_| ())
    } else {
        a.set_native_security(h, &changed)
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
fn security_publication_is_atomic_under_journal_recovery_and_fail_stop() {
    let mut faults = 0;
    let mut snapshots = 0;
    for journaled in [false, true] {
        let bytes = fixture(journaled);
        let jib = volume::be32(&bytes, 1036) as usize * volume::be32(&bytes, 1064) as usize;
        let journal = if journaled {
            volume::be64(&bytes, jib + 36) as usize
        } else {
            0
        };
        for operation in 0..3 {
            let (ok, complete) = attempt(&bytes, operation, None);
            assert!(ok);
            let count = complete.0.lock().unwrap().calls;
            assert!(count > 0);
            for fail in 0..count {
                let (ok, interrupted) = attempt(&bytes, operation, Some(fail));
                assert!(!ok);
                faults += 1;
                if !journaled {
                    continue;
                }
                for policy in 0..6 {
                    let mut recovered =
                        MemoryBackend::from_bytes(interrupted.snapshot(policy, journal));
                    HfsPlus::open(&mut recovered).unwrap();
                    let mut a = Adapter::from_device(recovered).unwrap();
                    for (path, data) in [("\\secured", b"protected"), ("\\plain", b"unchanged")] {
                        let h = a.open(path, all()).unwrap();
                        let info = a.file_info(h).unwrap();
                        let mut actual = [0; 9];
                        a.read(h, 0, &mut actual).unwrap();
                        assert_eq!(&actual, data);
                        assert_eq!(info.mac_mode & 0xfff, 0o644);
                        let security = a.native_security(h).unwrap();
                        let original = if path == "\\secured" {
                            Some(descriptor(0x1f01ff))
                        } else {
                            None
                        };
                        if (operation == 0 && path == "\\plain")
                            || (operation == 1 && path == "\\secured")
                        {
                            assert!(security == original || security == Some(descriptor(0x120089)));
                        } else {
                            assert_eq!(security, original);
                        }
                        a.close(h).unwrap();
                    }
                    if operation == 2 && a.path_info("\\new").is_ok() {
                        assert_eq!(
                            a.native_security_by_path("\\new").unwrap(),
                            Some(descriptor(0x120089))
                        );
                        let info = a.path_info("\\new").unwrap();
                        assert_eq!(info.attributes & 0x104, 0x104);
                        assert_eq!(info.allocation_size, 4096);
                    }
                    a.shutdown().unwrap();
                    snapshots += 1;
                }
            }
        }
    }
    println!(
        "SECURITY_RECOVERY: {faults} failed write/sync boundaries; {snapshots} journal replay snapshots passed"
    );
}
