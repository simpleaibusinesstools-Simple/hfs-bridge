use fstool::{
    block::MemoryBackend,
    fs::hfs_plus::{FormatOpts, HfsPlus},
};
use hfs_bridge::{
    links::{self, Node},
    volume,
    windows::{Access, Adapter, Kind, OpenRequest, Status},
};
#[path = "support/fault_disk.rs"]
#[allow(dead_code)]
mod fault;

fn fixture() -> (Adapter<fault::Disk>, fault::Disk) {
    let mut disk = MemoryBackend::new(4 * 1024 * 1024);
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
        &mut &b"retained"[..],
        8,
        0o644,
        501,
        20,
        1_700_000_000,
    )
    .unwrap();
    fs.flush(&mut disk).unwrap();
    let disk = fault::Disk::new(&disk.into_bytes());
    (Adapter::from_device(disk.clone()).unwrap(), disk)
}

#[test]
fn link_namespace_interruptions_preserve_the_target_and_recover_one_name() {
    let (mut prepared, disk) = fixture();
    let h = prepared.create(r"\link", Kind::File, all()).unwrap();
    prepared
        .set_symbolic_link(h, &links::symbolic_packet("target").unwrap())
        .unwrap();
    prepared.cleanup(h, false).unwrap();
    prepared.close(h).unwrap();
    drop(prepared);
    let before = disk.snapshot(1, 0);
    let journal = match volume::inspect(&mut MemoryBackend::from_bytes(before.clone()))
        .unwrap()
        .journal
    {
        volume::Journal::Clean { offset, .. } => offset as usize,
        _ => panic!("journal required"),
    };
    let observe = |bytes: Vec<u8>| {
        let mut disk = fault::Disk::new(&bytes);
        // Production mounts refuse pending journals. This fault oracle
        // explicitly replays only its private simulator copy before opening.
        HfsPlus::open(&mut disk).unwrap();
        let mut a = Adapter::from_device(disk).unwrap();
        let t = a.open(r"\target", OpenRequest::default()).unwrap();
        let mut content = [0; 8];
        a.read(t, 0, &mut content).unwrap();
        assert_eq!(&content, b"retained");
        let mut found = Vec::new();
        for path in [r"\link", r"\renamed"] {
            match a.path_info(path) {
                Ok(info) => {
                    assert_eq!(info.node, Node::SymbolicLink);
                    let packet = a.reparse_by_path(path).unwrap().unwrap();
                    assert_eq!(links::relative_symbolic_target(&packet).unwrap(), "target");
                    found.push(path.to_owned());
                }
                Err(e) => assert_eq!(e.status, Status::NotFound),
            }
        }
        assert!(a.path_info(r"\.hfs-bridge-orphans-v1").is_err());
        found
    };
    let operation = |a: &mut Adapter<fault::Disk>, h, deleting| {
        if deleting {
            a.cleanup(h, true)?;
            a.close(h)
        } else {
            a.rename(h, r"\renamed")
        }
    };
    let mut commits = 0;
    let mut replays = 0;
    for deleting in [false, true] {
        let disk = fault::Disk::new(&before);
        let mut a = Adapter::from_device(disk.clone()).unwrap();
        let h = a.open_reparse(r"\link", deletion()).unwrap();
        disk.arm(None);
        operation(&mut a, h, deleting).unwrap();
        let calls = disk.0.lock().unwrap().calls;
        let new = observe(disk.snapshot(1, journal));
        assert_eq!(
            new,
            if deleting {
                Vec::<String>::new()
            } else {
                vec![r"\renamed".to_owned()]
            }
        );
        let mut pending = None;
        for failure in 0..calls {
            let disk = fault::Disk::new(&before);
            let mut a = Adapter::from_device(disk.clone()).unwrap();
            let h = a.open_reparse(r"\link", deletion()).unwrap();
            disk.arm(Some(failure));
            assert!(operation(&mut a, h, deleting).is_err());
            drop(a);
            for policy in 0..6 {
                let bytes = disk.snapshot(policy, journal);
                if matches!(
                    volume::inspect(&mut MemoryBackend::from_bytes(bytes.clone()))
                        .unwrap()
                        .journal,
                    volume::Journal::Pending { .. }
                ) {
                    pending.get_or_insert_with(|| bytes.clone());
                }
                let state = observe(bytes);
                assert!(
                    state == [r"\link"] || state == new,
                    "partial namespace {deleting}/{failure}/{policy}: {state:?}"
                );
                commits += 1;
            }
        }
        let pending = pending.expect("journal commit observable");
        let mut disk = fault::Disk::new(&pending);
        HfsPlus::open(&mut disk).unwrap();
        Adapter::from_device(disk.clone()).unwrap();
        let calls = disk.0.lock().unwrap().calls;
        for failure in 0..calls {
            let mut disk = fault::Disk::new(&pending);
            disk.arm(Some(failure));
            let recovered = HfsPlus::open(&mut disk).map(|_| ()).and_then(|_| {
                Adapter::from_device(disk.clone())
                    .map(|_| ())
                    .map_err(|e| fstool::Error::InvalidImage(e.to_string()))
            });
            assert!(recovered.is_err());
            for policy in 0..6 {
                assert_eq!(observe(disk.snapshot(policy, journal)), new);
                replays += 1;
            }
        }
    }
    println!("SYMLINK_NAMESPACE: {commits} commit + {replays} recovery snapshots");
}
fn all() -> OpenRequest {
    OpenRequest {
        access: Access::ALL,
        ..Default::default()
    }
}

fn deletion() -> OpenRequest {
    OpenRequest {
        access: Access {
            delete: true,
            ..Access::READ
        },
        ..Default::default()
    }
}

#[test]
fn explicit_link_handle_can_rename_and_delete_without_following_target() {
    let (mut a, disk) = fixture();
    let h = a.create(r"\link", Kind::File, all()).unwrap();
    a.set_symbolic_link(h, &links::symbolic_packet("target").unwrap())
        .unwrap();
    a.cleanup(h, false).unwrap();
    a.close(h).unwrap();
    assert_eq!(
        a.open(r"\link", deletion()).unwrap_err().status,
        Status::AccessDenied
    );
    assert_eq!(
        a.open_reparse(r"\link", all()).unwrap_err().status,
        Status::AccessDenied
    );
    let h = a.open_reparse(r"\link", deletion()).unwrap();
    a.rename(h, r"\renamed").unwrap();
    assert_eq!(a.path_info(r"\link").unwrap_err().status, Status::NotFound);
    assert_eq!(a.path_info(r"\renamed").unwrap().node, Node::SymbolicLink);
    a.can_delete(h).unwrap();
    a.cleanup(h, true).unwrap();
    a.close(h).unwrap();
    drop(a);
    let mut a = Adapter::from_device(disk).unwrap();
    assert_eq!(
        a.path_info(r"\renamed").unwrap_err().status,
        Status::NotFound
    );
    let t = a.open(r"\target", OpenRequest::default()).unwrap();
    let mut bytes = [0; 8];
    a.read(t, 0, &mut bytes).unwrap();
    assert_eq!(&bytes, b"retained");
}

#[test]
fn directory_target_is_not_traversed_during_link_deletion_or_orphan_recovery() {
    let (mut a, disk) = fixture();
    let directory = a.create(r"\directory", Kind::Directory, all()).unwrap();
    a.cleanup(directory, false).unwrap();
    a.close(directory).unwrap();
    let h = a.create(r"\link", Kind::File, all()).unwrap();
    a.set_symbolic_link(h, &links::symbolic_packet("directory").unwrap())
        .unwrap();
    assert_ne!(a.file_info(h).unwrap().attributes & 0x10, 0);
    a.cleanup(h, true).unwrap();
    // Simulate a host exiting after durable unlink but before final close.
    drop(a);
    let mut a = Adapter::from_device(disk).unwrap();
    assert_eq!(a.path_info(r"\link").unwrap_err().status, Status::NotFound);
    assert_eq!(a.path_info(r"\directory").unwrap().kind, Kind::Directory);
    assert!(a.path_info(r"\.hfs-bridge-orphans-v1").is_err());
}

#[test]
fn adapter_publishes_link_dates_and_preserves_target_after_reopen() {
    let (mut a, disk) = fixture();
    let h = a.create(r"\link", Kind::File, all()).unwrap();
    let creation = a.file_info(h).unwrap().creation_time;
    a.set_symbolic_link(h, &links::symbolic_packet("target").unwrap())
        .unwrap();
    let info = a.file_info(h).unwrap();
    assert_eq!(info.node, Node::SymbolicLink);
    assert_eq!(info.creation_time, creation);
    assert!(info.change_time >= creation);
    assert_eq!(info.write_time, info.change_time);
    assert_eq!(
        links::relative_symbolic_target(&a.reparse_by_handle(h).unwrap().unwrap()).unwrap(),
        "target"
    );
    assert_eq!(
        a.read(h, 0, &mut [0; 16]).unwrap_err().status,
        Status::Unsupported
    );
    assert!(a.write(h, 0, b"bad", false, false).is_err());
    a.cleanup(h, false).unwrap();
    a.close(h).unwrap();
    drop(a);
    let mut a = Adapter::from_device(disk).unwrap();
    let h = a.open(r"\link", OpenRequest::default()).unwrap();
    let reopened = a.file_info(h).unwrap();
    assert_eq!(reopened.write_time, info.write_time);
    assert_eq!(reopened.change_time, info.change_time);
    let t = a.open(r"\target", OpenRequest::default()).unwrap();
    let mut bytes = [0; 8];
    assert_eq!(a.read(t, 0, &mut bytes).unwrap(), 8);
    assert_eq!(&bytes, b"retained");
}

#[test]
fn populated_streams_shared_handles_and_readonly_handles_refuse_without_writes() {
    for scenario in 0..5 {
        let (mut a, disk) = fixture();
        let h = a.create(r"\link", Kind::File, all()).unwrap();
        match scenario {
            0 => {
                a.write(h, 0, b"base", false, false).unwrap();
            }
            1 | 2 => {
                let path = if scenario == 1 {
                    r"\link:AFP_Resource"
                } else {
                    r"\link:note"
                };
                let stream = a.create(path, Kind::File, all()).unwrap();
                a.write(stream, 0, b"retained", false, false).unwrap();
                a.cleanup(stream, false).unwrap();
                a.close(stream).unwrap();
            }
            3 => {
                a.open(r"\link", OpenRequest::default()).unwrap();
            }
            _ => (),
        }
        let h = if scenario == 4 {
            a.cleanup(h, false).unwrap();
            a.close(h).unwrap();
            a.open(r"\link", OpenRequest::default()).unwrap()
        } else {
            h
        };
        disk.arm(None);
        assert!(
            a.set_symbolic_link(h, &links::symbolic_packet("target").unwrap())
                .is_err(),
            "scenario {scenario}"
        );
        assert!(
            a.failure().is_none(),
            "preflight refusal poisoned the adapter"
        );
        assert_eq!(a.file_info(h).unwrap().node, Node::Ordinary);
        assert_eq!(disk.0.lock().unwrap().calls, 0, "scenario {scenario} wrote");
    }
}

#[test]
fn directory_placeholder_retains_type_when_dangling_and_unlinks_without_target_changes() {
    for dangling in [false, true] {
        let (mut a, disk) = fixture();
        if !dangling {
            let target = a.create(r"\folder", Kind::Directory, all()).unwrap();
            a.cleanup(target, false).unwrap();
            a.close(target).unwrap();
            let child = a.create(r"\folder\child", Kind::File, all()).unwrap();
            a.write(child, 0, b"target data", false, false).unwrap();
            a.cleanup(child, false).unwrap();
            a.close(child).unwrap();
        }
        let h = a.create(r"\dirlink", Kind::Directory, all()).unwrap();
        let before = a.file_info(h).unwrap();
        a.set_symbolic_link(h, &links::symbolic_packet("folder").unwrap())
            .unwrap();
        let info = a.file_info(h).unwrap();
        assert_eq!(info.cnid, before.cnid);
        assert_eq!(info.node, Node::SymbolicLink);
        assert_eq!(
            info.attributes & 0x410,
            0x410,
            "directory kind must not depend on target existence"
        );
        assert_eq!(
            (info.creation_time, info.access_time),
            (before.creation_time, before.access_time)
        );
        assert_eq!(info.write_time, info.change_time);
        assert!(a.write(h, 0, b"bad", false, false).is_err());
        a.cleanup(h, false).unwrap();
        a.close(h).unwrap();
        if let Some(dir) = std::env::var_os("HFS_DIRECTORY_ADAPTER_ARTIFACT_DIR") {
            use std::io::Write;
            std::fs::create_dir_all(&dir).unwrap();
            let name = if dangling {
                "dangling-directory.img"
            } else {
                "valid-directory.img"
            };
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(std::path::Path::new(&dir).join(name))
                .unwrap();
            file.write_all(&disk.snapshot(1, 0)).unwrap();
            file.sync_all().unwrap();
        }
        drop(a);
        let mut a = Adapter::from_device(disk).unwrap();
        let reopened = a.path_info(r"\dirlink").unwrap();
        assert_eq!(reopened.attributes & 0x410, 0x410);
        assert_eq!(
            (
                reopened.creation_time,
                reopened.access_time,
                reopened.write_time,
                reopened.change_time
            ),
            (
                info.creation_time,
                info.access_time,
                info.write_time,
                info.change_time
            )
        );
        let h = a.open_reparse(r"\dirlink", deletion()).unwrap();
        a.rename(h, r"\renamed-dirlink").unwrap();
        assert_eq!(a.file_info(h).unwrap().attributes & 0x410, 0x410);
        a.cleanup(h, true).unwrap();
        a.close(h).unwrap();
        assert_eq!(
            a.path_info(r"\renamed-dirlink").unwrap_err().status,
            Status::NotFound
        );
        if !dangling {
            let child = a.open(r"\folder\child", OpenRequest::default()).unwrap();
            let mut bytes = [0; 11];
            a.read(child, 0, &mut bytes).unwrap();
            assert_eq!(&bytes, b"target data");
        }
    }
}

#[test]
fn directory_conversion_refuses_children_other_handles_and_named_streams_before_writes() {
    for scenario in 0..3 {
        let (mut a, disk) = fixture();
        let h = a.create(r"\dirlink", Kind::Directory, all()).unwrap();
        match scenario {
            0 => {
                let child = a.create(r"\dirlink\child", Kind::File, all()).unwrap();
                a.cleanup(child, false).unwrap();
                a.close(child).unwrap();
            }
            1 => {
                a.open(r"\dirlink", OpenRequest::default()).unwrap();
            }
            _ => {
                let stream = a.create(r"\dirlink:retained", Kind::File, all()).unwrap();
                a.write(stream, 0, b"stream", false, false).unwrap();
                a.cleanup(stream, false).unwrap();
                a.close(stream).unwrap();
            }
        }
        disk.arm(None);
        assert!(
            a.set_symbolic_link(h, &links::symbolic_packet("target").unwrap())
                .is_err()
        );
        assert!(a.failure().is_none());
        assert_eq!(a.file_info(h).unwrap().kind, Kind::Directory);
        assert_eq!(disk.0.lock().unwrap().calls, 0);
    }
}

#[test]
fn interrupted_directory_conversion_keeps_precise_dates_and_kind_with_its_publication() {
    let (mut a, disk) = fixture();
    let h = a.create(r"\dirlink", Kind::Directory, all()).unwrap();
    a.cleanup(h, false).unwrap();
    a.close(h).unwrap();
    drop(a);
    let before = disk.snapshot(1, 0);
    let journal = match volume::inspect(&mut MemoryBackend::from_bytes(before.clone()))
        .unwrap()
        .journal
    {
        volume::Journal::Clean { offset, .. } => offset as usize,
        _ => panic!("journal required"),
    };
    let observe = |bytes: Vec<u8>| {
        let mut disk = fault::Disk::new(&bytes);
        HfsPlus::open(&mut disk).unwrap();
        let mut a = Adapter::from_device(disk).unwrap();
        let info = a.path_info(r"\dirlink").unwrap();
        (
            info.cnid,
            info.node,
            info.kind,
            info.attributes,
            info.creation_time,
            info.access_time,
            info.write_time,
            info.change_time,
        )
    };
    let old = observe(before.clone());
    let mut commits = 0;
    let disk = fault::Disk::new(&before);
    let mut a = Adapter::from_device(disk.clone()).unwrap();
    let h = a.open(r"\dirlink", all()).unwrap();
    disk.arm(None);
    a.set_symbolic_link(h, &links::symbolic_packet("missing").unwrap())
        .unwrap();
    let calls = disk.0.lock().unwrap().calls;
    for failure in 0..calls {
        let disk = fault::Disk::new(&before);
        let mut a = Adapter::from_device(disk.clone()).unwrap();
        let h = a.open(r"\dirlink", all()).unwrap();
        disk.arm(Some(failure));
        assert!(
            a.set_symbolic_link(h, &links::symbolic_packet("missing").unwrap())
                .is_err()
        );
        assert!(a.failure().is_some());
        drop(a);
        for policy in 0..6 {
            let actual = observe(disk.snapshot(policy, journal));
            if actual.1 == Node::Ordinary {
                assert_eq!(actual, old);
            } else {
                assert_eq!(actual.0, old.0);
                assert_eq!(actual.1, Node::SymbolicLink);
                assert_eq!(actual.2, Kind::File); // HFS catalog kind, not Windows hint.
                assert_eq!(actual.3 & 0x410, 0x410);
                assert_eq!((actual.4, actual.5), (old.4, old.5));
                assert_eq!(actual.6, actual.7);
                assert!(actual.6 >= old.6);
            }
            commits += 1;
        }
    }
    println!("DIRECTORY_LINK_ADAPTER: {commits} persistence checkpoints");
}
