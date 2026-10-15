use fstool::{
    block::MemoryBackend,
    fs::hfs_plus::{FormatOpts, HfsPlus},
};
use hfs_bridge::{
    links,
    windows::{Access, Adapter, Handle, Kind, OpenRequest},
};
#[path = "support/fault_disk.rs"]
#[allow(dead_code)]
mod fault;

fn control() -> OpenRequest {
    OpenRequest {
        access: Access {
            metadata: true,
            ..Access::READ
        },
        ..Default::default()
    }
}
fn all() -> OpenRequest {
    OpenRequest {
        access: Access::ALL,
        ..Default::default()
    }
}
fn finish(a: &mut Adapter<fault::Disk>, h: Handle) {
    a.cleanup(h, false).unwrap();
    a.close(h).unwrap();
}
fn fixture(directory: bool) -> (Adapter<fault::Disk>, fault::Disk) {
    let mut disk = MemoryBackend::new(4 * 1024 * 1024);
    let mut fs = HfsPlus::format(
        &mut disk,
        &FormatOpts {
            journaled: true,
            ..Default::default()
        },
    )
    .unwrap();
    for (name, data) in [("/old", b"old payload"), ("/new", b"new payload")] {
        fs.create_file(
            &mut disk,
            name,
            &mut &data[..],
            data.len() as u64,
            0o640,
            501,
            20,
            1_700_000_000,
        )
        .unwrap();
    }
    fs.flush(&mut disk).unwrap();
    let disk = fault::Disk::new(&disk.into_bytes());
    let mut a = Adapter::from_device(disk.clone()).unwrap();
    let h = a
        .create(
            r"\link",
            if directory {
                Kind::Directory
            } else {
                Kind::File
            },
            all(),
        )
        .unwrap();
    a.set_symbolic_link(h, &links::symbolic_packet("old").unwrap())
        .unwrap();
    finish(&mut a, h);
    (a, disk)
}
fn packet() -> [u8; 8] {
    [12, 0, 0, 160, 0, 0, 0, 0]
}
#[test]
fn removal_preserves_identity_dates_and_targets_then_allows_ordinary_use() {
    for directory in [false, true] {
        let (mut a, disk) = fixture(directory);
        let before = a.path_info(r"\link").unwrap();
        let h = a.open_reparse(r"\link", control()).unwrap();
        a.remove_symbolic_link(h, &packet()).unwrap();
        let after = a.file_info(h).unwrap();
        assert_eq!(after.cnid, before.cnid);
        assert_eq!(after.creation_time, before.creation_time);
        assert_eq!(after.access_time, before.access_time);
        assert_eq!(after.attributes & 0x410, if directory { 0x10 } else { 0 });
        assert_eq!(after.size, 0);
        assert!(after.change_time >= before.change_time);
        assert_eq!(after.write_time, after.change_time);
        assert_eq!(a.reparse_by_handle(h).unwrap(), None);
        finish(&mut a, h);
        drop(a);
        let mut a = Adapter::from_device(disk.clone()).unwrap();
        assert_eq!(a.path_info(r"\link").unwrap().write_time, after.write_time);
        for (path, want) in [(r"\old", b"old payload"), (r"\new", b"new payload")] {
            let h = a.open(path, OpenRequest::default()).unwrap();
            let mut bytes = [0; 11];
            assert_eq!(a.read(h, 0, &mut bytes).unwrap(), 11);
            assert_eq!(&bytes, want);
            finish(&mut a, h);
        }
        if let Some(dir) = std::env::var_os("HFS_LINK_REMOVAL_ADAPTER_DIR") {
            std::fs::create_dir_all(&dir).unwrap();
            let path = std::path::Path::new(&dir).join(format!("adapter-{directory}.img"));
            assert!(!path.exists());
            std::fs::write(path, disk.snapshot(1, 0)).unwrap();
        }
        let child = if directory {
            a.create(r"\link\child", Kind::File, all()).unwrap()
        } else {
            a.open(r"\link", all()).unwrap()
        };
        assert_eq!(
            a.write(child, 0, b"ordinary payload", false, false)
                .unwrap(),
            16
        );
        finish(&mut a, child);
    }
}
#[test]
fn removal_rejects_invalid_packet_access_and_shared_lifetimes_before_io() {
    for scenario in 0..8 {
        let (mut a, disk) = fixture(false);
        let h = a
            .open_reparse(
                r"\link",
                if scenario == 0 {
                    OpenRequest::default()
                } else {
                    control()
                },
            )
            .unwrap();
        if scenario == 1 || scenario == 2 {
            let other = a.open_reparse(r"\link", OpenRequest::default()).unwrap();
            if scenario == 2 {
                a.cleanup(other, false).unwrap();
            }
        }
        if scenario == 3 {
            a.cleanup(h, false).unwrap();
        }
        let mut p = packet().to_vec();
        match scenario {
            4 => p[0] = 3,
            5 => p[4] = 1,
            6 => p.push(0),
            7 => {
                p.pop();
            }
            _ => (),
        }
        disk.arm(None);
        let before = disk.snapshot(1, 0);
        assert!(
            a.remove_symbolic_link(h, &p).is_err(),
            "scenario {scenario}"
        );
        assert_eq!(disk.0.lock().unwrap().calls, 0);
        assert_eq!(disk.snapshot(1, 0), before);
    }
}
#[test]
fn interrupted_removal_keeps_type_kind_dates_and_fork_in_one_publication() {
    let mut checkpoints = 0;
    for directory in [false, true] {
        let (a, disk) = fixture(directory);
        drop(a);
        let before = disk.snapshot(1, 0);
        let journal =
            match hfs_bridge::volume::inspect(&mut MemoryBackend::from_bytes(before.clone()))
                .unwrap()
                .journal
            {
                hfs_bridge::volume::Journal::Clean { offset, .. } => offset as usize,
                _ => panic!("journal required"),
            };
        let observe = |bytes: Vec<u8>| {
            let mut disk = fault::Disk::new(&bytes);
            HfsPlus::open(&mut disk).unwrap();
            let mut a = Adapter::from_device(disk).unwrap();
            let info = a.path_info(r"\link").unwrap();
            (
                a.reparse_by_path(r"\link").unwrap(),
                info.attributes & 0x410,
                info.cnid,
                info.creation_time,
                info.access_time,
                info.write_time,
                info.change_time,
            )
        };
        let old = observe(before.clone());
        let disk = fault::Disk::new(&before);
        let mut a = Adapter::from_device(disk.clone()).unwrap();
        let h = a.open_reparse(r"\link", control()).unwrap();
        disk.arm(None);
        a.remove_symbolic_link(h, &packet()).unwrap();
        let calls = disk.0.lock().unwrap().calls;
        for failure in 0..calls {
            let disk = fault::Disk::new(&before);
            let mut a = Adapter::from_device(disk.clone()).unwrap();
            let h = a.open_reparse(r"\link", control()).unwrap();
            disk.arm(Some(failure));
            assert!(a.remove_symbolic_link(h, &packet()).is_err());
            drop(a);
            for policy in 0..6 {
                let state = observe(disk.snapshot(policy, journal));
                if state.0.is_some() {
                    assert_eq!(state, old);
                } else {
                    assert_eq!(state.1, if directory { 0x10 } else { 0 });
                    assert_eq!((state.2, state.3, state.4), (old.2, old.3, old.4));
                    assert!(state.5 >= old.5);
                    assert_eq!(state.5, state.6);
                }
                checkpoints += 1;
            }
        }
    }
    println!("LINK_REMOVAL_ADAPTER: {checkpoints} persistence checkpoints");
}
