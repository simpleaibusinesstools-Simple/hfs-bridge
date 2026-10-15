use fstool::{
    block::MemoryBackend,
    fs::hfs_plus::{FormatOpts, HfsPlus},
};
use hfs_bridge::{
    links,
    windows::{Access, Adapter, BasicTimes, Handle, Kind, OpenRequest, Status},
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
#[test]
fn explicit_control_retargets_without_changing_identity_kind_dates_or_other_files() {
    for directory in [false, true] {
        let (mut a, disk) = fixture(directory);
        let before = a.path_info(r"\link").unwrap();
        let h = a.open_reparse(r"\link", control()).unwrap();
        a.set_symbolic_link(h, &links::symbolic_packet("new").unwrap())
            .unwrap();
        let after = a.file_info(h).unwrap();
        assert_eq!(before.cnid, after.cnid);
        assert_eq!(before.attributes & 0x410, after.attributes & 0x410);
        assert_eq!(before.creation_time, after.creation_time);
        assert_eq!(before.access_time, after.access_time);
        assert!(after.change_time >= before.change_time);
        assert_eq!(after.change_time, after.write_time);
        assert_eq!(
            links::relative_symbolic_target(&a.reparse_by_handle(h).unwrap().unwrap()).unwrap(),
            "new"
        );
        assert!(a.write(h, 0, b"not link data", false, false).is_err());
        finish(&mut a, h);
        drop(a);
        let mut a = Adapter::from_device(disk.clone()).unwrap();
        assert_eq!(a.path_info(r"\link").unwrap().write_time, after.write_time);
        assert_eq!(
            a.path_info(r"\link").unwrap().attributes & 0x10 != 0,
            directory
        );
        assert_eq!(
            links::relative_symbolic_target(&a.reparse_by_path(r"\link").unwrap().unwrap())
                .unwrap(),
            "new"
        );
        for path in [r"\old", r"\new"] {
            let h = a.open(path, OpenRequest::default()).unwrap();
            let mut data = [0; 11];
            assert_eq!(a.read(h, 0, &mut data).unwrap(), 11);
            assert_eq!(
                &data,
                if path == r"\old" {
                    b"old payload"
                } else {
                    b"new payload"
                }
            );
            finish(&mut a, h);
        }
        if let Some(dir) = std::env::var_os("HFS_LINK_REPLACEMENT_ADAPTER_DIR") {
            std::fs::create_dir_all(&dir).unwrap();
            let path = std::path::Path::new(&dir).join(format!("adapter-{directory}.img"));
            assert!(!path.exists());
            std::fs::write(path, disk.snapshot(1, 0)).unwrap();
        }
    }
}
#[test]
fn new_attribute_access_cannot_bypass_ordinary_link_metadata_or_data_guards() {
    let (mut a, disk) = fixture(false);
    assert_eq!(
        a.open(r"\link", control()).unwrap_err().status,
        Status::AccessDenied
    );
    assert_eq!(
        a.open_reparse(r"\link", all()).unwrap_err().status,
        Status::AccessDenied
    );
    let h = a.open_reparse(r"\link", control()).unwrap();
    disk.arm(None);
    assert!(
        a.set_basic_info(
            h,
            BasicTimes {
                write: Some(133_000_000_000_000_000),
                ..Default::default()
            },
            None
        )
        .is_err()
    );
    assert!(a.write(h, 0, b"bad", false, false).is_err());
    assert_eq!(disk.0.lock().unwrap().calls, 0);
    assert_eq!(
        links::relative_symbolic_target(&a.reparse_by_handle(h).unwrap().unwrap()).unwrap(),
        "old"
    );
}
#[test]
fn shared_cleaned_readonly_and_escape_replacements_refuse_before_io() {
    for scenario in 0..5 {
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
        if scenario == 1 || scenario == 4 {
            let other = a.open_reparse(r"\link", OpenRequest::default()).unwrap();
            if scenario == 4 {
                a.cleanup(other, false).unwrap();
            }
        }
        if scenario == 2 {
            a.cleanup(h, false).unwrap();
        }
        disk.arm(None);
        let packet =
            links::symbolic_packet(if scenario == 3 { r"..\escape" } else { "new" }).unwrap();
        assert!(a.set_symbolic_link(h, &packet).is_err());
        assert_eq!(
            disk.0.lock().unwrap().calls,
            0,
            "refusal {scenario} wrote/flushed"
        );
    }
}

#[test]
fn interrupted_retarget_keeps_the_directory_hint_and_dates_with_its_target() {
    let (a, disk) = fixture(true);
    drop(a);
    let before = disk.snapshot(1, 0);
    let journal = match hfs_bridge::volume::inspect(&mut MemoryBackend::from_bytes(before.clone()))
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
        assert_eq!(info.attributes & 0x410, 0x410);
        let packet = a.reparse_by_path(r"\link").unwrap().unwrap();
        (
            links::relative_symbolic_target(&packet).unwrap(),
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
    a.set_symbolic_link(h, &links::symbolic_packet("new").unwrap())
        .unwrap();
    let calls = disk.0.lock().unwrap().calls;
    let mut checkpoints = 0;
    for failure in 0..calls {
        let disk = fault::Disk::new(&before);
        let mut a = Adapter::from_device(disk.clone()).unwrap();
        let h = a.open_reparse(r"\link", control()).unwrap();
        disk.arm(Some(failure));
        assert!(
            a.set_symbolic_link(h, &links::symbolic_packet("new").unwrap())
                .is_err()
        );
        drop(a);
        for policy in 0..6 {
            let state = observe(disk.snapshot(policy, journal));
            if state.0 == "old" {
                assert_eq!(state, old);
            } else {
                assert_eq!(state.0, "new");
                assert_eq!((state.1, state.2, state.3), (old.1, old.2, old.3));
                assert!(state.4 >= old.4);
                assert_eq!(state.4, state.5);
            }
            checkpoints += 1;
        }
    }
    println!("LINK_REPLACEMENT_ADAPTER: {checkpoints} persistence checkpoints");
}
