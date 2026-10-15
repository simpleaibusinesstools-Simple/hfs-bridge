//! Actual Windows constructor/reservation callbacks publish one complete state.
use fstool::{
    block::MemoryBackend,
    fs::hfs_plus::{FormatOpts, HfsPlus},
};
use hfs_bridge::{
    ea::Change,
    volume,
    windows::{Access, Adapter, Handle, Kind, OpenRequest, Status},
};
use std::{
    io::{Read, Write},
    path::Path,
};
#[path = "support/fault_disk.rs"]
mod fault;

fn all() -> OpenRequest {
    OpenRequest {
        access: Access::ALL,
        ..Default::default()
    }
}
fn fixture(journaled: bool, sensitive: bool) -> Vec<u8> {
    let mut d = MemoryBackend::new(8 * 1024 * 1024);
    let fs = HfsPlus::format(
        &mut d,
        &FormatOpts {
            journaled,
            ..Default::default()
        },
    )
    .unwrap();
    drop(fs);
    if sensitive {
        let mut bytes = d.into_bytes();
        bytes[1024..1026].copy_from_slice(b"HX");
        bytes[1026..1028].copy_from_slice(&5u16.to_be_bytes());
        let cat = volume::be32(&bytes, 1312) as usize * 4096;
        bytes[cat + 51] = 0xbc;
        let header = bytes[1024..1536].to_vec();
        let alt = bytes.len() - 1024;
        bytes[alt..alt + 512].copy_from_slice(&header);
        d = MemoryBackend::from_bytes(bytes);
    }
    let mut fs = HfsPlus::open(&mut d).unwrap();
    for (name, data) in [("/file", &b"original"[..]), ("/empty", &b""[..])] {
        fs.create_file(
            &mut d,
            name,
            &mut &data[..],
            data.len() as u64,
            0o644,
            501,
            20,
            1_700_000_000,
        )
        .unwrap();
    }
    fs.flush(&mut d).unwrap();
    let mut f = fs
        .open_resource_fork_rw(&mut d, Path::new("/file"))
        .unwrap();
    f.write_all(b"resource").unwrap();
    f.sync().unwrap();
    drop(f);
    d.into_bytes()
}
fn changes() -> [Change; 1] {
    [Change {
        name: "com.example.constructor".into(),
        value: Some(vec![0x55; 6001]),
    }]
}
fn perform(
    a: &mut Adapter<fault::Disk>,
    h: Handle,
    operation: usize,
) -> hfs_bridge::windows::Result<()> {
    let changes = changes();
    match operation {
        0 => a
            .create_initialized_with_ea("\\new", Kind::File, all(), Some(0x22), 12288, &changes)
            .map(|_| ()),
        1 | 2 | 5 => a.overwrite_with_ea(
            h,
            0x22,
            true,
            if operation == 5 { 0 } else { 12288 },
            if operation == 2 { &[] } else { &changes },
        ),
        3 => a.set_allocation_size(h, 12288),
        4 => a.set_allocation_size(h, 0),
        _ => unreachable!(),
    }
}
fn path(operation: usize) -> &'static str {
    match operation {
        2 => "\\file:AFP_Resource",
        5 => "\\empty",
        _ => "\\file",
    }
}
#[derive(Debug, PartialEq)]
struct Entry {
    path: &'static str,
    cnid: u32,
    attributes: u16,
    dates: [bool; 4],
    allocation: [u32; 2],
    data: Vec<u8>,
    resource: Vec<u8>,
    attribute: Option<Vec<u8>>,
}
#[derive(Debug, PartialEq)]
struct Observation {
    entries: Vec<Entry>,
    counter: u32,
    free: u32,
    root_dates: [bool; 2],
}
fn observe(bytes: Vec<u8>) -> Observation {
    let mut d = MemoryBackend::from_bytes(bytes);
    let fs = HfsPlus::open(&mut d).unwrap(); // replays a pending journal, if present
    let root = fs.catalog_record_cnid(2).unwrap();
    let mut entries = Vec::new();
    for name in ["/file", "/empty", "/new"] {
        let Ok(body) = fs.catalog_record(name) else {
            continue;
        };
        let cnid = volume::be32(&body, 8);
        let mut data = Vec::new();
        fs.open_file_reader(&mut d, name)
            .unwrap()
            .read_to_end(&mut data)
            .unwrap();
        let mut resource = Vec::new();
        if volume::be64(&body, 168) != 0 {
            fs.open_resource_fork_reader(&mut d, name)
                .unwrap()
                .read_to_end(&mut resource)
                .unwrap();
        }
        let date = |offset| volume::be32(&body, offset) > 3_790_000_000;
        if name == "/new" {
            assert_eq!(volume::be32(&body, 12), volume::be32(&body, 16));
            assert_eq!(volume::be32(&body, 12), volume::be32(&body, 20));
            assert_eq!(volume::be32(&body, 12), volume::be32(&body, 24));
            assert_eq!(volume::be32(&root, 16), volume::be32(&body, 12));
            assert_eq!(volume::be32(&root, 20), volume::be32(&body, 12));
        }
        entries.push(Entry {
            path: name,
            cnid,
            attributes: volume::be16(&body, 56),
            dates: [date(12), date(24), date(16), date(20)],
            allocation: [volume::be32(&body, 100), volume::be32(&body, 180)],
            data,
            resource,
            attribute: fs
                .inline_attribute(&mut d, cnid, "com.example.constructor")
                .unwrap(),
        });
    }
    Observation {
        entries,
        counter: volume::be32(d.as_slice(), 1092),
        free: volume::be32(d.as_slice(), 1072),
        root_dates: [
            volume::be32(&root, 16) > 3_790_000_000,
            volume::be32(&root, 20) > 3_790_000_000,
        ],
    }
}
fn retain(name: &str, bytes: &[u8]) {
    if let Some(dir) = std::env::var_os("HFS_CONSTRUCTOR_EXPORT") {
        let target = std::path::PathBuf::from(dir);
        std::fs::create_dir_all(&target).unwrap();
        let mut f = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(target.join(name))
            .unwrap();
        f.write_all(bytes).unwrap();
    }
}
#[test]
fn constructor_overwrite_and_allocation_publish_once_on_hfs_plus_and_hfsx() {
    for journaled in [false, true] {
        for sensitive in [false, true] {
            for operation in 0..6 {
                let before = fixture(journaled, sensitive);
                let disk = fault::Disk::new(&before);
                let observer = disk.clone();
                let mut a = Adapter::from_device(disk).unwrap();
                let h = a.open(path(operation), all()).unwrap();
                observer.arm(None);
                perform(&mut a, h, operation).unwrap();
                let saved = observer.snapshot(0, 0);
                assert_eq!(volume::be32(&saved, 1092), volume::be32(&before, 1092) + 1);
                let observed = observe(saved.clone());
                let target = observed
                    .entries
                    .iter()
                    .find(|e| {
                        e.path
                            == match operation {
                                0 => "/new",
                                5 => "/empty",
                                _ => "/file",
                            }
                    })
                    .unwrap();
                if operation == 0 || operation == 1 || operation == 5 {
                    assert_eq!(target.attribute, Some(vec![0x55; 6001]));
                }
                match operation {
                    0 | 1 => {
                        assert!(target.data.is_empty());
                        assert_eq!(target.allocation[0], 3);
                    }
                    2 => {
                        assert!(target.resource.is_empty());
                        assert_eq!(target.allocation[1], 3);
                        assert_eq!(target.data, b"original");
                    }
                    3 => {
                        assert_eq!(target.data, b"original");
                        assert_eq!(target.allocation[0], 3);
                    }
                    4 | 5 => {
                        assert!(target.data.is_empty());
                        assert_eq!(target.allocation[0], 0);
                    }
                    _ => unreachable!(),
                }
                if operation != 0 && operation != 2 && operation != 5 {
                    assert_eq!(target.resource, b"resource");
                }
                retain(
                    &format!("constructor-{journaled}-{sensitive}-{operation}.img"),
                    &saved,
                );
                a.close(h).unwrap();
            }
        }
    }
}
#[test]
fn interrupted_constructor_and_overwrite_recover_complete_metadata_without_retry() {
    let mut checks = 0;
    for sensitive in [false, true] {
        for operation in [0, 1, 2, 4, 5] {
            let baseline = fixture(true, sensitive);
            let old = observe(baseline.clone());
            let jib = volume::be32(&baseline, 1036) as usize * 4096;
            let journal = volume::be64(&baseline, jib + 36) as usize;
            let disk = fault::Disk::new(&baseline);
            let observer = disk.clone();
            let mut a = Adapter::from_device(disk).unwrap();
            let h = a.open(path(operation), all()).unwrap();
            observer.arm(None);
            perform(&mut a, h, operation).unwrap();
            let calls = observer.0.lock().unwrap().calls;
            let new = observe(observer.snapshot(0, 0));
            drop(a);
            for stop in 0..calls {
                let disk = fault::Disk::new(&baseline);
                let observer = disk.clone();
                let mut a = Adapter::from_device(disk).unwrap();
                let h = a.open(path(operation), all()).unwrap();
                observer.arm(Some(stop));
                assert!(perform(&mut a, h, operation).is_err());
                assert!(a.failure().is_some(), "operation {operation} stop {stop}");
                let calls = observer.0.lock().unwrap().calls;
                assert_eq!(a.file_info(h).unwrap_err().status, Status::FailedVolume);
                assert!(a.close(h).is_err());
                assert!(a.shutdown().is_err());
                assert_eq!(observer.0.lock().unwrap().calls, calls);
                for policy in 0..6 {
                    let actual = observe(observer.snapshot(policy, journal));
                    assert!(
                        actual == old || actual == new,
                        "operation{operation} stop{stop} policy{policy}: {actual:?}"
                    );
                    checks += 1;
                }
            }
        }
    }
    println!(
        "WINDOWS_CONSTRUCTOR_PUBLICATION: {checks} persistence snapshots; 10 scenarios; no failed publication acknowledged or retried"
    );
}
#[test]
fn constructor_refusal_and_same_allocation_leave_bytes_and_adapter_healthy() {
    let baseline = fixture(true, false);
    let disk = fault::Disk::new(&baseline);
    let observer = disk.clone();
    let mut a = Adapter::from_device(disk).unwrap();
    let h = a.open("\\file", all()).unwrap();
    for invalid in [
        vec![Change {
            name: "com.apple.decmpfs".into(),
            value: Some(vec![0; 32]),
        }],
        vec![
            Change {
                name: "duplicate".into(),
                value: Some(vec![1])
            };
            2
        ],
    ] {
        observer.arm(None);
        assert!(
            a.create_initialized_with_ea("\\new", Kind::File, all(), Some(0x20), 8192, &invalid)
                .is_err()
        );
        assert!(a.failure().is_none());
        assert_eq!(observer.0.lock().unwrap().calls, 0);
        assert!(observer.snapshot(1, 0) == baseline);
    }
    observer.arm(None);
    a.set_allocation_size(h, 4096).unwrap();
    assert_eq!(observer.0.lock().unwrap().calls, 0);
    a.close(h).unwrap();
    a.shutdown().unwrap();
    assert!(observer.snapshot(0, 0) == baseline);
}
