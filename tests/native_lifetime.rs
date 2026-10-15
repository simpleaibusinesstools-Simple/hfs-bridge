//! Native cleanup/replacement lifetime and persistence-boundary regression.
#![cfg(all(windows, feature = "native-mount"))]
use fstool::{
    block::{BlockDevice, MemoryBackend},
    fs::hfs_plus::{FormatOpts, HfsPlus},
};
use hfs_bridge::{
    engine,
    native::{Context, Native},
    volume,
    windows::{Access, Adapter, Kind, OpenRequest, Status},
};
use winfsp::{
    U16CString,
    filesystem::{FileInfo, FileSystemContext, OpenFileInfo},
};
#[path = "support/fault_disk.rs"]
mod fault;
use fault::Disk;

fn name(s: &str) -> U16CString {
    U16CString::from_str(s).unwrap()
}
fn info() -> OpenFileInfo {
    // No normalized-name buffer is supplied in these callback-level tests.
    unsafe { std::mem::zeroed() }
}
fn open<D: BlockDevice>(n: &Native<D>, path: &str) -> Context {
    n.open(&name(path), 0x40, 0x1011f, &mut info()).unwrap()
}
fn read<D: BlockDevice>(n: &Native<D>, file: &Context) -> Vec<u8> {
    let mut result = vec![0; 32];
    let count = n.read(file, &mut result, 0).unwrap() as usize;
    result.truncate(count);
    result
}
fn fixture(journaled: bool) -> Vec<u8> {
    hfs_bridge::native::load_runtime().unwrap();
    let mut disk = MemoryBackend::new(8 * 1024 * 1024);
    HfsPlus::format(
        &mut disk,
        &FormatOpts {
            journaled,
            ..Default::default()
        },
    )
    .unwrap();
    let mut a = Adapter::from_device(disk).unwrap();
    for (path, bytes) in [
        ("\\source", b"new source".as_slice()),
        ("\\target", b"old target"),
        ("\\survivor", b"unchanged"),
    ] {
        let f = a
            .create(
                path,
                Kind::File,
                OpenRequest {
                    access: Access::ALL,
                    ..Default::default()
                },
            )
            .unwrap();
        a.write(f, 0, bytes, false, false).unwrap();
        a.set_allocation_size(f, 65536).unwrap();
        a.close(f).unwrap();
    }
    a.shutdown().unwrap().into_bytes()
}

#[test]
fn native_replacement_preserves_both_live_payloads_and_new_name_identity() {
    for journaled in [false, true] {
        let n = Native::new(
            Adapter::from_device(MemoryBackend::from_bytes(fixture(journaled))).unwrap(),
        )
        .unwrap();
        let source = open(&n, "\\source");
        let target = open(&n, "\\target");
        assert!(
            n.rename(&source, &name("\\source"), &name("\\target"), true)
                .is_err()
        );
        n.cleanup(&target, None, 0);
        n.rename(&source, &name("\\source"), &name("\\target"), true)
            .unwrap();
        assert_eq!(read(&n, &target), b"old target");
        assert_eq!(read(&n, &source), b"new source");
        n.write(&target, b"OLD", 0, false, true, &mut FileInfo::default())
            .unwrap();
        let current = open(&n, "\\target");
        assert_eq!(read(&n, &current), b"new source");
        assert_eq!(read(&n, &target), b"OLD target");
        n.close(target);
        assert_eq!(read(&n, &current), b"new source");
        n.cleanup(&current, None, 0);
        n.close(current);
        n.cleanup(&source, None, 0);
        n.close(source);
        assert!(n.failure().is_none());
        n.flush_for_shutdown().unwrap();
    }
}

#[test]
fn native_unlink_allows_name_reuse_without_touching_retained_file() {
    let n = Native::new(Adapter::from_device(MemoryBackend::from_bytes(fixture(true))).unwrap())
        .unwrap();
    let old = open(&n, "\\target");
    n.cleanup(&old, None, 1);
    assert_eq!(
        n.open(&name("\\target"), 0x40, 1, &mut info())
            .err()
            .unwrap()
            .to_ntstatus(),
        Status::NotFound.ntstatus() as i32
    );
    let new = n
        .create(
            &name("\\target"),
            0x40,
            0x1011f,
            0x80,
            None,
            0,
            None,
            false,
            &mut info(),
        )
        .unwrap();
    n.write(
        &new,
        b"replacement",
        0,
        false,
        false,
        &mut FileInfo::default(),
    )
    .unwrap();
    assert_eq!(read(&n, &old), b"old target");
    n.write(&old, b"OLD", 0, false, true, &mut FileInfo::default())
        .unwrap();
    assert_eq!(read(&n, &new), b"replacement");
    n.close(old);
    assert_eq!(read(&n, &new), b"replacement");
    n.cleanup(&new, None, 0);
    n.close(new);
    n.flush_for_shutdown().unwrap();
}

fn attempt(bytes: &[u8], operation: usize, fail: Option<usize>) -> (bool, Disk) {
    let disk = Disk::new(bytes);
    let n = Native::new(Adapter::from_device(disk.clone()).unwrap()).unwrap();
    let source = open(&n, "\\source");
    let target = open(&n, "\\target");
    n.cleanup(&target, None, 0);
    disk.arm(fail);
    let success = match operation {
        0 => n
            .rename(&source, &name("\\source"), &name("\\target"), true)
            .is_ok(),
        1 => {
            n.cleanup(&source, None, 2);
            n.failure().is_none()
        }
        2 => {
            n.cleanup(&source, None, 1);
            n.failure().is_none()
        }
        _ => unreachable!(),
    };
    if !success {
        let calls = disk.0.lock().unwrap().calls;
        assert!(n.flush(Some(&source), &mut FileInfo::default()).is_err());
        n.close(target);
        n.close(source);
        assert_eq!(
            disk.0.lock().unwrap().calls,
            calls,
            "failed host retried persistence"
        );
    }
    // Deliberately abandon surviving contexts to model process death. No Drop
    // callback may publish metadata after the captured write/sync boundary.
    (success, disk)
}

#[test]
fn native_lifetime_failures_never_report_success_and_journal_replay_is_atomic() {
    let mut failures = 0;
    let mut snapshots = 0;
    for journaled in [false, true] {
        let bytes = fixture(journaled);
        let journal = if journaled {
            let jib = volume::be32(&bytes, 1036) as usize * volume::be32(&bytes, 1064) as usize;
            volume::be64(&bytes, jib + 36) as usize
        } else {
            0
        };
        for operation in 0..3 {
            let (success, complete) = attempt(&bytes, operation, None);
            assert!(success);
            let count = complete.0.lock().unwrap().calls;
            assert!(count > 0);
            for fail in 0..count {
                let (success, interrupted) = attempt(&bytes, operation, Some(fail));
                assert!(!success, "operation {operation}, fail {fail}/{count}");
                failures += 1;
                if !journaled {
                    continue;
                }
                for policy in 0..6 {
                    let mut recovered =
                        MemoryBackend::from_bytes(interrupted.snapshot(policy, journal));
                    // Explicit replay on synthetic bytes only, followed by the
                    // normal adapter orphan recovery and read-only assertions.
                    HfsPlus::open(&mut recovered).unwrap();
                    let mut a = Adapter::from_device(recovered).unwrap();
                    let source_exists = a.path_info("\\source").is_ok();
                    let mut recovered = a.shutdown().unwrap();
                    let target = engine::snapshot_device(&mut recovered, "/target", &[]).unwrap();
                    let old_hash = engine::sha256(&mut &b"old target"[..]).unwrap();
                    let new_hash = engine::sha256(&mut &b"new source"[..]).unwrap();
                    if operation == 0 {
                        assert_eq!(
                            target.data_sha256,
                            if source_exists {
                                old_hash
                            } else {
                                new_hash.clone()
                            }
                        );
                    } else {
                        assert_eq!(target.data_sha256, old_hash);
                    }
                    if source_exists {
                        assert_eq!(
                            engine::snapshot_device(&mut recovered, "/source", &[])
                                .unwrap()
                                .data_sha256,
                            new_hash
                        );
                    } else {
                        assert_ne!(operation, 1, "allocation cleanup lost source");
                    }
                    assert_eq!(
                        engine::snapshot_device(&mut recovered, "/survivor", &[])
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
        "Native lifetime: {failures} failing write/sync boundaries; {snapshots} journal recovery snapshots passed"
    );
}
