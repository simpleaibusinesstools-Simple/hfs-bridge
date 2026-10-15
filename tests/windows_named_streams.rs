use fstool::{
    block::MemoryBackend,
    fs::hfs_plus::{FormatOpts, HfsPlus},
};
use hfs_bridge::{
    named_streams, volume,
    windows::{Access, Adapter, BasicTimes, Handle, Kind, OpenRequest, Share, Status},
};
#[path = "support/fault_disk.rs"]
mod fault;

fn all() -> OpenRequest {
    OpenRequest {
        access: Access::ALL,
        ..Default::default()
    }
}
fn fixture() -> Vec<u8> {
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
        "/file",
        &mut &b"base payload"[..],
        12,
        0o644,
        501,
        20,
        1_700_000_000,
    )
    .unwrap();
    fs.create_dir(&mut disk, "/folder", 0o755, 501, 20, 1_700_000_000)
        .unwrap();
    fs.flush(&mut disk).unwrap();
    disk.into_bytes()
}
fn adapter() -> Adapter<MemoryBackend> {
    Adapter::from_device(MemoryBackend::from_bytes(fixture())).unwrap()
}
fn data<D: fstool::block::BlockDevice>(a: &mut Adapter<D>, h: Handle) -> Vec<u8> {
    let mut bytes = vec![0; a.file_info(h).unwrap().size as usize];
    assert_eq!(a.read(h, 0, &mut bytes).unwrap(), bytes.len());
    bytes
}
fn finish<D: fstool::block::BlockDevice>(a: &mut Adapter<D>, h: Handle) {
    a.cleanup(h, false).unwrap();
    a.close(h).unwrap();
}

#[test]
fn refused_owned_edit_reloads_committed_stream_and_allows_later_writes() {
    let mut a = adapter();
    let h = a.create("\\file:owned", Kind::File, all()).unwrap();
    let mut expected = vec![0x71; 256 * 1024];
    a.write(h, 0, &expected, false, false).unwrap();
    let old = a.file_info(h).unwrap();
    // The payload alone fits the numeric limit, but the encoded container's
    // headers exceed it. This refuses inside the owned plan after cache removal.
    assert_eq!(
        a.set_size(h, named_streams::MAX_BYTES as u64)
            .unwrap_err()
            .status,
        Status::InvalidParameter
    );
    let current = a.file_info(h).unwrap();
    assert_eq!(
        (
            current.cnid,
            current.size,
            current.allocation_size,
            current.attributes,
            current.creation_time,
            current.access_time,
            current.write_time,
            current.change_time
        ),
        (
            old.cnid,
            old.size,
            old.allocation_size,
            old.attributes,
            old.creation_time,
            old.access_time,
            old.write_time,
            old.change_time
        ),
    );
    assert_eq!(data(&mut a, h), expected);
    a.write(h, 17, b"updated", false, false).unwrap();
    expected[17..24].copy_from_slice(b"updated");
    assert_eq!(data(&mut a, h), expected);
    finish(&mut a, h);
    let mut reopened = Adapter::from_device(a.shutdown().unwrap()).unwrap();
    let h = reopened.open("\\file:owned", all()).unwrap();
    assert_eq!(data(&mut reopened, h), expected);
    finish(&mut reopened, h);
    reopened.shutdown().unwrap();
}

#[test]
fn repeated_small_stream_reads_are_bounded_and_mutations_stay_visible() {
    use std::{
        io::{self, Read, Seek, SeekFrom, Write},
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
    };
    struct CountReads {
        inner: MemoryBackend,
        bytes: Arc<AtomicUsize>,
    }
    impl Read for CountReads {
        fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
            let n = self.inner.read(b)?;
            self.bytes.fetch_add(n, Ordering::Relaxed);
            Ok(n)
        }
    }
    impl Seek for CountReads {
        fn seek(&mut self, p: SeekFrom) -> io::Result<u64> {
            self.inner.seek(p)
        }
    }
    impl Write for CountReads {
        fn write(&mut self, b: &[u8]) -> io::Result<usize> {
            self.inner.write(b)
        }
        fn flush(&mut self) -> io::Result<()> {
            self.inner.flush()
        }
    }
    impl fstool::block::BlockDevice for CountReads {
        fn block_size(&self) -> u32 {
            512
        }
        fn total_size(&self) -> u64 {
            self.inner.total_size()
        }
        fn sync(&mut self) -> fstool::Result<()> {
            self.inner.sync()
        }
    }
    let reads = Arc::new(AtomicUsize::new(0));
    let mut a = Adapter::from_device(CountReads {
        inner: MemoryBackend::from_bytes(fixture()),
        bytes: reads.clone(),
    })
    .unwrap();
    let stream = a.create("\\file:large", Kind::File, all()).unwrap();
    let payload = vec![0x7d; 256 * 1024];
    a.write(stream, 0, &payload, false, false).unwrap();
    assert_eq!(data(&mut a, stream), payload);
    reads.store(0, Ordering::Relaxed);
    for i in 0..32 {
        let mut piece = [0; 512];
        assert_eq!(a.read(stream, i * 512, &mut piece).unwrap(), 512);
        assert_eq!(piece, [0x7d; 512]);
    }
    let repeated_read_bytes = reads.load(Ordering::Relaxed);
    println!("NAMED_STREAM_READ_BYTES={repeated_read_bytes}");
    assert!(
        repeated_read_bytes < 1024 * 1024,
        "32 tiny reads reload the entire stream container: {repeated_read_bytes}"
    );
    a.write(stream, 513, b"changed", false, false).unwrap();
    let mut expected = payload;
    expected[513..520].copy_from_slice(b"changed");
    assert_eq!(data(&mut a, stream), expected);
    let other = a.create("\\file:other", Kind::File, all()).unwrap();
    a.write(other, 0, b"second", false, false).unwrap();
    assert_eq!(data(&mut a, stream), expected);
    assert_eq!(data(&mut a, other), b"second");
    let different_file = a.create("\\folder:other", Kind::File, all()).unwrap();
    a.write(different_file, 0, b"another base", false, false)
        .unwrap();
    assert_eq!(data(&mut a, different_file), b"another base");
    assert_eq!(data(&mut a, stream), expected);
    finish(&mut a, different_file);
    a.cleanup(other, true).unwrap();
    a.close(other).unwrap();
    assert_eq!(
        a.open("\\file:other", all()).unwrap_err().status,
        Status::NotFound
    );
    finish(&mut a, stream);
    let disk = a.shutdown().unwrap();
    let mut reopened = Adapter::from_device(disk).unwrap();
    let stream = reopened.open("\\file:large", all()).unwrap();
    assert_eq!(data(&mut reopened, stream), expected);
    finish(&mut reopened, stream);
    reopened.shutdown().unwrap();
}

#[test]
fn stream_roundtrip_spelling_unicode_and_directory_contexts() {
    let mut a = adapter();
    let long = "s".repeat(255);
    for (i, name) in ["Zone.Identifier", "é", "e\u{301}", &long]
        .iter()
        .enumerate()
    {
        let h = a
            .create(&format!("\\file:{name}:$DATA"), Kind::File, all())
            .unwrap();
        a.write(h, 3, &[i as u8 + 1; 21], false, false).unwrap();
        assert_eq!(
            a.extended_attributes(h).unwrap_err().status,
            Status::Unsupported
        );
        finish(&mut a, h);
    }
    let h = a.open("\\file:ZONE.IDENTIFIER", all()).unwrap();
    assert_eq!(data(&mut a, h), [vec![0; 3], vec![1; 21]].concat());
    assert_eq!(
        a.create("\\file:zone.identifier", Kind::File, all())
            .unwrap_err()
            .status,
        Status::Collision
    );
    finish(&mut a, h);
    let h = a.create("\\folder:notes", Kind::File, all()).unwrap();
    a.write(h, 0, b"directory data", false, false).unwrap();
    assert_eq!(a.file_info(h).unwrap().kind, Kind::File);
    assert_eq!(
        a.read_directory(h).unwrap_err().status,
        Status::NotDirectory
    );
    finish(&mut a, h);
    let disk = a.shutdown().unwrap();
    let mut a = Adapter::from_device(disk).unwrap();
    let h = a.open("\\file", all()).unwrap();
    assert_eq!(data(&mut a, h), b"base payload");
    let names = a
        .streams(h)
        .unwrap()
        .into_iter()
        .map(|(n, _)| n)
        .collect::<Vec<_>>();
    assert_eq!(names, ["", "Zone.Identifier", "é", "e\u{301}", &long]);
    finish(&mut a, h);
    let h = a.open("\\folder:NOTES", all()).unwrap();
    assert_eq!(data(&mut a, h), b"directory data");
    finish(&mut a, h);
    a.shutdown().unwrap();
}

#[test]
fn stream_edits_preserve_base_data_times_and_exact_allocation_rules() {
    let mut a = adapter();
    let base = a.open("\\file", all()).unwrap();
    let exact = 133_444_736_009_876_543;
    a.set_basic_info(
        base,
        BasicTimes {
            creation: Some(exact),
            access: Some(exact),
            write: Some(exact),
            change: Some(exact),
        },
        None,
    )
    .unwrap();
    let h = a
        .create_initialized("\\file:payload", Kind::File, all(), None, 20019)
        .unwrap();
    assert_eq!(a.file_info(h).unwrap().allocation_size, 20480);
    a.write(h, 0, &vec![7; 12001], false, false).unwrap();
    a.set_allocation_size(h, 4097).unwrap();
    assert_eq!(a.file_info(h).unwrap().size, 8192);
    a.set_size(h, 10001).unwrap();
    assert_eq!(data(&mut a, h), [vec![7; 8192], vec![0; 1809]].concat());
    a.write(h, 9999, b"tail!", false, true).unwrap();
    assert_eq!(&data(&mut a, h)[9999..], b"ta");
    a.write(h, 0, b"appended", true, false).unwrap();
    assert!(data(&mut a, h).ends_with(b"appended"));
    let info = a.file_info(base).unwrap();
    assert_eq!(info.creation_time, exact);
    assert_eq!(info.access_time, exact);
    assert!(info.write_time > exact);
    assert_eq!(info.write_time, info.change_time);
    assert_ne!(info.attributes & 0x20, 0);
    assert_eq!(data(&mut a, base), b"base payload");
    a.overwrite(h, 0x80, true, 4097).unwrap();
    assert_eq!(a.file_info(h).unwrap().size, 0);
    assert_eq!(a.file_info(h).unwrap().allocation_size, 8192);
    finish(&mut a, h);
    finish(&mut a, base);
    a.shutdown().unwrap();
}

#[test]
fn explicit_stream_dates_survive_edits_but_do_not_leak_to_new_handles() {
    let mut a = adapter();
    let base = a.open("\\file", all()).unwrap();
    let stream = a.create("\\file:dates", Kind::File, all()).unwrap();
    let exact = 0x4100000041;
    a.set_basic_times(
        stream,
        BasicTimes {
            creation: Some(exact),
            access: Some(exact),
            write: Some(exact),
            change: Some(exact),
        },
    )
    .unwrap();
    a.set_size(stream, 42).unwrap();
    a.write(stream, 0, b"keep explicit dates", false, false)
        .unwrap();
    a.set_allocation_size(stream, 8192).unwrap();
    for handle in [base, stream] {
        let info = a.file_info(handle).unwrap();
        assert_eq!(
            [
                info.creation_time,
                info.access_time,
                info.write_time,
                info.change_time
            ],
            [exact; 4]
        );
    }
    finish(&mut a, stream);
    finish(&mut a, base);
    let mut a = Adapter::from_device(a.shutdown().unwrap()).unwrap();
    let reopened = a.open("\\file:dates", all()).unwrap();
    assert_eq!(a.file_info(reopened).unwrap().write_time, exact);
    a.write(reopened, 0, b"new handle", false, false).unwrap();
    let info = a.file_info(reopened).unwrap();
    assert_eq!(info.creation_time, exact);
    assert_eq!(info.access_time, exact);
    assert!(info.write_time > exact);
    assert_eq!(info.write_time, info.change_time);
    finish(&mut a, reopened);
    a.shutdown().unwrap();
}

#[test]
fn sharing_is_stream_specific_but_base_delete_covers_all_streams() {
    let mut a = adapter();
    for name in ["one", "two"] {
        let h = a
            .create(&format!("\\file:{name}"), Kind::File, all())
            .unwrap();
        finish(&mut a, h);
    }
    let held = a
        .open(
            "\\file:ONE",
            OpenRequest {
                access: Access::READ,
                share: Share {
                    read: true,
                    write: false,
                    delete: false,
                },
                kind: None,
            },
        )
        .unwrap();
    assert_eq!(
        a.open("\\file:one:$DATA", all()).unwrap_err().status,
        Status::SharingViolation
    );
    let writer = OpenRequest {
        access: Access {
            write: true,
            ..Default::default()
        },
        ..Default::default()
    };
    for path in ["\\file", "\\file:two"] {
        let h = a.open(path, writer).unwrap();
        finish(&mut a, h);
    }
    assert_eq!(
        a.open("\\file", all()).unwrap_err().status,
        Status::SharingViolation
    );
    a.cleanup(held, false).unwrap();
    let h = a.open("\\file:one", all()).unwrap();
    finish(&mut a, h);
    a.close(held).unwrap();
    let base = a
        .open(
            "\\file",
            OpenRequest {
                access: Access {
                    delete: true,
                    ..Default::default()
                },
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(
        a.open(
            "\\file:two",
            OpenRequest {
                share: Share {
                    delete: false,
                    ..Share::ALL
                },
                ..Default::default()
            }
        )
        .unwrap_err()
        .status,
        Status::SharingViolation
    );
    finish(&mut a, base);
    a.shutdown().unwrap();
}

#[test]
fn deleted_stream_handles_cannot_republish_or_change_recreated_name() {
    let mut a = adapter();
    let old = a.create("\\file:one", Kind::File, all()).unwrap();
    a.write(old, 0, b"old", false, false).unwrap();
    let other = a.open("\\file:ONE", all()).unwrap();
    a.cleanup(old, true).unwrap();
    assert_eq!(
        a.open("\\file:one", all()).unwrap_err().status,
        Status::NotFound
    );
    let new = a.create("\\file:one", Kind::File, all()).unwrap();
    a.write(new, 0, b"new", false, false).unwrap();
    a.write(other, 0, b"detached", false, false).unwrap();
    assert_eq!(data(&mut a, old), b"detached");
    assert_eq!(data(&mut a, new), b"new");
    a.cleanup(other, true).unwrap();
    a.close(other).unwrap();
    a.close(old).unwrap();
    finish(&mut a, new);
    let mut a = Adapter::from_device(a.shutdown().unwrap()).unwrap();
    let h = a.open("\\file:one", all()).unwrap();
    assert_eq!(data(&mut a, h), b"new");
    finish(&mut a, h);
    a.shutdown().unwrap();
}

#[test]
fn base_rename_replace_and_deferred_deletion_keep_named_handle_identity() {
    let mut a = adapter();
    let base = a.open("\\file", all()).unwrap();
    let h = a.create("\\file:one", Kind::File, all()).unwrap();
    a.write(h, 0, b"old data", false, false).unwrap();
    a.rename(base, "\\renamed").unwrap();
    assert_eq!(data(&mut a, h), b"old data");
    a.cleanup(base, true).unwrap();
    a.close(base).unwrap();
    // Non-kernel cleanup keeps the name delete-pending until the old handles
    // close. The distinct base must remain independent throughout reclamation.
    assert_eq!(
        a.open("\\renamed", all()).unwrap_err().status,
        Status::DeletePending
    );
    let newbase = a.create("\\newbase", Kind::File, all()).unwrap();
    let new = a.create("\\newbase:one", Kind::File, all()).unwrap();
    a.write(new, 0, b"new", false, false).unwrap();
    a.write(h, 0, b"retained", false, false).unwrap();
    assert_eq!(data(&mut a, new), b"new");
    finish(&mut a, h);
    finish(&mut a, new);
    finish(&mut a, newbase);
    a.shutdown().unwrap();
}

#[test]
fn invalid_names_bounds_and_readonly_refuse_without_poisoning_or_data_changes() {
    let mut a = adapter();
    let h = a.create("\\file:ok", Kind::File, all()).unwrap();
    a.write(h, 0, b"keep", false, false).unwrap();
    for name in ["", "no:$INDEX", "bad\\name", &"x".repeat(256)] {
        assert!(
            a.create(&format!("\\file:{name}"), Kind::File, all())
                .is_err()
        );
    }
    assert!(a.set_size(h, named_streams::MAX_BYTES as u64).is_err());
    assert!(a.set_allocation_size(h, u64::MAX).is_err());
    assert_eq!(data(&mut a, h), b"keep");
    assert!(a.failure().is_none());
    finish(&mut a, h);
    let base = a.open("\\file", all()).unwrap();
    a.set_basic_info(base, BasicTimes::default(), Some(1))
        .unwrap();
    finish(&mut a, base);
    assert_eq!(
        a.open("\\file:ok", all()).unwrap_err().status,
        Status::AccessDenied
    );
    assert_eq!(
        a.create("\\file:new", Kind::File, all())
            .unwrap_err()
            .status,
        Status::AccessDenied
    );
    let h = a.open("\\file:ok", Default::default()).unwrap();
    assert_eq!(data(&mut a, h), b"keep");
    finish(&mut a, h);
    a.shutdown().unwrap();
}

#[test]
fn base_overwrite_detaches_old_streams_and_preserves_new_identity() {
    let mut a = adapter();
    let base = a.open("\\file", all()).unwrap();
    let old = a.create("\\file:one", Kind::File, all()).unwrap();
    a.write(old, 0, b"old contents", false, false).unwrap();
    let two = a.create("\\file:two", Kind::File, all()).unwrap();
    finish(&mut a, two);
    a.overwrite(base, 0x80, true, 0).unwrap();
    assert!(data(&mut a, base).is_empty());
    assert_eq!(
        a.open("\\file:one", all()).unwrap_err().status,
        Status::DeletePending
    );
    assert_eq!(
        a.open("\\file:two", all()).unwrap_err().status,
        Status::NotFound
    );
    assert_eq!(data(&mut a, old), b"old contents");
    a.cleanup(old, false).unwrap();
    let new = a.create("\\file:one", Kind::File, all()).unwrap();
    a.write(new, 0, b"replacement", false, false).unwrap();
    a.write(old, 0, b"OLD", false, false).unwrap();
    assert_eq!(data(&mut a, new), b"replacement");
    a.close(old).unwrap();
    finish(&mut a, new);
    finish(&mut a, base);
    let disk = a.shutdown().unwrap();
    let mut a = Adapter::from_device(disk).unwrap();
    let h = a.open("\\file:one", all()).unwrap();
    assert_eq!(data(&mut a, h), b"replacement");
    finish(&mut a, h);
    assert_eq!(
        a.open("\\file:two", all()).unwrap_err().status,
        Status::NotFound
    );
    a.shutdown().unwrap();
}

#[test]
fn overwrite_removes_named_streams_and_base_data_in_one_recoverable_transaction() {
    let mut a = adapter();
    let h = a.create("\\file:one", Kind::File, all()).unwrap();
    a.write(h, 0, &vec![7; 12001], false, false).unwrap();
    finish(&mut a, h);
    let bytes = a.shutdown().unwrap().into_bytes();
    let info = volume::be32(&bytes, 1036) as usize * volume::be32(&bytes, 1064) as usize;
    let journal = volume::be64(&bytes, info + 36) as usize;
    let run = |fail| {
        let disk = fault::Disk::new(&bytes);
        let mut a = Adapter::from_device(disk.clone()).unwrap();
        let base = a.open("\\file", all()).unwrap();
        disk.arm(fail);
        let result = a.overwrite(base, 0x80, true, 0);
        let calls = disk.0.lock().unwrap().calls;
        if result.is_err() {
            assert!(a.failure().is_some());
            assert!(a.flush(None).is_err());
            assert_eq!(calls, disk.0.lock().unwrap().calls);
        }
        (disk, calls, result.is_ok())
    };
    let (_, calls, pass) = run(None);
    assert!(pass);
    let mut count = 0;
    for stop in 0..=calls {
        let (disk, _, _) = run(Some(stop));
        for policy in 0..6 {
            let mut recovered = MemoryBackend::from_bytes(disk.snapshot(policy, journal));
            HfsPlus::open(&mut recovered).unwrap();
            let mut a = Adapter::from_device(recovered).unwrap();
            let h = a.open("\\file", all()).unwrap();
            let payload = data(&mut a, h);
            finish(&mut a, h);
            if payload == b"base payload" {
                let h = a.open("\\file:one", all()).unwrap();
                assert_eq!(data(&mut a, h), vec![7; 12001]);
                finish(&mut a, h);
            } else {
                assert!(payload.is_empty());
                assert_eq!(
                    a.open("\\file:one", all()).unwrap_err().status,
                    Status::NotFound
                );
            }
            a.shutdown().unwrap();
            count += 1;
        }
    }
    println!("named overwrite fault snapshots: {count}");
}

#[test]
fn named_payload_catalog_and_precision_commit_together_at_each_fault_boundary() {
    let mut a = adapter();
    let h = a.create("\\file:one", Kind::File, all()).unwrap();
    a.write(h, 0, b"old", false, false).unwrap();
    finish(&mut a, h);
    let bytes = a.shutdown().unwrap().into_bytes();
    let info = volume::be32(&bytes, 1036) as usize * volume::be32(&bytes, 1064) as usize;
    let journal = volume::be64(&bytes, info + 36) as usize;
    let old = {
        let mut a = Adapter::from_device(MemoryBackend::from_bytes(bytes.clone())).unwrap();
        a.path_info("\\file").unwrap().write_time
    };
    let run = |fail| {
        let disk = fault::Disk::new(&bytes);
        let mut a = Adapter::from_device(disk.clone()).unwrap();
        let h = a.open("\\file:one", all()).unwrap();
        disk.arm(fail);
        let result = a.write(h, 0, &vec![19; 20019], false, false);
        let calls = disk.0.lock().unwrap().calls;
        if result.is_err() {
            assert!(a.failure().is_some());
            assert!(a.flush(None).is_err());
            assert_eq!(calls, disk.0.lock().unwrap().calls);
        }
        (disk, calls, result.is_ok())
    };
    let (_, calls, pass) = run(None);
    assert!(pass);
    let mut count = 0;
    for stop in 0..=calls {
        let (disk, _, _) = run(Some(stop));
        for policy in 0..6 {
            // Explicit recovery is part of this disposable simulator. The
            // production adapter correctly refuses an unreplayed journal.
            let mut recovered = MemoryBackend::from_bytes(disk.snapshot(policy, journal));
            HfsPlus::open(&mut recovered).unwrap();
            let mut a = Adapter::from_device(recovered).unwrap();
            let h = a.open("\\file:one", all()).unwrap();
            let payload = data(&mut a, h);
            let meta = a.path_info("\\file").unwrap();
            if payload == b"old" {
                assert_eq!(meta.write_time, old);
            } else {
                assert_eq!(payload, vec![19; 20019]);
                assert!(meta.write_time > old);
                assert_eq!(meta.write_time, meta.change_time);
            }
            finish(&mut a, h);
            a.shutdown().unwrap();
            count += 1;
        }
    }
    println!("named adapter fault snapshots: {count}");
}
