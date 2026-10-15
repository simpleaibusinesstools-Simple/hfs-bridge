use super::*;
use hfs_bridge::{
    named_streams as wire,
    windows::{Handle, Kind},
};
fn all() -> OpenRequest {
    OpenRequest {
        access: Access::ALL,
        ..Default::default()
    }
}
fn read<D: fstool::block::BlockDevice>(a: &mut Adapter<D>, h: Handle) -> Vec<u8> {
    let mut bytes = vec![0; a.file_info(h).unwrap().size as usize];
    assert_eq!(a.read(h, 0, &mut bytes).unwrap(), bytes.len());
    bytes
}
fn verify(bytes: Vec<u8>, plain: &[u8], user_resource: bool, operation: usize) {
    let mut d = MemoryBackend::from_bytes(bytes);
    let fs = HfsPlus::open(&mut d).unwrap();
    let body = fs.catalog_record("/compressed").unwrap();
    let id = volume::be32(&body, 8);
    let compressed = body[41] & 0x20 != 0;
    let mut data = Vec::new();
    fs.open_file_reader(&mut d, "/compressed")
        .unwrap()
        .read_to_end(&mut data)
        .unwrap();
    assert_eq!(data, plain);
    assert_eq!(
        fs.inline_attribute(&mut d, id, "com.example.note")
            .unwrap()
            .unwrap(),
        b"keep"
    );
    assert_eq!(
        fs.inline_attribute(&mut d, id, "com.apple.decmpfs")
            .unwrap()
            .is_some(),
        compressed
    );
    let store = wire::decode(
        &fs.inline_attribute(&mut d, id, wire::ATTRIBUTE)
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    let prior = store.find("prior").unwrap();
    let created = store.find("new").unwrap();
    if compressed {
        assert_eq!(prior.unwrap().data, b"old stream");
        assert!(created.is_none());
    } else {
        match operation {
            0 => {
                assert_eq!(prior.unwrap().data, b"old stream");
                assert_eq!(created.unwrap().allocation, 73728);
                assert!(created.unwrap().data.is_empty());
            }
            1 => {
                assert_eq!(prior.unwrap().data, b"new stream");
                assert!(created.is_none());
            }
            2 => {
                assert!(prior.is_none());
                assert!(created.is_none());
            }
            _ => unreachable!(),
        }
    }
    if user_resource {
        let mut resource = Vec::new();
        fs.open_resource_fork_reader(&mut d, "/compressed")
            .unwrap()
            .read_to_end(&mut resource)
            .unwrap();
        assert_eq!(resource, b"user resource");
    } else if !compressed {
        assert_eq!(&body[168..248], &[0; 80]);
    }
}
#[test]
fn named_stream_conversion_preserves_decoded_data_user_metadata_and_live_readers() {
    let mut count = 0;
    for kind in [1, 3, 4, 7, 8, 9, 10, 11, 12, 13, 14] {
        let resource = matches!(kind, 1 | 3 | 7 | 9 | 11 | 13);
        for journal in [false, true] {
            for sensitive in [false, true] {
                let (d, plain) = fixture_with_named(kind, journal, sensitive, resource, true);
                let source = d.as_slice().to_vec();
                let observer = faults::Disk::new(&source);
                let mut a = Adapter::from_device(observer.clone()).unwrap();
                let base = a.open("\\compressed", all()).unwrap();
                let old = a.open("\\compressed:prior", all()).unwrap();
                observer.arm(None);
                assert_eq!(read(&mut a, old), b"old stream");
                a.write(old, 0, b"", false, false).unwrap();
                a.set_size(old, 10).unwrap();
                assert_eq!(
                    observer.0.lock().unwrap().calls,
                    0,
                    "opens and no-op edits must preserve compression"
                );
                let h = a
                    .create_initialized("\\compressed:new", Kind::File, all(), None, 70019)
                    .unwrap();
                assert_eq!(
                    volume::be32(&observer.snapshot(1, 0), 1092),
                    volume::be32(&source, 1092) + 1
                );
                assert_eq!(read(&mut a, base), plain);
                assert_eq!(read(&mut a, old), b"old stream");
                let converted = observer.snapshot(0, 0);
                verify(converted.clone(), &plain, resource, 0);
                if journal
                    && !sensitive
                    && matches!(kind, 3 | 8 | 13 | 14)
                    && let Some(dir) = std::env::var_os("HFS_COMPRESSED_STREAM_IMAGES")
                {
                    use std::io::Write;
                    let dir = std::path::Path::new(&dir);
                    std::fs::create_dir_all(dir).unwrap();
                    for (name, bytes) in [
                        (format!("source-{kind}.img"), source.as_slice()),
                        (format!("converted-{kind}.img"), converted.as_slice()),
                        (format!("payload-{kind}.bin"), plain.as_slice()),
                    ] {
                        std::fs::OpenOptions::new()
                            .create_new(true)
                            .write(true)
                            .open(dir.join(name))
                            .unwrap()
                            .write_all(bytes)
                            .unwrap();
                    }
                }
                a.write(h, 0, b"named payload", false, false).unwrap();
                for handle in [h, old, base] {
                    a.close(handle).unwrap();
                }
                let d = a.shutdown().unwrap();
                let mut a = Adapter::from_device(d).unwrap();
                let h = a.open("\\compressed:new", all()).unwrap();
                assert_eq!(read(&mut a, h), b"named payload");
                a.close(h).unwrap();
                a.shutdown().unwrap();
                count += 1;
            }
        }
    }
    println!("compressed named-stream conversion: {count} format/volume cases");
}
#[test]
fn named_stream_conversion_and_store_publish_atomically_at_every_write_boundary() {
    let mut count = 0;
    for kind in [3, 8, 13, 14] {
        let resource = matches!(kind, 3 | 13);
        let (d, plain) = fixture_with_named(kind, true, false, resource, true);
        let source = d.into_bytes();
        let jib = volume::be32(&source, 1036) as usize * 4096;
        let journal = volume::be64(&source, jib + 36) as usize;
        for op in 0..3 {
            let perform = |a: &mut Adapter<faults::Disk>, h| match op {
                0 => a
                    .create_initialized("\\compressed:new", Kind::File, all(), None, 70019)
                    .map(|_| ()),
                1 => a.write(h, 0, b"new stream", false, false).map(|_| ()),
                2 => a.cleanup(h, true),
                _ => unreachable!(),
            };
            let run = |failure| {
                let observer = faults::Disk::new(&source);
                let mut a = Adapter::from_device(observer.clone()).unwrap();
                let h = a.open("\\compressed:prior", all()).unwrap();
                observer.arm(failure);
                let pass = perform(&mut a, h).is_ok();
                let calls = observer.0.lock().unwrap().calls;
                if !pass {
                    assert!(a.failure().is_some());
                    assert!(a.flush(None).is_err());
                    assert_eq!(observer.0.lock().unwrap().calls, calls);
                }
                (observer, calls, pass)
            };
            let (d, calls, pass) = run(None);
            assert!(pass);
            assert_eq!(
                volume::be32(&d.snapshot(0, 0), 1092),
                volume::be32(&source, 1092) + 1
            );
            verify(d.snapshot(0, 0), &plain, resource, op);
            for stop in 0..calls {
                let (d, _, pass) = run(Some(stop));
                assert!(!pass);
                for policy in 0..6 {
                    verify(d.snapshot(policy, journal), &plain, resource, op);
                    count += 1;
                }
            }
        }
    }
    println!("compressed named-stream fault snapshots: {count}");
}
#[test]
fn named_stream_conversion_refusals_preserve_source_and_leave_adapter_usable() {
    for kind in [3, 8] {
        let (d, _) = fixture_with_named(kind, true, false, kind == 3, true);
        let baseline = d.into_bytes();
        for variant in 0..3 {
            let mut source = baseline.clone();
            if variant == 1 {
                let base = volume::be32(&source, 1392) as usize * 4096;
                let len = volume::be64(&source, 1376) as usize;
                let at = base
                    + source[base..base + len]
                        .windows(4)
                        .position(|v| v == b"fpmc")
                        .unwrap();
                source[at + 4..at + 8].copy_from_slice(&999u32.to_le_bytes());
            }
            let d = faults::Disk::new(&source);
            let mut a = Adapter::from_device(d.clone()).unwrap();
            if variant == 2 {
                let h = a.open("\\compressed", all()).unwrap();
                a.set_basic_info(h, Default::default(), Some(1)).unwrap();
                a.close(h).unwrap();
                source = d.snapshot(0, 0);
            }
            d.arm(None);
            let reserve = if variant == 0 {
                a.volume_info().unwrap().free_bytes
            } else {
                4096
            };
            assert!(
                a.create_initialized("\\compressed:new", Kind::File, all(), None, reserve)
                    .is_err()
            );
            assert!(a.failure().is_none());
            assert_eq!(d.0.lock().unwrap().calls, 0);
            assert_eq!(d.snapshot(1, 0), source);
            let h = a.open("\\ordinary", all()).unwrap();
            a.write(h, 0, b"still usable", false, false).unwrap();
            a.close(h).unwrap();
            a.shutdown().unwrap();
        }
    }
}
