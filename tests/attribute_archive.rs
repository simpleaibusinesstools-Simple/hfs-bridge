use fstool::{
    block::MemoryBackend,
    fs::Filesystem,
    fs::hfs_plus::{FormatOpts, HfsPlus},
};
use hfs_bridge::{
    attribute_archive as wire,
    windows::{Access, Adapter, Handle, Kind, OpenRequest, Status},
};
use sha2::{Digest, Sha256};
#[path = "support/fault_disk.rs"]
#[allow(dead_code)]
mod faults;
fn all() -> OpenRequest {
    OpenRequest {
        access: Access::ALL,
        ..Default::default()
    }
}
fn fixture(journaled: bool) -> MemoryBackend {
    let mut disk = MemoryBackend::new(32 * 1024 * 1024);
    let mut fs = HfsPlus::format(
        &mut disk,
        &FormatOpts {
            journaled,
            ..Default::default()
        },
    )
    .unwrap();
    fs.create_file(&mut disk, "/file", &mut &b"data"[..], 4, 0o640, 501, 20, 0)
        .unwrap();
    fs.create_dir(&mut disk, "/folder", 0o750, 501, 20, 0)
        .unwrap();
    fs.flush(&mut disk).unwrap();
    disk
}
fn read(adapter: &mut Adapter<MemoryBackend>, handle: Handle) -> Vec<u8> {
    let mut bytes = vec![0; adapter.file_info(handle).unwrap().size as usize];
    let mut position = 0;
    while position < bytes.len() {
        let count = adapter
            .read(handle, position as u64, &mut bytes[position..])
            .unwrap();
        assert_ne!(count, 0);
        position += count;
    }
    bytes
}
fn store(adapter: &mut Adapter<MemoryBackend>, path: &str, values: &[(String, Vec<u8>)]) -> Handle {
    let handle = adapter.create(path, Kind::File, all()).unwrap();
    let bytes = wire::encode(values).unwrap();
    adapter.set_size(handle, bytes.len() as u64).unwrap();
    // Deliberately reverse chunks; no attribute publication before every byte arrives.
    let chunks = bytes.chunks(4093).enumerate().collect::<Vec<_>>();
    for (i, chunk) in chunks.into_iter().rev() {
        adapter
            .write(handle, (i * 4093) as u64, chunk, false, false)
            .unwrap();
    }
    adapter.flush(Some(handle)).unwrap();
    handle
}
#[test]
fn metadata_archive_preserves_large_exact_values_files_directories_and_reopen() {
    let values = vec![
        ("Case".into(), vec![0; 70019]),
        ("case".into(), vec![255]),
        ("\u{1f30a}".into(), vec![]),
    ];
    let expected = wire::decode(&wire::encode(&values).unwrap()).unwrap();
    let projected = expected
        .iter()
        .map(|(name, value)| (name.clone(), (value.len() > 12288).then(|| value.clone())))
        .collect::<Vec<_>>();
    for journaled in [false, true] {
        let mut a = Adapter::from_device(fixture(journaled)).unwrap();
        for path in [r"\file", r"\folder"] {
            let stream = store(&mut a, &format!("{path}:HFSB_Attributes"), &values);
            assert_eq!(wire::decode(&read(&mut a, stream)).unwrap(), expected);
            a.close(stream).unwrap();
            let base = a.open(path, all()).unwrap();
            assert!(
                a.streams(base)
                    .unwrap()
                    .iter()
                    .any(|(name, _)| *name == wire::STREAM)
            );
            a.close(base).unwrap();
        }
        let mut a = Adapter::from_device(a.shutdown().unwrap()).unwrap();
        for path in [r"\file:HFSB_Attributes:$DATA", r"\folder:hfsb_attributes"] {
            let stream = a.open(path, all()).unwrap();
            let snapshot = wire::decode_snapshot(&read(&mut a, stream)).unwrap();
            assert!(snapshot.projected);
            assert_eq!(snapshot.records, projected);
            a.close(stream).unwrap();
        }
        let file = a.open(r"\file", all()).unwrap();
        assert_eq!(read(&mut a, file), b"data");
        a.close(file).unwrap();
        a.shutdown().unwrap();
    }
}
#[test]
fn archive_replacement_removes_only_ordinary_attributes_and_keeps_finder_and_data() {
    let mut a = Adapter::from_device(fixture(true)).unwrap();
    let base = a.open(r"\file", all()).unwrap();
    let finder = fstool::fs::hfs_plus::attributes::public_finder_info(&[7; 32]).to_vec();
    let packet = hfs_bridge::ea::encode(
        &hfs_bridge::ea::records(&[("com.apple.FinderInfo".into(), finder.clone())]).unwrap(),
    )
    .unwrap();
    a.set_extended_attributes(base, &packet).unwrap();
    let stream = store(
        &mut a,
        r"\file:HFSB_Attributes",
        &[("old".into(), vec![2; 20019])],
    );
    assert_eq!(
        a.set_extended_attributes(base, &packet).unwrap_err().status,
        Status::SharingViolation
    );
    let bytes = wire::encode(&[("new".into(), vec![9; 17019])]).unwrap();
    a.overwrite(stream, 0x80, true, 0).unwrap();
    for (i, chunk) in bytes.chunks(3333).enumerate() {
        a.write(stream, (i * 3333) as u64, chunk, false, false)
            .unwrap();
    }
    a.close(stream).unwrap();
    let records = a.extended_attributes(base).unwrap();
    let changes = hfs_bridge::ea::changes(&hfs_bridge::ea::encode(&records).unwrap(), &[]).unwrap();
    assert!(
        changes
            .iter()
            .any(|c| c.name == "new" && c.value == Some(vec![9; 17019]))
    );
    assert!(
        changes
            .iter()
            .any(|c| c.name == "com.apple.FinderInfo"
                && c.value.as_deref() == Some(finder.as_slice()))
    );
    assert!(!changes.iter().any(|c| c.name == "old"));
    assert_eq!(read(&mut a, base), b"data");
    a.close(base).unwrap();
    a.shutdown().unwrap();
}
#[test]
fn incomplete_or_corrupt_archive_cannot_flush_or_change_existing_attributes() {
    let original = vec![("original".into(), b"unchanged".to_vec())];
    let mut a = Adapter::from_device(fixture(true)).unwrap();
    let stream = store(&mut a, r"\file:HFSB_Attributes", &original);
    let bytes = wire::encode(&[("replacement".into(), vec![7; 20019])]).unwrap();
    a.overwrite(stream, 0, true, 0).unwrap();
    a.write(stream, 0, &bytes[..23], false, false).unwrap();
    assert_eq!(
        a.flush(Some(stream)).unwrap_err().status,
        Status::InvalidParameter
    );
    let base = a.open(r"\file", all()).unwrap();
    let names = a.extended_attributes(base).unwrap();
    assert_eq!(names.len(), 1);
    let changes = hfs_bridge::ea::changes(&hfs_bridge::ea::encode(&names).unwrap(), &[]).unwrap();
    assert_eq!(changes[0].name, "original");
    a.close(base).unwrap();
    a.overwrite(stream, 0, true, 0).unwrap();
    let mut corrupt = bytes.clone();
    *corrupt.last_mut().unwrap() ^= 1;
    assert!(a.write(stream, 0, &corrupt, false, false).is_err());
    assert!(a.flush(Some(stream)).is_err());
    a.overwrite(stream, 0, true, 0).unwrap();
    a.write(stream, 0, &bytes, false, false).unwrap();
    a.close(stream).unwrap();
    let mut a = Adapter::from_device(a.shutdown().unwrap()).unwrap();
    let stream = a.open(r"\file:HFSB_Attributes", all()).unwrap();
    assert_eq!(
        wire::decode_snapshot(&read(&mut a, stream))
            .unwrap()
            .records,
        vec![("replacement".into(), Some(vec![7; 20019]))]
    );
    a.close(stream).unwrap();
    a.shutdown().unwrap();
}
#[test]
fn archive_unlink_keeps_old_handles_and_recreation_separate() {
    let mut a = Adapter::from_device(fixture(true)).unwrap();
    let old = vec![("old".into(), vec![1; 20019])];
    let stream = store(&mut a, r"\file:HFSB_Attributes", &old);
    let reader = a.open(r"\file:HFSB_Attributes", all()).unwrap();
    a.cleanup(stream, true).unwrap();
    assert_eq!(read(&mut a, reader), wire::encode(&old).unwrap());
    assert_eq!(
        a.write(reader, 0, b"x", false, false).unwrap_err().status,
        Status::DeletePending
    );
    assert!(a.open(r"\file:HFSB_Attributes", all()).is_err());
    let new = vec![("new".into(), vec![9; 20019])];
    let fresh = store(&mut a, r"\file:HFSB_Attributes", &new);
    a.close(fresh).unwrap();
    assert_eq!(read(&mut a, reader), wire::encode(&old).unwrap());
    a.cleanup(reader, true).unwrap();
    a.close(reader).unwrap();
    a.close(stream).unwrap();
    let reader = a.open(r"\file:HFSB_Attributes", all()).unwrap();
    assert_eq!(
        wire::decode_snapshot(&read(&mut a, reader))
            .unwrap()
            .records,
        new.into_iter()
            .map(|(name, value)| (name, Some(value)))
            .collect::<Vec<_>>()
    );
    a.close(reader).unwrap();
    a.shutdown().unwrap();
}
#[test]
fn archive_access_limits_and_incomplete_final_close_are_visible() {
    let mut a = Adapter::from_device(fixture(true)).unwrap();
    let mut denied = all();
    denied.access = Access::READ;
    let readonly = a
        .create(r"\file:HFSB_Attributes", Kind::File, denied)
        .unwrap();
    assert_eq!(
        a.write(readonly, 0, b"x", false, false).unwrap_err().status,
        Status::AccessDenied
    );
    a.cleanup(readonly, true).unwrap_err();
    // An authorized delete discards this uncommitted empty creation.
    let mut delete_request = all();
    delete_request.access.write = false;
    let deletion = a.open(r"\file:HFSB_Attributes", delete_request).unwrap();
    a.cleanup(deletion, true).unwrap();
    a.close(deletion).unwrap();
    a.close(readonly).unwrap();
    let stream = a
        .create(r"\file:HFSB_Attributes", Kind::File, all())
        .unwrap();
    assert!(a.set_size(stream, wire::MAX_BYTES as u64 + 1).is_err());
    assert!(a.write(stream, u64::MAX, &[1], false, false).is_err());
    a.write(stream, 0, b"incomplete", false, false).unwrap();
    assert!(a.close(stream).is_err());
    assert!(a.failure().is_some());
    assert!(a.shutdown().is_err());
}

fn projected_client(mut records: Vec<(String, Option<Vec<u8>>)>) -> Vec<u8> {
    records.sort_by_key(|(name, _)| name.encode_utf16().collect::<Vec<_>>());
    let mut bytes = b"HFSBXA1\0".to_vec();
    bytes.extend_from_slice(&(records.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&1u32.to_le_bytes());
    bytes.extend_from_slice(&0u64.to_le_bytes());
    for (name, value) in records {
        let name = name.encode_utf16().collect::<Vec<_>>();
        bytes.extend_from_slice(&(name.len() as u16).to_le_bytes());
        bytes.extend_from_slice(&u16::from(value.is_none()).to_le_bytes());
        let value = value.unwrap_or_default();
        bytes.extend_from_slice(&(value.len() as u32).to_le_bytes());
        bytes.extend(name.into_iter().flat_map(u16::to_le_bytes));
        bytes.extend(value);
    }
    let size = bytes.len() + 32;
    bytes[16..24].copy_from_slice(&(size as u64).to_le_bytes());
    bytes.extend_from_slice(&Sha256::digest(&bytes));
    bytes
}
#[test]
fn projected_copy_uses_supplied_eas_including_edits_additions_and_deletions() {
    let mut a = Adapter::from_device(fixture(true)).unwrap();
    let old = store(
        &mut a,
        r"\file:HFSB_Attributes",
        &[
            ("old".into(), vec![5]),
            ("deleted".into(), vec![6]),
            ("before-large".into(), vec![31; 18019]),
        ],
    );
    a.close(old).unwrap();
    let base = a.open(r"\file", all()).unwrap();
    let supplied = vec![
        hfs_bridge::ea::Change {
            name: "Case".into(),
            value: Some(vec![10, 11]),
        },
        hfs_bridge::ea::Change {
            name: "case".into(),
            value: Some(vec![]),
        },
        hfs_bridge::ea::Change {
            name: "added".into(),
            value: Some(vec![8]),
        },
    ];
    a.overwrite_with_ea(base, 0x80, true, 0, &supplied).unwrap();
    a.write(base, 0, b"data", false, false).unwrap();
    let stream = a.open(r"\file:HFSB_Attributes", all()).unwrap();
    a.overwrite(stream, 0x80, true, 0).unwrap();
    let bytes = projected_client(vec![
        ("Case".into(), None),
        ("case".into(), None),
        ("deleted".into(), None),
        ("large".into(), Some(vec![17; 30019])),
    ]);
    a.write(stream, 0, &bytes, false, false).unwrap();
    a.close(stream).unwrap();
    a.close(base).unwrap();
    let mut disk = a.shutdown().unwrap();
    let fs = HfsPlus::open(&mut disk).unwrap();
    let cnid = hfs_bridge::volume::be32(&fs.catalog_record("/file").unwrap(), 8);
    assert_eq!(
        fs.attribute_names(&mut disk, cnid).unwrap(),
        [
            "Case",
            "added",
            "case",
            "large",
            hfs_bridge::timestamps::TIMES_ATTRIBUTE
        ]
    );
    for (name, value) in [
        ("Case", vec![10, 11]),
        ("case", vec![]),
        ("added", vec![8]),
        ("large", vec![17; 30019]),
    ] {
        assert_eq!(
            fs.inline_attribute(&mut disk, cnid, name).unwrap(),
            Some(value)
        );
    }
}

#[test]
fn archive_publication_failures_are_sticky_and_recover_as_complete_old_or_new_maps() {
    let old = vec![("old".into(), vec![3; 20019])];
    let new = vec![("new".into(), vec![17; 30019])];
    let mut initial = Adapter::from_device(fixture(true)).unwrap();
    let stream = store(&mut initial, r"\file:HFSB_Attributes", &old);
    initial.close(stream).unwrap();
    let baseline = initial.shutdown().unwrap().into_bytes();
    let jib = hfs_bridge::volume::be32(&baseline, 1036) as usize * 4096;
    let journal = hfs_bridge::volume::be64(&baseline, jib + 36) as usize;
    let frame = wire::encode(&new).unwrap();
    let mut count = 0;
    for delete in [false, true] {
        let prepare = |disk: faults::Disk| {
            let mut a = Adapter::from_device(disk).unwrap();
            let stream = a.open(r"\file:HFSB_Attributes", all()).unwrap();
            if !delete {
                a.overwrite(stream, 0x80, true, 0).unwrap();
                a.write(stream, 0, &frame[..frame.len() - 1], false, false)
                    .unwrap();
            }
            (a, stream)
        };
        let disk = faults::Disk::new(&baseline);
        let observer = disk.clone();
        let (mut a, stream) = prepare(disk);
        observer.arm(None);
        if delete {
            a.cleanup(stream, true).unwrap();
        } else {
            a.write(
                stream,
                (frame.len() - 1) as u64,
                &frame[frame.len() - 1..],
                false,
                false,
            )
            .unwrap();
        }
        let calls = observer.0.lock().unwrap().calls;
        assert!(calls > 10);
        drop(a);
        for stop in 0..calls {
            let disk = faults::Disk::new(&baseline);
            let observer = disk.clone();
            let (mut a, stream) = prepare(disk);
            observer.arm(Some(stop));
            let failed = if delete {
                a.cleanup(stream, true).is_err()
            } else {
                a.write(
                    stream,
                    (frame.len() - 1) as u64,
                    &frame[frame.len() - 1..],
                    false,
                    false,
                )
                .is_err()
            };
            assert!(failed);
            assert!(a.failure().is_some());
            let calls = observer.0.lock().unwrap().calls;
            assert!(a.flush(Some(stream)).is_err());
            assert!(a.close(stream).is_err());
            assert_eq!(observer.0.lock().unwrap().calls, calls);
            for policy in 0..6 {
                let snapshot = observer.snapshot(policy, journal);
                let mut recovered = MemoryBackend::from_bytes(snapshot);
                // Test-only replay; production still refuses dirty journals before writes.
                let mut fs = HfsPlus::open(&mut recovered).unwrap();
                let body = fs.catalog_record("/file").unwrap();
                let cnid = hfs_bridge::volume::be32(&body, 8);
                let names = fs.attribute_names(&mut recovered, cnid).unwrap();
                let mut actual = Vec::new();
                for name in names {
                    let value = fs
                        .inline_attribute(&mut recovered, cnid, &name)
                        .unwrap()
                        .unwrap();
                    if name == hfs_bridge::timestamps::TIMES_ATTRIBUTE {
                        assert!(hfs_bridge::timestamps::PrecisionRecord::decode(&value).is_some());
                        continue;
                    }
                    actual.push((name, value));
                }
                let marker = fs
                    .fixed_inline_attribute(
                        &mut recovered,
                        2,
                        hfs_bridge::timestamps::GENERATION_ATTRIBUTE,
                        80,
                    )
                    .unwrap()
                    .unwrap();
                let generation = hfs_bridge::timestamps::Generation::decode(&marker).unwrap();
                assert!(generation.matches(hfs_bridge::timestamps::VolumeState {
                    id: recovered.as_slice()[1128..1136].try_into().unwrap(),
                    created: hfs_bridge::volume::be32(recovered.as_slice(), 1040),
                    write_count: hfs_bridge::volume::be32(recovered.as_slice(), 1092),
                }));
                assert!(actual == old || actual == if delete { vec![] } else { new.clone() });
                let mut data = Vec::new();
                use std::io::Read;
                fs.open_file_ro(&mut recovered, std::path::Path::new("/file"))
                    .unwrap()
                    .read_to_end(&mut data)
                    .unwrap();
                assert_eq!(data, b"data");
                count += 1;
            }
        }
    }
    println!(
        "ARCHIVE_ADAPTER_FAULTS: {count} selected persistence checks; no failed publication or retry acknowledged"
    );
}
