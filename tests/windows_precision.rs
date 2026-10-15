use fstool::{
    block::MemoryBackend,
    fs::hfs_plus::{FormatOpts, HfsPlus},
};
use hfs_bridge::{
    timestamps::{GENERATION_ATTRIBUTE, Generation, VolumeState},
    volume,
    windows::{Access, Adapter, BasicTimes, FileInfo, Kind, OpenRequest, hfs_to_filetime},
};
use std::{
    io::Write,
    time::{SystemTime, UNIX_EPOCH},
};
#[allow(dead_code)]
#[path = "support/attribute_wire.rs"]
mod attribute_wire;
#[allow(dead_code)]
#[path = "support/catalog_wire.rs"]
mod catalog_wire;
#[path = "support/fault_disk.rs"]
mod fault;

fn all() -> OpenRequest {
    OpenRequest {
        access: Access::ALL,
        ..Default::default()
    }
}
fn fixture(journaled: bool, sensitive: bool) -> MemoryBackend {
    let mut disk = MemoryBackend::new(8 * 1024 * 1024);
    HfsPlus::format(
        &mut disk,
        &FormatOpts {
            journaled,
            ..Default::default()
        },
    )
    .unwrap();
    let mut bytes = disk.into_bytes();
    if sensitive {
        bytes[1024..1026].copy_from_slice(b"HX");
        bytes[1026..1028].copy_from_slice(&5u16.to_be_bytes());
        let catalog = volume::be32(&bytes, 1312) as usize * 4096;
        bytes[catalog + 51] = 0xbc;
        // The formatter's empty root needs the HFSX folder-count flag.
        let node = catalog + 4096;
        let count = volume::be16(&bytes, node + 10) as usize;
        for record in 0..count {
            let start = volume::be16(&bytes, node + 4096 - 2 * (record + 1)) as usize;
            let body = node + start + 2 + volume::be16(&bytes, node + start) as usize;
            if volume::be16(&bytes, body) == 1 {
                bytes[body + 3] |= 0x10;
            }
        }
        let header = bytes[1024..1536].to_vec();
        let alternate = bytes.len() - 1024;
        bytes[alternate..alternate + 512].copy_from_slice(&header);
    }
    MemoryBackend::from_bytes(bytes)
}
fn dates(info: FileInfo) -> [u64; 4] {
    [
        info.creation_time,
        info.access_time,
        info.write_time,
        info.change_time,
    ]
}
fn basic(d: [u64; 4]) -> BasicTimes {
    BasicTimes {
        creation: Some(d[0]),
        access: Some(d[1]),
        write: Some(d[2]),
        change: Some(d[3]),
    }
}
fn now() -> u64 {
    let t = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    (t.as_secs() + 11_644_473_600) * 10_000_000 + u64::from(t.subsec_nanos() / 100)
}
fn exact() -> [u64; 4] {
    std::array::from_fn(|i| {
        hfs_to_filetime(3_800_000_000 + i as u32) + [1, 9999999, 66, 1234567][i]
    })
}
fn retain(disk: &MemoryBackend, name: &str) {
    if let Some(dir) = std::env::var_os("HFS_PRECISION_IMAGES") {
        let path = std::path::PathBuf::from(dir).join(name);
        let mut file = hfs_bridge::image::create_output(&path).unwrap();
        file.write_all(disk.as_slice()).unwrap();
        file.sync_all().unwrap();
    }
}
fn marker(disk: &mut MemoryBackend) -> Generation {
    let state = VolumeState {
        id: disk.as_slice()[1128..1136].try_into().unwrap(),
        created: volume::be32(disk.as_slice(), 1040),
        write_count: volume::be32(disk.as_slice(), 1092),
    };
    let fs = HfsPlus::open(disk).unwrap();
    let record = Generation::decode(
        &fs.fixed_inline_attribute(disk, 2, GENERATION_ATTRIBUTE, 80)
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    assert!(record.matches(state));
    record
}

#[test]
fn precise_creation_explicit_fields_payload_namespace_and_remount() {
    for journal in [false, true] {
        for sensitive in [false, true] {
            let mut adapter = Adapter::from_device(fixture(journal, sensitive)).unwrap();
            let lower = now();
            let file = adapter.create(r"\precise", Kind::File, all()).unwrap();
            let upper = now();
            assert!(
                dates(adapter.file_info(file).unwrap())
                    .iter()
                    .all(|&date| date >= lower && date <= upper)
            );
            let mut expected = exact();
            adapter.set_basic_times(file, basic(expected)).unwrap();
            assert_eq!(dates(adapter.file_info(file).unwrap()), expected);
            let official = 116_444_736_000_000_000 + 0x4200000042;
            adapter
                .set_basic_times(
                    file,
                    BasicTimes {
                        access: Some(official),
                        ..Default::default()
                    },
                )
                .unwrap();
            expected[1] = official;
            assert_eq!(dates(adapter.file_info(file).unwrap()), expected);
            adapter
                .write(file, 0, b"precise payload", false, false)
                .unwrap();
            let after_write = dates(adapter.file_info(file).unwrap());
            assert_eq!(&after_write[..2], &expected[..2]);
            assert_ne!(after_write[2] % 10_000_000, 0);
            adapter.rename(file, r"\renamed").unwrap();
            let after_rename = dates(adapter.file_info(file).unwrap());
            assert_eq!(&after_rename[..3], &after_write[..3]);
            adapter.set_allocation_size(file, 65536).unwrap();
            assert_eq!(dates(adapter.file_info(file).unwrap()), after_rename);
            adapter.set_volume_label("Precise volume").unwrap();
            assert_eq!(dates(adapter.file_info(file).unwrap()), after_rename);
            let untouched = adapter.create(r"\untouched", Kind::File, all()).unwrap();
            adapter
                .write(untouched, 0, b"untouched", false, false)
                .unwrap();
            adapter.set_basic_times(untouched, basic(exact())).unwrap();
            adapter.close(untouched).unwrap();
            adapter.set_basic_times(file, basic(expected)).unwrap();
            adapter.close(file).unwrap();
            let mut disk = adapter.shutdown().unwrap();
            marker(&mut disk);
            retain(&disk, &format!("precision-{journal}-{sensitive}.img"));
            let before = disk.as_slice().to_vec();
            let mut adapter = Adapter::from_device(disk).unwrap();
            let file = adapter.open(r"\renamed", all()).unwrap();
            assert_eq!(dates(adapter.file_info(file).unwrap()), expected);
            adapter.set_size(file, 15).unwrap(); // Payload is already exactly fifteen bytes.
            adapter
                .set_basic_times(file, BasicTimes::default())
                .unwrap();
            adapter.rename(file, r"\renamed").unwrap();
            adapter.set_allocation_size(file, 65536).unwrap();
            adapter.set_volume_label("Precise volume").unwrap();
            adapter.flush(Some(file)).unwrap();
            adapter.close(file).unwrap();
            let disk = adapter.shutdown().unwrap();
            assert_eq!(disk.as_slice(), before);
        }
    }
}

#[test]
fn foreign_same_second_publication_invalidates_old_fractions_without_reviving_others() {
    for journal in [false, true] {
        let mut adapter = Adapter::from_device(fixture(journal, false)).unwrap();
        for name in [r"\first", r"\second"] {
            let h = adapter.create(name, Kind::File, all()).unwrap();
            adapter.set_basic_times(h, basic(exact())).unwrap();
            adapter.close(h).unwrap();
        }
        let mut disk = adapter.shutdown().unwrap();
        let original = marker(&mut disk);
        let mut fs = HfsPlus::open(&mut disk).unwrap();
        let id = volume::be32(&fs.catalog_record("/first").unwrap(), 8);
        fs.set_catalog_times(id, [None, None, Some(3_800_000_002), None])
            .unwrap();
        fs.flush(&mut disk).unwrap();
        let rounded = exact().map(|v| v / 10_000_000 * 10_000_000);
        let mut adapter = Adapter::from_device(disk).unwrap();
        assert_eq!(dates(adapter.path_info(r"\first").unwrap()), rounded);
        assert_eq!(dates(adapter.path_info(r"\second").unwrap()), rounded);
        let first = adapter.open(r"\first", all()).unwrap();
        adapter
            .set_basic_times(
                first,
                BasicTimes {
                    write: Some(exact()[2]),
                    ..Default::default()
                },
            )
            .unwrap();
        let mut updated = rounded;
        updated[2] = exact()[2];
        assert_eq!(dates(adapter.file_info(first).unwrap()), updated);
        assert_eq!(dates(adapter.path_info(r"\second").unwrap()), rounded);
        adapter.close(first).unwrap();
        let mut disk = adapter.shutdown().unwrap();
        assert_ne!(
            &marker(&mut disk).encode()[24..40],
            &original.encode()[24..40]
        );
        let mut adapter = Adapter::from_device(disk).unwrap();
        assert_eq!(dates(adapter.path_info(r"\first").unwrap()), updated);
        assert_eq!(dates(adapter.path_info(r"\second").unwrap()), rounded);
        adapter.shutdown().unwrap();
    }
}

#[test]
fn interrupted_adapter_dates_payload_and_namespace_recover_with_matching_generation() {
    let mut adapter = Adapter::from_device(fixture(true, false)).unwrap();
    let handle = adapter.create(r"\file", Kind::File, all()).unwrap();
    adapter.write(handle, 0, b"before", false, false).unwrap();
    adapter.set_basic_times(handle, basic(exact())).unwrap();
    adapter.close(handle).unwrap();
    let bytes = adapter.shutdown().unwrap().into_bytes();
    let old_count = volume::be32(&bytes, 1092);
    let jib = volume::be32(&bytes, 1036) as usize * 4096;
    let journal = volume::be64(&bytes, jib + 36) as usize;
    let changed = exact().map(|date| date + 100_000_009);
    let mut failures = 0;
    let mut snapshots = 0;
    for operation in 0..3 {
        let mutate = |a: &mut Adapter<fault::Disk>, h| match operation {
            0 => a.set_basic_times(h, basic(changed)),
            1 => a.write(h, 0, b"after!", false, false).map(|_| ()),
            _ => a.rename(h, r"\moved"),
        };
        let disk = fault::Disk::new(&bytes);
        let mut a = Adapter::from_device(disk.clone()).unwrap();
        let h = a.open(r"\file", all()).unwrap();
        disk.arm(None);
        mutate(&mut a, h).unwrap();
        let count = disk.0.lock().unwrap().calls;
        assert!(count > 10);
        drop(a);
        for fail in 0..count {
            let disk = fault::Disk::new(&bytes);
            let mut a = Adapter::from_device(disk.clone()).unwrap();
            let h = a.open(r"\file", all()).unwrap();
            disk.arm(Some(fail));
            let lower = now();
            assert!(mutate(&mut a, h).is_err());
            let upper = now();
            assert!(a.failure().is_some());
            let calls = disk.0.lock().unwrap().calls;
            assert!(a.flush(None).is_err());
            assert_eq!(disk.0.lock().unwrap().calls, calls);
            drop(a);
            failures += 1;
            for policy in 0..6 {
                let mut recovered = MemoryBackend::from_bytes(disk.snapshot(policy, journal));
                // Test-only native journal replay, before the production adapter.
                HfsPlus::open(&mut recovered).unwrap();
                marker(&mut recovered);
                let new = volume::be32(recovered.as_slice(), 1092) != old_count;
                assert_eq!(
                    volume::be32(recovered.as_slice(), 1092),
                    old_count + u32::from(new)
                );
                let mut check = Adapter::from_device(recovered).unwrap();
                let path = if operation == 2 && new {
                    r"\moved"
                } else {
                    r"\file"
                };
                let h = check.open(path, all()).unwrap();
                let actual = dates(check.file_info(h).unwrap());
                let mut data = [0; 6];
                assert_eq!(check.read(h, 0, &mut data).unwrap(), 6);
                if !new {
                    assert_eq!(actual, exact());
                    assert_eq!(&data, b"before");
                } else if operation == 0 {
                    assert_eq!(actual, changed);
                    assert_eq!(&data, b"before");
                } else {
                    assert_eq!(&actual[..2], &exact()[..2]);
                    assert!(actual[3] >= lower && actual[3] <= upper);
                    if operation == 1 {
                        assert_eq!(actual[2], actual[3]);
                        assert_eq!(&data, b"after!");
                    } else {
                        assert_eq!(actual[2], exact()[2]);
                        assert_eq!(&data, b"before");
                        assert!(check.path_info(r"\file").is_err());
                    }
                }
                check.close(h).unwrap();
                check.shutdown().unwrap();
                snapshots += 1;
            }
        }
    }
    println!(
        "PRECISE_ADAPTER_RECOVERY: {failures} failed boundaries; {snapshots} persistence snapshots"
    );
}

#[test]
fn growing_timestamp_tree_keeps_records_and_survives_interrupted_relocation() {
    let mut recovery_base = None;
    for journaled in [false, true] {
        for sensitive in [false, true] {
            let disk = fault::Disk::new(fixture(journaled, sensitive).as_slice());
            let mut adapter = Adapter::from_device(disk.clone()).unwrap();
            let mut expected = Vec::new();
            let mut growths = 0;
            for index in 0..320 {
                let path = format!(r"\file-{index:04}");
                let before = disk.snapshot(0, 0);
                let old_size = volume::be64(&before, 1376);
                let handle = adapter.create(&path, Kind::File, all()).unwrap();
                expected.push((path.clone(), dates(adapter.file_info(handle).unwrap())));
                adapter.close(handle).unwrap();
                let after = disk.snapshot(0, 0);
                let new_size = volume::be64(&after, 1376);
                if old_size != 0 && old_size < new_size {
                    growths += 1;
                    assert_eq!(new_size, old_size * 2);
                    let start = volume::be32(&after, 1392);
                    let old_start = volume::be32(&before, 1392);
                    let block_size = volume::be32(&after, 1064) as usize;
                    let bitmap = volume::be32(&after, 1152) as usize * block_size;
                    assert_ne!(old_start, start);
                    for old in old_start..old_start + volume::be32(&before, 1388) {
                        assert_eq!(after[bitmap + old as usize / 8] & (0x80 >> (old & 7)), 0);
                    }
                    attribute_wire::audit_initialized(&after);
                    catalog_wire::audit(&after);
                    if journaled && !sensitive && recovery_base.is_none() {
                        recovery_base = Some((before, path, expected[..index].to_vec()));
                    }
                }
            }
            assert!(growths >= 2);
            adapter.shutdown().unwrap();
            let mut saved = MemoryBackend::from_bytes(disk.snapshot(0, 0));
            marker(&mut saved);
            assert_eq!(
                attribute_wire::audit_initialized(saved.as_slice()).len(),
                322
            );
            catalog_wire::audit(saved.as_slice());
            retain(&saved, &format!("growth-{journaled}-{sensitive}.img"));
            let mut reopened = Adapter::from_device(saved).unwrap();
            for (path, dates_before) in expected {
                assert_eq!(dates(reopened.path_info(&path).unwrap()), dates_before);
            }
            reopened.shutdown().unwrap();
        }
    }
    let (base, next, expected) = recovery_base.unwrap();
    let old_size = volume::be64(&base, 1376);
    let old_free = volume::be32(&base, 1072);
    let old_count = volume::be32(&base, 1092);
    let journal = volume::be64(&base, volume::be32(&base, 1036) as usize * 4096 + 36) as usize;
    let disk = fault::Disk::new(&base);
    let mut adapter = Adapter::from_device(disk.clone()).unwrap();
    disk.arm(None);
    adapter.create(&next, Kind::File, all()).unwrap();
    let boundaries = disk.0.lock().unwrap().calls;
    let completed = disk.snapshot(0, 0);
    let new_free = volume::be32(&completed, 1072);
    assert_eq!(volume::be64(&completed, 1376), old_size * 2);
    drop(adapter);
    let mut snapshots = 0;
    for failure in 0..boundaries {
        let disk = fault::Disk::new(&base);
        let mut adapter = Adapter::from_device(disk.clone()).unwrap();
        disk.arm(Some(failure));
        assert!(adapter.create(&next, Kind::File, all()).is_err());
        assert!(adapter.failure().is_some());
        let calls = disk.0.lock().unwrap().calls;
        assert!(adapter.flush(None).is_err());
        drop(adapter);
        assert_eq!(disk.0.lock().unwrap().calls, calls);
        for policy in 0..6 {
            let mut recovered = MemoryBackend::from_bytes(disk.snapshot(policy, journal));
            HfsPlus::open(&mut recovered).unwrap(); // Explicit test-only journal replay.
            marker(&mut recovered);
            let committed = volume::be64(recovered.as_slice(), 1376) != old_size;
            assert_eq!(
                volume::be64(recovered.as_slice(), 1376),
                old_size * if committed { 2 } else { 1 }
            );
            assert_eq!(
                volume::be32(recovered.as_slice(), 1072),
                if committed { new_free } else { old_free }
            );
            assert_eq!(
                volume::be32(recovered.as_slice(), 1092),
                old_count + u32::from(committed)
            );
            attribute_wire::audit_initialized(recovered.as_slice());
            catalog_wire::audit(recovered.as_slice());
            let mut check = Adapter::from_device(recovered).unwrap();
            assert_eq!(check.path_info(&next).is_ok(), committed);
            for (path, dates_before) in &expected {
                assert_eq!(dates(check.path_info(path).unwrap()), *dates_before);
            }
            check.shutdown().unwrap();
            snapshots += 1;
        }
    }
    println!(
        "ATTRIBUTE_GROWTH: four 320-file volumes; {boundaries} failed relocation boundaries; {snapshots} sector-persistence snapshots"
    );
}
