use fstool::{
    block::MemoryBackend,
    fs::hfs_plus::{FormatOpts, HfsPlus},
};
use hfs_bridge::{
    timestamps::*,
    volume,
    windows::{Access, Adapter, BasicTimes, Kind, OpenRequest, Status, hfs_to_filetime},
};
use sha2::{Digest, Sha256};
#[path = "support/fault_disk.rs"]
mod fault;
fn all() -> OpenRequest {
    OpenRequest {
        access: Access::ALL,
        ..Default::default()
    }
}
fn state(count: u32) -> VolumeState {
    VolumeState {
        id: *b"EXTtime!",
        created: 3782844799,
        write_count: count,
    }
}
fn generation() -> Generation {
    Generation::next(state(1), None, Epoch::new([3; 16]).unwrap()).unwrap()
}
fn dates() -> [u64; 4] {
    [
        0x4100000041,
        1,
        hfs_to_filetime(u32::MAX) + 123456789,
        i64::MAX as u64,
    ]
}
fn times(d: [u64; 4]) -> BasicTimes {
    BasicTimes {
        creation: Some(d[0]),
        access: Some(d[1]),
        write: Some(d[2]),
        change: Some(d[3]),
    }
}
fn fixture() -> Vec<u8> {
    let mut disk = MemoryBackend::new(8 * 1024 * 1024);
    HfsPlus::format(
        &mut disk,
        &FormatOpts {
            journaled: true,
            ..Default::default()
        },
    )
    .unwrap();
    let mut a = Adapter::from_device(disk).unwrap();
    let h = a.create("\\dates", Kind::File, all()).unwrap();
    a.write(h, 0, b"unchanged date payload", false, false)
        .unwrap();
    a.close(h).unwrap();
    a.shutdown().unwrap().into_bytes()
}
fn export(name: &str, bytes: &[u8]) {
    if let Some(dir) = std::env::var_os("HFS_EXTENDED_IMAGES") {
        std::fs::create_dir_all(&dir).unwrap();
        let path = std::path::Path::new(&dir).join(name);
        use std::io::Write;
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .unwrap()
            .write_all(bytes)
            .unwrap();
    }
}
#[test]
fn extended_wire_roundtrip_projection_and_foreign_generation_invalidation() {
    let g = generation();
    let d = dates();
    let seconds = d.map(|d| catalog_seconds(d).unwrap());
    assert_eq!(seconds, [0, 0, u32::MAX, u32::MAX]);
    let r = ExtendedRecord::new(g, 20, EntryKind::File, seconds, d.map(Some)).unwrap();
    assert_eq!(r.encode().len(), 128);
    assert!(PrecisionRecord::decode(&r.encode()).is_none());
    let decoded = ExtendedRecord::decode(&r.encode()).unwrap();
    assert_eq!(
        decoded.resolve(Some(g), state(2), 20, EntryKind::File, seconds),
        d
    );
    for (g, current, id, kind) in [
        (None, state(2), 20, EntryKind::File),
        (Some(g), state(3), 20, EntryKind::File),
        (Some(g), state(2), 21, EntryKind::File),
        (Some(g), state(2), 20, EntryKind::Directory),
    ] {
        assert_eq!(
            decoded.resolve(g, current, id, kind, seconds),
            seconds.map(hfs_to_filetime)
        );
    }
    let mut changed = seconds;
    changed[2] = 1;
    let resolved = decoded.resolve(Some(g), state(2), 20, EntryKind::File, changed);
    assert_eq!(resolved, [d[0], d[1], hfs_to_filetime(1), d[3]]);
    changed[0] = 1;
    assert_eq!(
        decoded.resolve(Some(g), state(2), 20, EntryKind::File, changed),
        changed.map(hfs_to_filetime)
    );
    assert!(catalog_seconds(u64::MAX).is_err());
}
#[test]
fn extended_wire_refuses_all_truncations_corruption_and_resealed_invalid_fields() {
    let seconds = dates().map(|d| catalog_seconds(d).unwrap());
    let bytes = ExtendedRecord::new(
        generation(),
        20,
        EntryKind::File,
        seconds,
        dates().map(Some),
    )
    .unwrap()
    .encode();
    for n in 0..bytes.len() {
        assert!(ExtendedRecord::decode(&bytes[..n]).is_none());
    }
    for n in 0..bytes.len() * 8 {
        let mut b = bytes;
        b[n / 8] ^= 1 << (n % 8);
        assert!(ExtendedRecord::decode(&b).is_none());
    }
    for (offset, value) in [
        (7, 3),
        (40, 3),
        (41, 16),
        (42, 1),
        (47, 1),
        (48, 1),
        (64, 255),
    ] {
        let mut b = bytes;
        b[offset] = value;
        let digest = Sha256::digest(&b[..96]);
        b[96..].copy_from_slice(&digest);
        assert!(ExtendedRecord::decode(&b).is_none(), "offset {offset}");
    }
    let mut b = bytes;
    b[41] &= !1;
    let digest = Sha256::digest(&b[..96]);
    b[96..].copy_from_slice(&digest);
    assert!(ExtendedRecord::decode(&b).is_none());
}
#[test]
fn adapter_preserves_extended_dates_across_reopen_and_version_transitions() {
    let mut a = Adapter::from_device(MemoryBackend::from_bytes(fixture())).unwrap();
    let h = a.open("\\dates", all()).unwrap();
    a.set_basic_times(h, times(dates())).unwrap();
    let before = a.file_info(h).unwrap();
    assert_eq!(
        [
            before.creation_time,
            before.access_time,
            before.write_time,
            before.change_time
        ],
        dates()
    );
    assert_eq!(
        a.set_basic_times(h, times([u64::MAX; 4]))
            .unwrap_err()
            .status,
        Status::InvalidParameter
    );
    a.close(h).unwrap();
    let mut disk = a.shutdown().unwrap();
    export("extended-dates.img", disk.as_slice());
    let fs = HfsPlus::open(&mut disk).unwrap();
    let body = fs.catalog_record("/dates").unwrap();
    assert_eq!(
        [12, 24, 16, 20].map(|off| volume::be32(&body, off)),
        [0, 0, u32::MAX, u32::MAX]
    );
    let mut a = Adapter::from_device(disk).unwrap();
    let h = a.open("\\dates", all()).unwrap();
    let info = a.file_info(h).unwrap();
    assert_eq!(
        [
            info.creation_time,
            info.access_time,
            info.write_time,
            info.change_time
        ],
        dates()
    );
    let modern = hfs_to_filetime(3782844800) + 1234567;
    a.set_basic_times(h, times([modern; 4])).unwrap();
    a.close(h).unwrap();
    let mut disk = a.shutdown().unwrap();
    export("legacy-compatible-dates.img", disk.as_slice());
    let fs = HfsPlus::open(&mut disk).unwrap();
    let cnid = volume::be32(&fs.catalog_record("/dates").unwrap(), 8);
    let record = fs
        .fixed_inline_attribute(&mut disk, cnid, TIMES_ATTRIBUTE, RECORD_BYTES)
        .unwrap()
        .unwrap();
    assert!(PrecisionRecord::decode(&record).is_some());
    // A foreign native edit invalidates Windows-only values volume-wide.
    let mut a = Adapter::from_device(disk).unwrap();
    let h = a.open("\\dates", all()).unwrap();
    a.set_basic_times(h, times(dates())).unwrap();
    a.close(h).unwrap();
    let mut disk = a.shutdown().unwrap();
    let mut fs = HfsPlus::open(&mut disk).unwrap();
    fs.set_catalog_times(cnid, [None, None, Some(3782844800), None])
        .unwrap();
    fs.flush(&mut disk).unwrap();
    let mut a = Adapter::from_device(disk).unwrap();
    let info = a.path_info("\\dates").unwrap();
    assert_eq!(info.creation_time, hfs_to_filetime(0));
    assert_eq!(info.write_time, hfs_to_filetime(3782844800));
}
#[test]
fn extended_date_record_catalog_and_generation_are_atomic_under_interruption() {
    let bytes = fixture();
    let info = volume::be32(&bytes, 1036) as usize * volume::be32(&bytes, 1064) as usize;
    let journal = volume::be64(&bytes, info + 36) as usize;
    let mut a = Adapter::from_device(MemoryBackend::from_bytes(bytes.clone())).unwrap();
    let old = a.path_info("\\dates").unwrap();
    let old = [
        old.creation_time,
        old.access_time,
        old.write_time,
        old.change_time,
    ];
    let run = |fail| {
        let d = fault::Disk::new(&bytes);
        let mut a = Adapter::from_device(d.clone()).unwrap();
        let h = a.open("\\dates", all()).unwrap();
        d.arm(fail);
        let result = a.set_basic_times(h, times(dates()));
        let calls = d.0.lock().unwrap().calls;
        if result.is_err() {
            assert!(a.failure().is_some());
            assert!(a.flush(None).is_err());
            assert_eq!(calls, d.0.lock().unwrap().calls);
        }
        (d, calls, result.is_ok())
    };
    let (_, calls, pass) = run(None);
    assert!(pass);
    let mut count = 0;
    for stop in 0..=calls {
        let (d, _, _) = run(Some(stop));
        for policy in 0..6 {
            let mut disk = MemoryBackend::from_bytes(d.snapshot(policy, journal));
            HfsPlus::open(&mut disk).unwrap();
            let mut a = Adapter::from_device(disk).unwrap();
            let i = a.path_info("\\dates").unwrap();
            let seen = [i.creation_time, i.access_time, i.write_time, i.change_time];
            assert!(seen == old || seen == dates(), "partial dates: {seen:?}");
            a.shutdown().unwrap();
            count += 1;
        }
    }
    println!("extended date fault snapshots: {count}");
}
