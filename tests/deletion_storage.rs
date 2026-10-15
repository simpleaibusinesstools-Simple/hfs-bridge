use fstool::block::MemoryBackend;
use fstool::fs::hfs_plus::{FormatOpts, HfsPlus};
use hfs_bridge::volume;
use hfs_bridge::windows::{Access, Adapter, OpenRequest};
use std::io::Write;
#[path = "support/fault_disk.rs"]
mod faults;

fn record(bytes: &[u8], cnid: u32) -> usize {
    let base = volume::be32(bytes, 1312) as usize * 4096;
    let size = volume::be16(bytes, base + 32) as usize;
    let mut leaf = volume::be32(bytes, base + 24);
    while leaf != 0 {
        let node = base + leaf as usize * size;
        for i in 0..volume::be16(bytes, node + 10) as usize {
            let key = node + volume::be16(bytes, node + size - 2 * (i + 1)) as usize;
            let body = key + 2 + volume::be16(bytes, key) as usize;
            if volume::be16(bytes, body) == 2 && volume::be32(bytes, body + 8) == cnid {
                return body;
            }
        }
        leaf = volume::be32(bytes, node);
    }
    panic!("missing catalog record");
}

#[test]
fn deleting_a_file_with_another_files_storage_must_refuse_before_mutation() {
    let mut disk = MemoryBackend::new(16 * 1024 * 1024);
    let mut fs = HfsPlus::format(
        &mut disk,
        &FormatOpts {
            journaled: true,
            ..Default::default()
        },
    )
    .unwrap();
    for path in ["/first", "/second"] {
        fs.create_file(
            &mut disk,
            path,
            &mut &b"owned contents"[..],
            14,
            0o644,
            501,
            20,
            0,
        )
        .unwrap();
    }
    fs.flush(&mut disk).unwrap();
    let first = volume::be32(&fs.catalog_record("/first").unwrap(), 8);
    let second = volume::be32(&fs.catalog_record("/second").unwrap(), 8);
    drop(fs);
    let mut bytes = disk.into_bytes();
    let a = record(&bytes, first);
    let b = record(&bytes, second);
    let other_fork = bytes[b + 88..b + 168].to_vec();
    bytes[a + 88..a + 168].copy_from_slice(&other_fork);
    let baseline = bytes.clone();
    let mut disk = MemoryBackend::from_bytes(bytes);
    let mut fs = HfsPlus::open(&mut disk).unwrap();
    assert!(
        fs.remove(&mut disk, "/first").is_err(),
        "deletion accepted a fork owned by another file"
    );
    assert!(fs.catalog_record("/first").is_ok());
    assert_eq!(disk.as_slice(), baseline);
}

fn fixture(journaled: bool) -> (Vec<u8>, u32, u32) {
    let mut disk = MemoryBackend::new(16 * 1024 * 1024);
    let mut fs = HfsPlus::format(
        &mut disk,
        &FormatOpts {
            journaled,
            ..Default::default()
        },
    )
    .unwrap();
    for path in ["/first", "/second"] {
        fs.create_file(
            &mut disk,
            path,
            &mut &b"owned contents"[..],
            14,
            0o644,
            501,
            20,
            0,
        )
        .unwrap();
        let mut resource = fs.open_resource_fork_rw(&mut disk, path.as_ref()).unwrap();
        resource.write_all(&[0x5a; 9000]).unwrap();
        resource.sync().unwrap();
    }
    fs.flush(&mut disk).unwrap();
    let a = volume::be32(&fs.catalog_record("/first").unwrap(), 8);
    let b = volume::be32(&fs.catalog_record("/second").unwrap(), 8);
    drop(fs);
    (disk.into_bytes(), a, b)
}

fn put32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
}

fn single_block(bytes: &mut [u8], fork: usize, start: u32) {
    bytes[fork..fork + 80].fill(0);
    bytes[fork..fork + 8].copy_from_slice(&1u64.to_be_bytes());
    put32(bytes, fork + 12, 1);
    put32(bytes, fork + 16, start);
    put32(bytes, fork + 20, 1);
}

#[test]
fn malformed_reclamation_is_refused_without_writes_by_engine_cleanup_and_replacement() {
    let mut cases = 0;
    for journaled in [false, true] {
        let (baseline, a, b) = fixture(journaled);
        let first = record(&baseline, a);
        let second = record(&baseline, b);
        for fork in [88, 168] {
            for problem in 0..12 {
                if !journaled && matches!(problem, 5 | 6) {
                    continue;
                }
                let mut bytes = baseline.clone();
                let at = first + fork;
                match problem {
                    0 | 1 => {
                        let other = second + if problem == 0 { 88 } else { 168 };
                        let body = bytes[other..other + 80].to_vec();
                        bytes[at..at + 80].copy_from_slice(&body);
                    }
                    2 => {
                        let other = first + if fork == 88 { 168 } else { 88 };
                        let body = bytes[other..other + 80].to_vec();
                        bytes[at..at + 80].copy_from_slice(&body);
                    }
                    3 => single_block(&mut bytes, at, 0),
                    4 => {
                        let bitmap = volume::be32(&bytes, 1152);
                        single_block(&mut bytes, at, bitmap);
                    }
                    5 | 6 => {
                        let jib = volume::be32(&bytes, 1036);
                        let block = if problem == 5 {
                            jib
                        } else {
                            (volume::be64(&bytes, jib as usize * 4096 + 36) / 4096) as u32
                        };
                        single_block(&mut bytes, at, block);
                    }
                    7 => {
                        let last = volume::be32(&bytes, 1068) - 1;
                        single_block(&mut bytes, at, last);
                    }
                    8 => {
                        let start = volume::be32(&bytes, at + 16);
                        let bitmap = volume::be32(&bytes, 1152) as usize * 4096;
                        bytes[bitmap + start as usize / 8] &= !(0x80 >> (start % 8));
                    }
                    9 => put32(&mut bytes, at + 12, u32::MAX),
                    10 => bytes[at..at + 8].copy_from_slice(&u64::MAX.to_be_bytes()),
                    11 => {
                        let start = volume::be32(&bytes, at + 16);
                        single_block(&mut bytes, at, start);
                        put32(&mut bytes, at + 12, 2);
                        put32(&mut bytes, at + 24, start);
                        put32(&mut bytes, at + 28, 1);
                    }
                    _ => unreachable!(),
                }
                let mut disk = faults::Disk::new(&bytes);
                let observer = disk.clone();
                let mut fs = HfsPlus::open(&mut disk).unwrap();
                observer.arm(None);
                assert!(
                    fs.remove(&mut disk, "/first").is_err(),
                    "engine accepted {journaled}/{fork}/{problem}"
                );
                assert!(fs.catalog_record("/first").is_ok());
                assert_eq!(observer.0.lock().unwrap().calls, 0);
                assert_eq!(observer.snapshot(1, 0), bytes);
                drop(fs);
                let mut adapter = Adapter::from_device(disk).unwrap();
                let request = OpenRequest {
                    access: Access::ALL,
                    ..Default::default()
                };
                let first = adapter.open("\\first", request).unwrap();
                let second = adapter.open("\\second", request).unwrap();
                observer.arm(None);
                assert!(adapter.can_delete(first).is_err());
                assert!(adapter.cleanup(first, true).is_err());
                // Close the destination so sharing checks cannot mask the
                // storage-ownership preflight on replacement.
                adapter.close(first).unwrap();
                assert!(
                    adapter
                        .rename_with_replace(second, "\\first", true)
                        .is_err()
                );
                assert!(adapter.failure().is_none());
                assert_eq!(observer.0.lock().unwrap().calls, 0);
                assert_eq!(observer.snapshot(1, 0), bytes);
                adapter.close(second).unwrap();
                adapter.shutdown().unwrap();
                cases += 1;
            }
        }
    }
    assert_eq!(cases, 44);
    println!(
        "RECLAMATION_GUARDS: {cases} malformed data/resource cases refused by engine, cleanup and replacement with zero writes"
    );
}

#[test]
fn orphan_recovery_validates_all_storage_before_reclamation() {
    let (bytes, a, b) = fixture(true);
    let disk = faults::Disk::new(&bytes);
    let observer = disk.clone();
    let mut adapter = Adapter::from_device(disk).unwrap();
    let file = adapter
        .open(
            "\\first",
            OpenRequest {
                access: Access::ALL,
                ..Default::default()
            },
        )
        .unwrap();
    adapter.cleanup(file, true).unwrap();
    let mut bytes = observer.snapshot(1, 0);
    drop(adapter);
    let first = record(&bytes, a);
    let second = record(&bytes, b);
    let other = bytes[second + 88..second + 168].to_vec();
    bytes[first + 88..first + 168].copy_from_slice(&other);
    let disk = faults::Disk::new(&bytes);
    let observer = disk.clone();
    observer.arm(None);
    assert!(Adapter::from_device(disk).is_err());
    assert_eq!(observer.0.lock().unwrap().calls, 0);
    assert_eq!(observer.snapshot(1, 0), bytes);
}

#[test]
fn deletion_refuses_blocks_owned_by_a_fork_backed_attribute() {
    let (bytes, a, b) = fixture(true);
    let mut disk = MemoryBackend::from_bytes(bytes);
    let mut fs = HfsPlus::open(&mut disk).unwrap();
    fs.set_inline_attribute(&mut disk, b, "org.example.large", Some(&vec![0xa5; 70019]))
        .unwrap();
    fs.flush(&mut disk).unwrap();
    drop(fs);
    let mut bytes = disk.into_bytes();
    let base = volume::be32(&bytes, 1392) as usize * 4096;
    let size = volume::be16(&bytes, base + 32) as usize;
    let leaf = base + volume::be32(&bytes, base + 24) as usize * size;
    let key = leaf + volume::be16(&bytes, leaf + size - 2) as usize;
    assert_eq!(volume::be32(&bytes, key + 4), b);
    let body = key + 2 + volume::be16(&bytes, key) as usize;
    assert_eq!(volume::be32(&bytes, body), 0x20);
    let fork = bytes[body + 8..body + 88].to_vec();
    let a = record(&bytes, a);
    bytes[a + 88..a + 168].copy_from_slice(&fork);
    let mut disk = faults::Disk::new(&bytes);
    let observer = disk.clone();
    let mut fs = HfsPlus::open(&mut disk).unwrap();
    observer.arm(None);
    assert!(fs.remove(&mut disk, "/first").is_err());
    assert!(fs.catalog_record("/first").is_ok());
    assert_eq!(observer.0.lock().unwrap().calls, 0);
    assert_eq!(observer.snapshot(1, 0), bytes);
}

#[test]
fn valid_fragmented_deletion_reclaims_overflow_and_refuses_foreign_overflow_claims() {
    use std::io::Read;
    for resource in [false, true] {
        let mut disk = MemoryBackend::new(1024 * 1024);
        let mut fs = HfsPlus::format(&mut disk, &FormatOpts::default()).unwrap();
        for index in 0..9 {
            for prefix in ["gap", "keep"] {
                fs.create_file(
                    &mut disk,
                    &format!("/{prefix}{index}"),
                    &mut std::io::repeat(0x42),
                    4096,
                    0o644,
                    501,
                    20,
                    0,
                )
                .unwrap();
            }
        }
        fs.flush(&mut disk).unwrap();
        let remaining = u64::from(volume::inspect(&mut disk).unwrap().header.free_blocks) * 4096;
        fs.create_file(
            &mut disk,
            "/fill",
            &mut std::io::repeat(0),
            remaining,
            0o644,
            501,
            20,
            0,
        )
        .unwrap();
        fs.flush(&mut disk).unwrap();
        for index in 0..9 {
            fs.remove(&mut disk, &format!("/gap{index}")).unwrap();
        }
        fs.flush(&mut disk).unwrap();
        let payload = vec![0x53; 9 * 4096];
        fs.create_file(
            &mut disk,
            "/fragmented",
            &mut &if resource { &[][..] } else { &payload[..] }[..],
            if resource { 0 } else { payload.len() as u64 },
            0o644,
            501,
            20,
            0,
        )
        .unwrap();
        if resource {
            let mut file = fs
                .open_resource_fork_rw(&mut disk, "/fragmented".as_ref())
                .unwrap();
            file.write_all(&payload).unwrap();
            file.sync().unwrap();
        }
        fs.flush(&mut disk).unwrap();
        let target = volume::be32(&fs.catalog_record("/fragmented").unwrap(), 8);
        let victim = volume::be32(&fs.catalog_record("/keep0").unwrap(), 8);
        drop(fs);
        let baseline = disk.into_bytes();
        let base = volume::be32(&baseline, 1232) as usize * 4096;
        let size = volume::be16(&baseline, base + 32) as usize;
        let leaf = base + volume::be32(&baseline, base + 24) as usize * size;
        let key = leaf + volume::be16(&baseline, leaf + size - 2) as usize;
        assert_eq!(volume::be32(&baseline, key + 4), target);
        assert_eq!(volume::be32(&baseline, key + 8), 8);
        let start = volume::be32(&baseline, key + 12);
        let mut corrupt = baseline.clone();
        let victim = record(&corrupt, victim);
        single_block(&mut corrupt, victim + 88, start);
        let mut damaged = faults::Disk::new(&corrupt);
        let observer = damaged.clone();
        let mut fs = HfsPlus::open(&mut damaged).unwrap();
        observer.arm(None);
        assert!(fs.remove(&mut damaged, "/keep0").is_err());
        assert_eq!(observer.0.lock().unwrap().calls, 0);
        assert_eq!(observer.snapshot(1, 0), corrupt);
        drop(fs);
        let mut valid = MemoryBackend::from_bytes(baseline);
        let mut fs = HfsPlus::open(&mut valid).unwrap();
        let before = volume::inspect(&mut valid).unwrap().header.free_blocks;
        fs.remove(&mut valid, "/fragmented").unwrap();
        fs.flush(&mut valid).unwrap();
        assert_eq!(
            volume::inspect(&mut valid).unwrap().header.free_blocks,
            before + 9
        );
        drop(fs);
        let fs = HfsPlus::open(&mut valid).unwrap();
        assert!(fs.catalog_record("/fragmented").is_err());
        let mut actual = Vec::new();
        fs.open_file_reader(&mut valid, "/keep0")
            .unwrap()
            .read_to_end(&mut actual)
            .unwrap();
        assert_eq!(actual, vec![0x42; 4096]);
    }
}
