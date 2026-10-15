//! Attribute payload/ownership publication at each write and sync boundary.
//! Selected atomic-512-sector cache policies, not hardware power-loss proof.
use fstool::{
    block::MemoryBackend,
    fs::hfs_plus::{FormatOpts, HfsPlus},
};
use hfs_bridge::{engine, volume, windows::Adapter};
#[path = "support/fault_disk.rs"]
mod fault;
#[path = "support/attribute_wire.rs"]
#[allow(dead_code)]
mod wire;
use fault::Disk;
use std::io::Write;
const NAME: &str = "com.example.large";
fn value(new: bool) -> Vec<u8> {
    (0..if new { 13_013 } else { 8_207 })
        .map(|i| (i * if new { 29 } else { 17 }) as u8)
        .collect()
}
fn journal_offset(bytes: &[u8]) -> usize {
    let info = volume::be32(bytes, 1036) as usize * volume::be32(bytes, 1064) as usize;
    volume::be64(bytes, info + 36) as usize
}
fn fixture(operation: usize, little: bool, wrap: bool, sensitive: bool) -> Vec<u8> {
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
        &mut &b"main data"[..],
        9,
        0o640,
        501,
        20,
        0,
    )
    .unwrap();
    fs.create_file(
        &mut disk,
        "/survivor",
        &mut &b"survivor"[..],
        8,
        0o600,
        502,
        21,
        0,
    )
    .unwrap();
    fs.flush(&mut disk).unwrap();
    {
        let mut resource = fs
            .open_resource_fork_rw(&mut disk, std::path::Path::new("/file"))
            .unwrap();
        resource.write_all(b"resource data preserved").unwrap();
        resource.sync().unwrap();
    }
    if operation != 0 {
        let cnid = volume::be32(&fs.catalog_record("/file").unwrap(), 8);
        fs.set_inline_attribute(&mut disk, cnid, NAME, Some(&value(false)))
            .unwrap();
        fs.flush(&mut disk).unwrap();
    }
    drop(fs);
    let mut bytes = disk.into_bytes();
    if sensitive {
        bytes[1024..1026].copy_from_slice(b"HX");
        wire::p16(&mut bytes, 1026, 5);
        let cat = volume::be32(&bytes, 1312) as usize * 4096;
        bytes[cat + 51] = 0xbc;
        let alternate = bytes.len() - 1024;
        let header = bytes[1024..1536].to_vec();
        bytes[alternate..alternate + 512].copy_from_slice(&header);
    }
    let j = journal_offset(&bytes);
    let size = volume::be64(&bytes, j + 24);
    let cursor = if wrap { size - 512 } else { 512 };
    if little {
        for (offset, width) in [
            (0, 4),
            (4, 4),
            (8, 8),
            (16, 8),
            (24, 8),
            (32, 4),
            (36, 4),
            (40, 4),
            (44, 4),
        ] {
            bytes[j + offset..j + offset + width].reverse();
        }
    }
    for offset in [8, 16] {
        bytes[j + offset..j + offset + 8].copy_from_slice(&if little {
            cursor.to_le_bytes()
        } else {
            cursor.to_be_bytes()
        });
    }
    bytes[j + 36..j + 40].fill(0);
    let checksum = volume::journal_checksum(&bytes[j..j + 44]);
    bytes[j + 36..j + 40].copy_from_slice(&if little {
        checksum.to_le_bytes()
    } else {
        checksum.to_be_bytes()
    });
    bytes
}
fn attempt(bytes: &[u8], operation: usize, stop: Option<usize>) -> (bool, Disk) {
    let mut disk = Disk::new(bytes);
    let mut fs = engine::open_checked(&mut disk).unwrap();
    let cnid = volume::be32(&fs.catalog_record("/file").unwrap(), 8);
    disk.arm(stop);
    match operation {
        0 | 1 => fs
            .set_inline_attribute(&mut disk, cnid, NAME, Some(&value(true)))
            .unwrap(),
        2 => fs
            .set_inline_attribute(&mut disk, cnid, NAME, Some(b"small"))
            .unwrap(),
        3 => fs
            .set_inline_attribute(&mut disk, cnid, NAME, None)
            .unwrap(),
        4 => fs
            .set_inline_attributes(
                &mut disk,
                cnid,
                &[
                    (NAME, Some(&value(true))),
                    ("com.example.small", Some(b"batch")),
                    (
                        "com.apple.FinderInfo",
                        Some(&fstool::fs::hfs_plus::attributes::public_finder_info(
                            &[0x37; 32],
                        )),
                    ),
                ],
            )
            .unwrap(),
        5 => fs.remove(&mut disk, "/file").unwrap(),
        _ => unreachable!(),
    }
    let success = fs.flush(&mut disk).is_ok();
    if !success {
        let calls = disk.0.lock().unwrap().calls;
        assert!(fs.flush(&mut disk).is_err());
        assert_eq!(disk.0.lock().unwrap().calls, calls, "failed writer retried");
    }
    (success, disk)
}
fn audit_ownership(bytes: &[u8]) {
    let bs = volume::be32(bytes, 1064) as usize;
    let total = volume::be32(bytes, 1068) as usize;
    let mut used = vec![false; total];
    let mut mark = |start: usize, count: usize| {
        assert!(start + count <= total);
        for bit in &mut used[start..start + count] {
            assert!(!*bit, "shared allocation block");
            *bit = true;
        }
    };
    mark(0, 1536usize.div_ceil(bs));
    mark((total * bs - 1024) / bs, 1024usize.div_ceil(bs));
    let mut fork = |descriptor: usize| {
        for i in 0..8 {
            mark(
                volume::be32(bytes, descriptor + 16 + i * 8) as usize,
                volume::be32(bytes, descriptor + 20 + i * 8) as usize,
            );
        }
    };
    for offset in [1136, 1216, 1296, 1376, 1456] {
        fork(offset);
    }
    let cat = volume::be32(bytes, 1312) as usize * bs;
    let ns = wire::u16be(bytes, cat + 32) as usize;
    let mut leaf = volume::be32(bytes, cat + 24);
    while leaf != 0 {
        let node = cat + leaf as usize * ns;
        for i in 0..wire::u16be(bytes, node + 10) as usize {
            let key = node + wire::u16be(bytes, node + ns - 2 * (i + 1)) as usize;
            let body = key + 2 + wire::u16be(bytes, key) as usize;
            if wire::u16be(bytes, body) == 2 {
                fork(body + 88);
                fork(body + 168);
            }
        }
        leaf = volume::be32(bytes, node);
    }
    if volume::be32(bytes, 1388) != 0 {
        for record in wire::audit_initialized(bytes) {
            let body = 2 + wire::u16be(&record, 0) as usize;
            if volume::be32(&record, body) == 0x20 {
                for i in 0..8 {
                    mark(
                        volume::be32(&record, body + 24 + i * 8) as usize,
                        volume::be32(&record, body + 28 + i * 8) as usize,
                    );
                }
            }
        }
    }
    let bitmap = volume::be32(bytes, 1152) as usize * bs;
    for (block, &owner) in used.iter().enumerate() {
        assert_eq!(
            bytes[bitmap + block / 8] & (0x80 >> (block % 8)) != 0,
            owner,
            "ownership of block {block}"
        );
    }
    assert_eq!(
        used.iter().filter(|&&bit| !bit).count() as u32,
        volume::be32(bytes, 1072)
    );
}
fn verify(
    bytes: &[u8],
    operation: usize,
    before: &[u8],
    main: &engine::FileSnapshot,
    survivor: &engine::FileSnapshot,
) {
    let mut disk = Disk::new(bytes);
    let fs = HfsPlus::open(&mut disk).unwrap(); // explicit test-only replay
    assert_eq!(
        &engine::snapshot_device(&mut disk, "/survivor", &[]).unwrap(),
        survivor
    );
    if let Ok(body) = fs.catalog_record("/file") {
        let cnid = volume::be32(&body, 8);
        let actual = fs.inline_attribute(&mut disk, cnid, NAME).unwrap();
        let old = if operation == 0 {
            None
        } else {
            Some(value(false))
        };
        let new = match operation {
            0 | 1 | 4 => Some(value(true)),
            2 => Some(b"small".to_vec()),
            3 => None,
            5 => old.clone(),
            _ => unreachable!(),
        };
        assert!(actual == old || actual == new, "torn attribute payload");
        let batch_new = operation == 4 && actual == new;
        assert_eq!(
            fs.inline_attribute(&mut disk, cnid, "com.example.small")
                .unwrap(),
            if batch_new {
                Some(b"batch".to_vec())
            } else {
                None
            }
        );
        let finder = fstool::fs::hfs_plus::attributes::public_finder_info(&[0x37; 32]);
        assert_eq!(&body[48..80], if batch_new { &finder } else { &[0; 32] });
        let mut normalized = body.clone();
        normalized[48..80].copy_from_slice(&before[48..80]);
        normalized[2..4].copy_from_slice(&before[2..4]);
        assert_eq!(
            normalized, before,
            "data/resource fork or ownership changed"
        );
        let mut actual_snapshot = engine::snapshot_device(&mut disk, "/file", &[]).unwrap();
        actual_snapshot.catalog_sha256 = main.catalog_sha256.clone();
        assert_eq!(
            &actual_snapshot, main,
            "main data/resource payload or Mac ownership changed"
        );
        assert_eq!(
            volume::be16(&body, 2) & 4,
            if actual.is_some() || batch_new { 4 } else { 0 }
        );
    } else {
        assert_eq!(operation, 5);
    }
    audit_ownership(&disk.0.lock().unwrap().durable);
}
fn retain(bytes: &[u8], name: &str) {
    if let Some(directory) = std::env::var_os("HFS_ATTRIBUTE_FORK_CRASH_ARTIFACT_DIR") {
        std::fs::create_dir_all(&directory).unwrap();
        std::fs::write(std::path::PathBuf::from(directory).join(name), bytes).unwrap();
    }
}
#[test]
fn attribute_fork_payload_bitmap_catalog_commit_and_replay_are_atomic() {
    let mut commit_checks = 0;
    let mut replay_checks = 0;
    for sensitive in [false, true] {
        for little in [false, true] {
            for wrap in [false, true] {
                for operation in 0..6 {
                    let baseline = fixture(operation, little, wrap, sensitive);
                    let j = journal_offset(&baseline);
                    let mut probe = Disk::new(&baseline);
                    let fs = HfsPlus::open(&mut probe).unwrap();
                    let before = fs.catalog_record("/file").unwrap();
                    let main = engine::snapshot_device(&mut probe, "/file", &[]).unwrap();
                    let survivor = engine::snapshot_device(&mut probe, "/survivor", &[]).unwrap();
                    let (success, full) = attempt(&baseline, operation, None);
                    assert!(success);
                    let count = full.0.lock().unwrap().calls;
                    let completed = full.0.lock().unwrap().durable.clone();
                    verify(&completed, operation, &before, &main, &survivor);
                    let label = format!("{sensitive}-{little}-{wrap}-{operation}");
                    retain(&completed, &format!("fork-commit-{label}.img"));
                    let mut pending = None;
                    for stop in 0..count {
                        let (success, interrupted) = attempt(&baseline, operation, Some(stop));
                        assert!(!success);
                        for policy in 0..6 {
                            let bytes = interrupted.snapshot(policy, j);
                            if matches!(
                                volume::inspect(&mut Disk::new(&bytes)).unwrap().journal,
                                volume::Journal::Pending { .. }
                            ) {
                                pending.get_or_insert_with(|| bytes.clone());
                                let rejected = Disk::new(&bytes);
                                rejected.arm(Some(0));
                                assert!(Adapter::from_device(rejected.clone()).is_err());
                                assert_eq!(rejected.0.lock().unwrap().calls, 0);
                            }
                            verify(&bytes, operation, &before, &main, &survivor);
                            commit_checks += 1;
                        }
                    }
                    let pending = pending.expect("no pending transaction observed");
                    let mut replay = Disk::new(&pending);
                    HfsPlus::open(&mut replay).unwrap();
                    let count = replay.0.lock().unwrap().calls;
                    for stop in 0..count {
                        let mut interrupted = Disk::new(&pending);
                        interrupted.arm(Some(stop));
                        assert!(HfsPlus::open(&mut interrupted).is_err());
                        for policy in 0..6 {
                            verify(
                                &interrupted.snapshot(policy, j),
                                operation,
                                &before,
                                &main,
                                &survivor,
                            );
                            replay_checks += 1;
                        }
                    }
                    println!("fork scenario {label}: pass");
                }
            }
        }
    }
    println!(
        "FORK_ATTRIBUTE_MATRIX: {commit_checks} commit checkpoints + {replay_checks} replay checkpoints passed; 48 scenarios"
    );
}
