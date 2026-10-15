use fstool::{
    block::{BlockDevice, MemoryBackend},
    fs::hfs_plus::{CatalogUpdate, FormatOpts, HfsPlus, PublicationMetadata},
};
use hfs_bridge::volume;
use std::{io::Read, path::Path};
#[path = "support/fault_disk.rs"]
mod fault;

fn fixture(journaled: bool, sensitive: bool, block_size: u32, old: &str) -> Vec<u8> {
    let mut disk = MemoryBackend::new(4 * 1024 * 1024);
    let mut fs = HfsPlus::format(
        &mut disk,
        &FormatOpts {
            journaled,
            block_size,
            ..Default::default()
        },
    )
    .unwrap();
    fs.create_file(
        &mut disk,
        "/keep",
        &mut &b"untouched"[..],
        9,
        0o640,
        501,
        20,
        1_700_000_000,
    )
    .unwrap();
    fs.create_file(
        &mut disk,
        "/link",
        &mut &b""[..],
        0,
        0o750,
        501,
        20,
        1_700_000_000,
    )
    .unwrap();
    fs.flush(&mut disk).unwrap();
    fs.convert_empty_file_to_symlink_with_publication(
        &mut disk,
        Path::new("/link"),
        old,
        PublicationMetadata {
            attributes: &[
                ("com.example.preserved", Some(&vec![37; 8193])),
                ("com.example.version", Some(b"old")),
            ],
            related: &[(2, "com.example.marker", Some(b"old"))],
            ..Default::default()
        },
    )
    .unwrap();
    drop(fs);
    let mut bytes = disk.into_bytes();
    if sensitive {
        bytes[1024..1026].copy_from_slice(b"HX");
        bytes[1026..1028].copy_from_slice(&5u16.to_be_bytes());
        let catalog = volume::be32(&bytes, 1312) as usize * block_size as usize;
        bytes[catalog + 51] = 0xbc;
        let alternate = bytes.len() - 1024;
        let header = bytes[1024..1536].to_vec();
        bytes[alternate..alternate + 512].copy_from_slice(&header);
    }
    bytes
}
fn remove(fs: &mut HfsPlus, disk: &mut dyn BlockDevice, directory: bool) -> fstool::Result<()> {
    let cnid = volume::be32(&fs.catalog_record("/link")?, 8);
    fs.remove_symlink_with_publication(
        disk,
        Path::new("/link"),
        directory,
        PublicationMetadata {
            attributes: &[("com.example.version", Some(b"new"))],
            related: &[(2, "com.example.marker", Some(b"new"))],
            catalog: &[CatalogUpdate {
                cnid,
                times: [None, None, Some(3_800_000_000), Some(3_800_000_001)],
                attributes: None,
            }],
        },
    )
}
#[derive(Debug, PartialEq, Eq)]
struct State {
    body: Vec<u8>,
    target: Option<String>,
    version: Vec<u8>,
    marker: Vec<u8>,
    free: u32,
    counts: (u32, u32),
}
fn observe(bytes: Vec<u8>) -> State {
    let mut disk = MemoryBackend::from_bytes(bytes);
    let fs = HfsPlus::open(&mut disk).unwrap();
    let body = fs.catalog_record("/link").unwrap();
    let id = volume::be32(&body, 8);
    assert_eq!(volume::be32(&body, 32), 501);
    assert_eq!(volume::be32(&body, 36), 20);
    assert_eq!(
        fs.inline_attribute(&mut disk, id, "com.example.preserved")
            .unwrap()
            .unwrap(),
        vec![37; 8193]
    );
    let target = if volume::be16(&body, 42) & 0xf000 == 0xa000 {
        Some(fs.read_symlink_target(&mut disk, id).unwrap())
    } else {
        assert_eq!(&body[48..56], &[0; 8]);
        if body.len() == 248 {
            assert_eq!(volume::be16(&body, 42), 0x8000 | 0o750);
            let mut bytes = Vec::new();
            fs.open_file_reader(&mut disk, "/link")
                .unwrap()
                .read_to_end(&mut bytes)
                .unwrap();
            assert!(bytes.is_empty());
            assert!(body[100..248].iter().all(|x| *x == 0));
        } else {
            assert_eq!(body.len(), 88);
            assert_eq!(volume::be16(&body, 42), 0x4000 | 0o750);
            assert_eq!(volume::be32(&body, 4), 0);
        }
        None
    };
    let mut keep = Vec::new();
    fs.open_file_reader(&mut disk, "/keep")
        .unwrap()
        .read_to_end(&mut keep)
        .unwrap();
    assert_eq!(keep, b"untouched");
    let mut header = [0; 512];
    disk.read_at(1024, &mut header).unwrap();
    State {
        body,
        target,
        version: fs
            .inline_attribute(&mut disk, id, "com.example.version")
            .unwrap()
            .unwrap(),
        marker: fs
            .inline_attribute(&mut disk, 2, "com.example.marker")
            .unwrap()
            .unwrap(),
        free: volume::be32(&header, 48),
        counts: (volume::be32(&header, 32), volume::be32(&header, 36)),
    }
}
#[test]
fn removal_keeps_identity_ownership_attributes_and_retires_fork_on_all_formats() {
    for journaled in [false, true] {
        for sensitive in [false, true] {
            for bs in [512, 4096] {
                for directory in [false, true] {
                    let before = fixture(journaled, sensitive, bs, &"x".repeat(1024));
                    let old = observe(before.clone());
                    let mut disk = MemoryBackend::from_bytes(before);
                    let mut fs = HfsPlus::open(&mut disk).unwrap();
                    remove(&mut fs, &mut disk, directory).unwrap();
                    drop(fs);
                    let bytes = disk.into_bytes();
                    let new = observe(bytes.clone());
                    assert!(new.target.is_none());
                    assert_eq!(volume::be16(&new.body, 0), if directory { 1 } else { 2 });
                    assert_eq!(&new.body[8..16], &old.body[8..16]);
                    assert_eq!(&new.body[24..42], &old.body[24..42]);
                    assert_eq!(new.version, b"new");
                    assert_eq!(new.marker, b"new");
                    assert_eq!(new.free, old.free + 1024u32.div_ceil(bs));
                    assert_eq!(
                        new.counts,
                        if directory {
                            (old.counts.0 - 1, old.counts.1 + 1)
                        } else {
                            old.counts
                        }
                    );
                    if bs == 4096
                        && journaled
                        && let Some(dir) = std::env::var_os("HFS_LINK_REMOVAL_DIR")
                    {
                        std::fs::create_dir_all(&dir).unwrap();
                        let path =
                            Path::new(&dir).join(format!("core-{sensitive}-{directory}.img"));
                        assert!(!path.exists());
                        std::fs::write(path, bytes).unwrap();
                    }
                }
            }
        }
    }
}
#[test]
fn ordinary_nodes_flags_and_finder_replacement_are_refused_without_io() {
    for scenario in 0..4 {
        let before = fixture(true, false, 512, "keep");
        let mut disk = fault::Disk::new(&before);
        let mut fs = HfsPlus::open(&mut disk).unwrap();
        let id = volume::be32(&fs.catalog_record("/link").unwrap(), 8);
        disk.arm(None);
        let catalog = [CatalogUpdate {
            cnid: id,
            times: [None; 4],
            attributes: Some(0x20),
        }];
        let attrs = [("com.apple.FinderInfo", Some(&[0u8; 32][..]))];
        let metadata = PublicationMetadata {
            catalog: if scenario == 2 { &catalog } else { &[] },
            attributes: if scenario == 3 { &attrs } else { &[] },
            ..Default::default()
        };
        assert!(
            fs.remove_symlink_with_publication(
                &mut disk,
                Path::new(if scenario == 0 {
                    "/keep"
                } else if scenario == 1 {
                    "/"
                } else {
                    "/link"
                }),
                true,
                metadata
            )
            .is_err()
        );
        drop(fs);
        assert_eq!(disk.0.lock().unwrap().calls, 0);
        assert_eq!(disk.snapshot(1, 0), before);
    }
}
#[test]
fn every_removal_commit_and_replay_recovers_complete_old_or_new_type() {
    let mut commits = 0;
    let mut replays = 0;
    for directory in [false, true] {
        let before = fixture(true, false, 512, &"x".repeat(1024));
        let old = observe(before.clone());
        let journal = match volume::inspect(&mut MemoryBackend::from_bytes(before.clone()))
            .unwrap()
            .journal
        {
            volume::Journal::Clean { offset, .. } => offset as usize,
            _ => panic!("journal required"),
        };
        let mut complete = fault::Disk::new(&before);
        let mut fs = HfsPlus::open(&mut complete).unwrap();
        complete.arm(None);
        remove(&mut fs, &mut complete, directory).unwrap();
        drop(fs);
        let calls = complete.0.lock().unwrap().calls;
        let new = observe(complete.snapshot(1, journal));
        let mut pending = None;
        for failure in 0..calls {
            let mut disk = fault::Disk::new(&before);
            let mut fs = HfsPlus::open(&mut disk).unwrap();
            disk.arm(Some(failure));
            assert!(remove(&mut fs, &mut disk, directory).is_err());
            drop(fs);
            for policy in 0..6 {
                let bytes = disk.snapshot(policy, journal);
                if matches!(
                    volume::inspect(&mut MemoryBackend::from_bytes(bytes.clone()))
                        .unwrap()
                        .journal,
                    volume::Journal::Pending { .. }
                ) {
                    pending.get_or_insert_with(|| bytes.clone());
                }
                let actual = observe(bytes);
                assert!(
                    actual == old || actual == new,
                    "partial removal {failure}/{policy}"
                );
                commits += 1;
            }
        }
        let pending = pending.unwrap();
        let mut complete = fault::Disk::new(&pending);
        HfsPlus::open(&mut complete).unwrap();
        let calls = complete.0.lock().unwrap().calls;
        for failure in 0..calls {
            let mut disk = fault::Disk::new(&pending);
            disk.arm(Some(failure));
            assert!(HfsPlus::open(&mut disk).is_err());
            for policy in 0..6 {
                assert_eq!(observe(disk.snapshot(policy, journal)), new);
                replays += 1;
            }
        }
    }
    println!("LINK_REMOVAL: {commits} commit + {replays} replay snapshots");
}
