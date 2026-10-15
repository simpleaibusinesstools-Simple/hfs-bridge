use fstool::{
    block::{BlockDevice, MemoryBackend},
    fs::{
        Filesystem,
        hfs_plus::{CatalogUpdate, FormatOpts, HfsPlus, PublicationMetadata},
    },
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
fn replace(fs: &mut HfsPlus, disk: &mut dyn BlockDevice, target: &str) -> fstool::Result<()> {
    let cnid = volume::be32(&fs.catalog_record("/link")?, 8);
    fs.replace_symlink_target_with_publication(
        disk,
        Path::new("/link"),
        target,
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
    target: String,
    version: Vec<u8>,
    marker: Vec<u8>,
    free: u32,
}
fn observe(bytes: Vec<u8>) -> State {
    let mut disk = MemoryBackend::from_bytes(bytes);
    let fs = HfsPlus::open(&mut disk).unwrap();
    let body = fs.catalog_record("/link").unwrap();
    let id = volume::be32(&body, 8);
    assert_eq!(&body[48..56], b"slnkrhap");
    assert_eq!(volume::be16(&body, 42), 0xa000 | 0o750);
    assert_eq!(volume::be32(&body, 32), 501);
    assert_eq!(volume::be32(&body, 36), 20);
    assert!(body[168..248].iter().all(|x| *x == 0));
    assert_eq!(
        fs.inline_attribute(&mut disk, id, "com.example.preserved")
            .unwrap()
            .unwrap(),
        vec![37; 8193]
    );
    let mut keep = Vec::new();
    fs.open_file_reader(&mut disk, "/keep")
        .unwrap()
        .read_to_end(&mut keep)
        .unwrap();
    assert_eq!(keep, b"untouched");
    State {
        target: fs.read_symlink_target(&mut disk, id).unwrap(),
        version: fs
            .inline_attribute(&mut disk, id, "com.example.version")
            .unwrap()
            .unwrap(),
        marker: fs
            .inline_attribute(&mut disk, 2, "com.example.marker")
            .unwrap()
            .unwrap(),
        free: volume::inspect(&mut disk).unwrap().header.free_blocks,
        body,
    }
}
#[test]
fn replacements_grow_shrink_and_preserve_identity_on_all_four_formats() {
    for journaled in [false, true] {
        for sensitive in [false, true] {
            for bs in [512, 4096] {
                let mut bytes = fixture(journaled, sensitive, bs, "old");
                let old = observe(bytes.clone());
                for target in ["x".repeat(1024), "café".into(), "new".into()] {
                    let mut disk = MemoryBackend::from_bytes(bytes);
                    let mut fs = HfsPlus::open(&mut disk).unwrap();
                    replace(&mut fs, &mut disk, &target).unwrap();
                    drop(fs);
                    bytes = disk.into_bytes();
                    let state = observe(bytes.clone());
                    assert_eq!(state.target, target);
                    assert_eq!(state.version, b"new");
                    assert_eq!(state.marker, b"new");
                    assert_eq!(&state.body[8..16], &old.body[8..16]);
                    assert_eq!(&state.body[24..88], &old.body[24..88]);
                }
                assert_eq!(
                    observe(bytes.clone()).free,
                    old.free,
                    "replacement leaked allocation"
                );
                if bs == 4096
                    && let Some(dir) = std::env::var_os("HFS_LINK_REPLACEMENT_ARTIFACT_DIR")
                {
                    std::fs::create_dir_all(&dir).unwrap();
                    let path =
                        Path::new(&dir).join(format!("replacement-{journaled}-{sensitive}.img"));
                    assert!(!path.exists());
                    std::fs::write(path, bytes).unwrap();
                }
            }
        }
    }
}
#[test]
fn invalid_replacements_refuse_without_writes_and_ordinary_editors_stay_blocked() {
    for scenario in 0..8 {
        let before = fixture(true, false, 512, "old");
        let mut disk = fault::Disk::new(&before);
        let mut fs = HfsPlus::open(&mut disk).unwrap();
        let id = volume::be32(&fs.catalog_record("/link").unwrap(), 8);
        let long = "x".repeat(1025);
        let target = match scenario {
            0 => "",
            1 => "/absolute",
            2 => "bad\0target",
            3 => &long,
            _ => "new",
        };
        disk.arm(None);
        let result = match scenario {
            4 => fs.replace_symlink_target_with_publication(
                &mut disk,
                Path::new("/keep"),
                target,
                Default::default(),
            ),
            5 => fs.replace_symlink_target_with_publication(
                &mut disk,
                Path::new("/link"),
                target,
                PublicationMetadata {
                    catalog: &[CatalogUpdate {
                        cnid: id,
                        times: [None; 4],
                        attributes: Some(0x20),
                    }],
                    ..Default::default()
                },
            ),
            6 => fs.replace_symlink_target_with_publication(
                &mut disk,
                Path::new("/link"),
                target,
                PublicationMetadata {
                    attributes: &[("com.apple.FinderInfo", Some(&[0; 32]))],
                    ..Default::default()
                },
            ),
            7 => fs
                .open_file_rw(&mut disk, Path::new("/link"), Default::default(), None)
                .map(|_| ()),
            _ => replace(&mut fs, &mut disk, target),
        };
        assert!(result.is_err(), "scenario {scenario}");
        drop(fs);
        assert_eq!(
            disk.0.lock().unwrap().calls,
            0,
            "refusal {scenario} wrote or flushed"
        );
        assert_eq!(disk.snapshot(1, 0), before);
    }
}
#[test]
fn every_commit_and_replay_failure_retains_old_or_new_complete_link() {
    let mut commits = 0;
    let mut replays = 0;
    for (old_target, target) in [
        ("old".into(), "x".repeat(1024)),
        ("x".repeat(1024), "new".into()),
    ] {
        let before = fixture(true, false, 512, &old_target);
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
        replace(&mut fs, &mut complete, &target).unwrap();
        drop(fs);
        let calls = complete.0.lock().unwrap().calls;
        let new = observe(complete.snapshot(1, journal));
        let mut pending = None;
        for failure in 0..calls {
            let mut disk = fault::Disk::new(&before);
            let mut fs = HfsPlus::open(&mut disk).unwrap();
            disk.arm(Some(failure));
            assert!(replace(&mut fs, &mut disk, &target).is_err());
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
                    "partial replacement {failure}/{policy}"
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
    println!("LINK_REPLACEMENT: {commits} commit + {replays} replay snapshots");
}
