//! Folder/file record conversion must preserve identity and publish old-or-new.
use fstool::{
    block::{BlockDevice, MemoryBackend},
    fs::hfs_plus::{CatalogUpdate, FormatOpts, HfsPlus, PublicationMetadata},
};
use hfs_bridge::volume;
use std::{io::Read, path::Path};
#[path = "support/fault_disk.rs"]
mod fault;

const TARGET: &str = "../target";
const MARKER: &str = "org.hfsbridge.test.directory-link";

fn fixture(journaled: bool, sensitive: bool) -> Vec<u8> {
    let mut disk = MemoryBackend::new(4 * 1024 * 1024);
    let mut fs = HfsPlus::format(
        &mut disk,
        &FormatOpts {
            journaled,
            ..Default::default()
        },
    )
    .unwrap();
    for name in ["/parent", "/parent/link", "/target"] {
        fs.create_dir(&mut disk, name, 0o750, 501, 20, 1_700_000_000)
            .unwrap();
    }
    fs.create_file(
        &mut disk,
        "/target/keep",
        &mut &b"untouched"[..],
        9,
        0o640,
        501,
        20,
        1_700_000_000,
    )
    .unwrap();
    fs.flush(&mut disk).unwrap();
    let id = volume::be32(&fs.catalog_record("/parent/link").unwrap(), 8);
    fs.set_attributes_batch(
        &mut disk,
        &[
            (2, MARKER, Some(b"old")),
            (id, "com.example.retained", Some(b"retained")),
        ],
    )
    .unwrap();
    fs.flush(&mut disk).unwrap();
    drop(fs);
    let mut bytes = disk.into_bytes();
    if sensitive {
        bytes[1024..1026].copy_from_slice(b"HX");
        bytes[1026..1028].copy_from_slice(&5u16.to_be_bytes());
        let catalog = volume::be32(&bytes, 1312) as usize * 4096;
        bytes[catalog + 51] = 0xbc;
        let alternate = bytes.len() - 1024;
        let header = bytes[1024..1536].to_vec();
        bytes[alternate..alternate + 512].copy_from_slice(&header);
        // Establish HFSX folder-count flags before capturing the old state.
        let mut disk = MemoryBackend::from_bytes(bytes);
        let mut fs = HfsPlus::open(&mut disk).unwrap();
        fs.create_dir(&mut disk, "/case-sensitive", 0o750, 501, 20, 1_700_000_000)
            .unwrap();
        fs.flush(&mut disk).unwrap();
        bytes = disk.into_bytes();
    }
    bytes
}

fn convert(fs: &mut HfsPlus, disk: &mut dyn BlockDevice) -> fstool::Result<()> {
    let cnid = volume::be32(&fs.catalog_record("/parent/link")?, 8);
    fs.convert_empty_directory_to_symlink_with_publication(
        disk,
        Path::new("/parent/link"),
        TARGET,
        PublicationMetadata {
            attributes: &[("com.example.link", Some(b"new"))],
            related: &[(2, MARKER, Some(b"new"))],
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
    parent: Vec<u8>,
    root: Vec<u8>,
    target: Option<String>,
    attribute: Option<Vec<u8>>,
    marker: Option<Vec<u8>>,
    free: u32,
    files: u32,
    folders: u32,
}
fn observe(bytes: Vec<u8>) -> State {
    let mut disk = MemoryBackend::from_bytes(bytes);
    let fs = HfsPlus::open(&mut disk).unwrap();
    let body = fs.catalog_record("/parent/link").unwrap();
    let id = volume::be32(&body, 8);
    assert_eq!(
        fs.catalog_path(id).unwrap(),
        "/parent/link",
        "thread and entry disagree"
    );
    let target = if volume::be16(&body, 0) == 2 {
        assert_eq!(volume::be16(&body, 42), 0xa000 | 0o750);
        assert_eq!(&body[48..56], b"slnkrhap");
        assert!(body[168..248].iter().all(|b| *b == 0));
        Some(fs.read_symlink_target(&mut disk, id).unwrap())
    } else {
        assert_eq!(volume::be16(&body, 0), 1);
        assert_eq!(volume::be32(&body, 4), 0);
        None
    };
    assert_eq!(
        (volume::be32(&body, 32), volume::be32(&body, 36)),
        (501, 20)
    );
    assert_eq!(
        fs.inline_attribute(&mut disk, id, "com.example.retained")
            .unwrap()
            .as_deref(),
        Some(&b"retained"[..])
    );
    let mut keep = Vec::new();
    fs.open_file_reader(&mut disk, "/target/keep")
        .unwrap()
        .read_to_end(&mut keep)
        .unwrap();
    assert_eq!(keep, b"untouched");
    let attribute = fs
        .inline_attribute(&mut disk, id, "com.example.link")
        .unwrap();
    let marker = fs.inline_attribute(&mut disk, 2, MARKER).unwrap();
    let h = volume::inspect(&mut disk).unwrap().header;
    State {
        body,
        parent: fs.catalog_record("/parent").unwrap(),
        root: fs.catalog_record_cnid(2).unwrap(),
        target,
        attribute,
        marker,
        free: h.free_blocks,
        files: h.files,
        folders: h.folders,
    }
}

#[test]
fn directory_identity_thread_counts_and_metadata_survive_conversion() {
    for journaled in [false, true] {
        for sensitive in [false, true] {
            let before = fixture(journaled, sensitive);
            let old = observe(before.clone());
            let mut disk = MemoryBackend::from_bytes(before);
            let mut fs = HfsPlus::open(&mut disk).unwrap();
            convert(&mut fs, &mut disk).unwrap();
            let after = disk.into_bytes();
            let new = observe(after.clone());
            assert_eq!(new.target.as_deref(), Some(TARGET));
            assert_eq!(new.attribute.as_deref(), Some(&b"new"[..]));
            assert_eq!(new.marker.as_deref(), Some(&b"new"[..]));
            assert_eq!(&new.body[8..16], &old.body[8..16]); // CNID and creation date.
            assert_eq!(new.files, old.files + 1);
            assert_eq!(new.folders + 1, old.folders);
            assert_eq!(volume::be32(&new.parent, 4), volume::be32(&old.parent, 4));
            if sensitive {
                assert_eq!(
                    volume::be32(&new.parent, 84) + 1,
                    volume::be32(&old.parent, 84)
                );
            }
            if let Some(dir) = std::env::var_os("HFS_DIRECTORY_LINK_ARTIFACT_DIR") {
                use std::io::Write;
                let path =
                    Path::new(&dir).join(format!("directory-link-j{journaled}-x{sensitive}.img"));
                let mut file = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(path)
                    .unwrap();
                file.write_all(&after).unwrap();
                file.sync_all().unwrap();
            }
        }
    }
}

#[test]
fn populated_locked_special_metadata_and_invalid_requests_refuse_without_writes() {
    for scenario in 0..9 {
        let mut disk = MemoryBackend::from_bytes(fixture(true, false));
        let mut fs = HfsPlus::open(&mut disk).unwrap();
        let id = volume::be32(&fs.catalog_record("/parent/link").unwrap(), 8);
        match scenario {
            0 => {
                fs.create_dir(&mut disk, "/parent/link/child", 0o700, 501, 20, 0)
                    .unwrap();
            }
            1 => {
                fs.set_catalog_windows_info(id, [None; 4], Some(0x11))
                    .unwrap();
            }
            2 => {
                let mut finder = [0; 32];
                finder[0] = 1;
                fs.set_finder_info(id, &finder, None).unwrap();
            }
            _ => {}
        }
        fs.flush(&mut disk).unwrap();
        let before = disk.into_bytes();
        let mut disk = fault::Disk::new(&before);
        let mut fs = HfsPlus::open(&mut disk).unwrap();
        disk.arm(None);
        let metadata = PublicationMetadata {
            related: if scenario == 7 {
                &[(2, MARKER, Some(b"one")), (2, MARKER, Some(b"two"))]
            } else {
                &[]
            },
            ..Default::default()
        };
        let path = match scenario {
            3 => "/",
            4 => "/target/keep",
            _ => "/parent/link",
        };
        let long = "x".repeat(1025);
        let target = match scenario {
            5 => "/absolute",
            6 => "",
            8 => &long,
            _ => TARGET,
        };
        assert!(
            fs.convert_empty_directory_to_symlink_with_publication(
                &mut disk,
                Path::new(path),
                target,
                metadata
            )
            .is_err(),
            "scenario {scenario}"
        );
        assert_eq!(
            disk.0.lock().unwrap().calls,
            0,
            "scenario {scenario} wrote or synced"
        );
        assert_eq!(disk.snapshot(1, 0), before);
    }
}

#[test]
fn interrupted_directory_conversion_recovers_complete_catalog_and_counts() {
    let mut commits = 0;
    let mut replays = 0;
    for sensitive in [false, true] {
        let before = fixture(true, sensitive);
        let old = observe(before.clone());
        let mut complete = fault::Disk::new(&before);
        let journal = match volume::inspect(&mut complete).unwrap().journal {
            volume::Journal::Clean { offset, .. } => offset as usize,
            _ => panic!("journal required"),
        };
        let mut fs = HfsPlus::open(&mut complete).unwrap();
        complete.arm(None);
        convert(&mut fs, &mut complete).unwrap();
        let calls = complete.0.lock().unwrap().calls;
        let new = observe(complete.snapshot(1, journal));
        let mut pending = None;
        for failure in 0..calls {
            let mut disk = fault::Disk::new(&before);
            let mut fs = HfsPlus::open(&mut disk).unwrap();
            disk.arm(Some(failure));
            assert!(convert(&mut fs, &mut disk).is_err());
            assert!(
                fs.flush(&mut disk).is_err(),
                "failed conversion must not publish on retry"
            );
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
                    "partial directory conversion {sensitive}/{failure}/{policy}"
                );
                commits += 1;
            }
        }
        let pending = pending.expect("committed journal observable");
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
    println!("DIRECTORY_LINK_PUBLICATION: {commits} commit + {replays} replay checkpoints");
}

#[test]
fn directory_record_growth_preserves_catalog_threads_across_leaf_splits() {
    let mut disk = MemoryBackend::new(8 * 1024 * 1024);
    let mut fs = HfsPlus::format(
        &mut disk,
        &FormatOpts {
            journaled: true,
            catalog_nodes: 4,
            node_size: 4096,
            ..Default::default()
        },
    )
    .unwrap();
    let paths = (0..96)
        // Short keys make the 88 -> 248 byte body expansion dominate the
        // record size, exceeding the slack left by incremental insertion.
        .map(|i| format!("/entry-{i:03}"))
        .collect::<Vec<_>>();
    for path in &paths {
        fs.create_dir(&mut disk, path, 0o750, 501, 20, 1_700_000_000)
            .unwrap();
    }
    fs.flush(&mut disk).unwrap();
    let before = disk.into_bytes();
    let used_nodes = |bytes: &[u8]| {
        let start = volume::be32(bytes, 1312) as usize * volume::be32(bytes, 1064) as usize;
        volume::be32(bytes, start + 36) - volume::be32(bytes, start + 40)
    };
    let old_nodes = used_nodes(&before);
    let mut disk = MemoryBackend::from_bytes(before);
    let mut fs = HfsPlus::open(&mut disk).unwrap();
    let ids = paths
        .iter()
        .map(|path| volume::be32(&fs.catalog_record(path).unwrap(), 8))
        .collect::<Vec<_>>();
    for path in &paths {
        fs.convert_empty_directory_to_symlink_with_publication(
            &mut disk,
            Path::new(path),
            "missing",
            Default::default(),
        )
        .unwrap();
    }
    let after = disk.into_bytes();
    let new_nodes = used_nodes(&after);
    println!("DIRECTORY_LINK_CATALOG_NODES: {old_nodes} -> {new_nodes}");
    let mut disk = MemoryBackend::from_bytes(after);
    let fs = HfsPlus::open(&mut disk).unwrap();
    for (path, id) in paths.iter().zip(ids) {
        assert_eq!(volume::be32(&fs.catalog_record(path).unwrap(), 8), id);
        assert_eq!(fs.catalog_path(id).unwrap(), *path);
        assert_eq!(fs.read_symlink_target(&mut disk, id).unwrap(), "missing");
    }
    let header = volume::inspect(&mut disk).unwrap().header;
    assert_eq!(header.folders, 0);
    assert_eq!(header.files, 98); // 96 links and the two journal files.
    assert!(
        new_nodes > old_nodes,
        "test must exercise additional catalog nodes"
    );
    println!("DIRECTORY_LINK_CATALOG_SPLITS: 96 conversions with retained CNIDs and threads");
}
