//! Empty-file conversion must publish target, type and metadata together.
use fstool::{
    block::{BlockDevice, MemoryBackend},
    fs::hfs_plus::{CatalogUpdate, FormatOpts, HfsPlus, PublicationMetadata},
};
use hfs_bridge::volume;
use std::{
    io::{Read, Write},
    path::Path,
};
#[path = "support/fault_disk.rs"]
mod fault;
const TARGET: &str = "../folder/café.txt";
const MARKER: &str = "org.hfsbridge.test.link";

fn fixture(journaled: bool) -> Vec<u8> {
    let mut disk = MemoryBackend::new(2 * 1024 * 1024);
    let mut fs = HfsPlus::format(
        &mut disk,
        &FormatOpts {
            journaled,
            ..Default::default()
        },
    )
    .unwrap();
    fs.create_file(
        &mut disk,
        "/link",
        &mut &b""[..],
        0,
        0o644,
        501,
        20,
        1_700_000_000,
    )
    .unwrap();
    fs.create_file(
        &mut disk,
        "/keep",
        &mut &b"untouched"[..],
        9,
        0o644,
        501,
        20,
        1_700_000_000,
    )
    .unwrap();
    fs.flush(&mut disk).unwrap();
    fs.set_attributes_batch(&mut disk, &[(2, MARKER, Some(b"old"))])
        .unwrap();
    fs.flush(&mut disk).unwrap();
    disk.into_bytes()
}
fn convert(fs: &mut HfsPlus, disk: &mut dyn BlockDevice) -> fstool::Result<()> {
    let cnid = volume::be32(&fs.catalog_record("/link")?, 8);
    fs.convert_empty_file_to_symlink_with_publication(
        disk,
        Path::new("/link"),
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
    target: Option<String>,
    attribute: Option<Vec<u8>>,
    marker: Option<Vec<u8>>,
    free: u32,
}
fn observe(bytes: Vec<u8>) -> State {
    let mut disk = MemoryBackend::from_bytes(bytes);
    let fs = HfsPlus::open(&mut disk).unwrap();
    let body = fs.catalog_record("/link").unwrap();
    let cnid = volume::be32(&body, 8);
    let target = if volume::be16(&body, 42) & 0xf000 == 0xa000 {
        assert_eq!(&body[48..56], b"slnkrhap");
        assert!(body[168..248].iter().all(|b| *b == 0));
        Some(fs.read_symlink_target(&mut disk, cnid).unwrap())
    } else {
        let mut data = Vec::new();
        fs.open_file_reader(&mut disk, "/link")
            .unwrap()
            .read_to_end(&mut data)
            .unwrap();
        assert!(data.is_empty(), "target bytes exposed as an ordinary file");
        None
    };
    let mut keep = Vec::new();
    fs.open_file_reader(&mut disk, "/keep")
        .unwrap()
        .read_to_end(&mut keep)
        .unwrap();
    assert_eq!(keep, b"untouched");
    let attribute = fs
        .inline_attribute(&mut disk, cnid, "com.example.link")
        .unwrap();
    let marker = fs.inline_attribute(&mut disk, 2, MARKER).unwrap();
    State {
        body,
        target,
        attribute,
        marker,
        free: volume::inspect(&mut disk).unwrap().header.free_blocks,
    }
}
#[test]
fn relative_target_type_and_metadata_survive_reopen() {
    for journaled in [false, true] {
        let mut disk = MemoryBackend::from_bytes(fixture(journaled));
        let mut fs = HfsPlus::open(&mut disk).unwrap();
        convert(&mut fs, &mut disk).unwrap();
        let state = observe(disk.into_bytes());
        assert_eq!(state.target.as_deref(), Some(TARGET));
        assert_eq!(state.attribute.as_deref(), Some(&b"new"[..]));
        assert_eq!(state.marker.as_deref(), Some(&b"new"[..]));
        assert_eq!(volume::be16(&state.body, 42), 0xa000 | 0o644);
        assert_eq!(volume::be32(&state.body, 16), 3_800_000_000);
        assert_eq!(volume::be32(&state.body, 20), 3_800_000_001);
    }
}
#[test]
fn unsuitable_targets_and_populated_forks_refuse_before_any_write() {
    for kind in 0..7 {
        let mut source = MemoryBackend::from_bytes(fixture(true));
        let mut fs = HfsPlus::open(&mut source).unwrap();
        if kind == 0 {
            let mut file = fs
                .open_resource_fork_rw(&mut source, Path::new("/link"))
                .unwrap();
            file.write_all(b"resource").unwrap();
            file.sync().unwrap();
        } else if kind == 1 {
            fs.set_data_allocation(&mut source, Path::new("/link"), 4096, false)
                .unwrap();
        }
        let mut disk = fault::Disk::new(&source.into_bytes());
        let mut fs = HfsPlus::open(&mut disk).unwrap();
        disk.arm(None);
        let long = "x".repeat(1025);
        let target = match kind {
            3 => "",
            4 => "bad\0path",
            5 => "/outside",
            6 => &long,
            _ => TARGET,
        };
        let path = if kind == 2 { "/keep" } else { "/link" };
        assert!(
            fs.convert_empty_file_to_symlink_with_publication(
                &mut disk,
                Path::new(path),
                target,
                Default::default()
            )
            .is_err()
        );
        drop(fs);
        assert_eq!(
            disk.0.lock().unwrap().calls,
            0,
            "refusal {kind} wrote or flushed"
        );
    }
}
#[test]
fn interruption_never_exposes_half_converted_link() {
    let before = fixture(true);
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
    let mut snapshots = 0;
    let mut pending = None;
    for failure in 0..calls {
        let mut disk = fault::Disk::new(&before);
        let mut fs = HfsPlus::open(&mut disk).unwrap();
        disk.arm(Some(failure));
        assert!(convert(&mut fs, &mut disk).is_err());
        drop(fs); // Failed mutation must not retry publication on drop.
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
                "partial link at {failure}/{policy}"
            );
            snapshots += 1;
        }
    }
    let pending = pending.expect("journal commit must be observable");
    let mut complete = fault::Disk::new(&pending);
    HfsPlus::open(&mut complete).unwrap();
    let calls = complete.0.lock().unwrap().calls;
    let mut replays = 0;
    for failure in 0..calls {
        let mut disk = fault::Disk::new(&pending);
        disk.arm(Some(failure));
        assert!(HfsPlus::open(&mut disk).is_err());
        for policy in 0..6 {
            assert_eq!(
                observe(disk.snapshot(policy, journal)),
                new,
                "interrupted replay at {failure}/{policy}"
            );
            replays += 1;
        }
    }
    if let Some(dir) = std::env::var_os("HFS_SYMLINK_ARTIFACT_DIR") {
        for (name, bytes) in [
            ("before.img", before),
            ("after.img", complete.snapshot(1, journal)),
            ("pending.img", pending),
        ] {
            let mut file = std::fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(Path::new(&dir).join(name))
                .unwrap();
            file.write_all(&bytes).unwrap();
            file.sync_all().unwrap();
        }
    }
    println!("SYMLINK_PUBLICATION: {snapshots} commit + {replays} replay snapshots");
}
