//! A freed extents-tree node must become zero in the same publication as its map.
use fstool::{
    block::{BlockDevice, MemoryBackend},
    fs::hfs_plus::{FormatOpts, HfsPlus},
};
use hfs_bridge::volume;
use std::{io::Read, io::Write, path::Path};
#[path = "support/fault_disk.rs"]
mod fault;

fn fixture(resource: bool) -> Vec<u8> {
    let mut disk = MemoryBackend::new(2 * 1024 * 1024);
    let mut fs = HfsPlus::format(
        &mut disk,
        &FormatOpts {
            journaled: true,
            ..Default::default()
        },
    )
    .unwrap();
    for index in 0..9 {
        for prefix in ["gap", "keep"] {
            fs.create_file(
                &mut disk,
                &format!("/{prefix}{index}"),
                &mut &[0x42; 4096][..],
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
    let free = u64::from(volume::inspect(&mut disk).unwrap().header.free_blocks) * 4096;
    fs.create_file(
        &mut disk,
        "/fill",
        &mut std::io::repeat(0x64),
        free,
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
        let mut fork = fs
            .open_resource_fork_rw(&mut disk, Path::new("/fragmented"))
            .unwrap();
        fork.write_all(&payload).unwrap();
        fork.sync().unwrap();
    }
    fs.flush(&mut disk).unwrap();
    disk.into_bytes()
}

fn fork_bytes(bytes: &[u8], header_offset: usize) -> Vec<u8> {
    let block = volume::be32(bytes, 1064) as usize;
    let length = volume::be64(bytes, 1024 + header_offset) as usize;
    let mut result = Vec::new();
    for index in 0..8 {
        let off = 1024 + header_offset + 16 + index * 8;
        let start = volume::be32(bytes, off) as usize * block;
        let count = volume::be32(bytes, off + 4) as usize * block;
        result.extend_from_slice(&bytes[start..start + count]);
    }
    result.truncate(length);
    result
}

#[derive(Debug, PartialEq, Eq)]
struct State {
    free: u32,
    files: u32,
    bitmap: Vec<u8>,
    extents: Vec<u8>,
    fragmented: Option<Vec<u8>>,
    keep: Vec<Vec<u8>>,
}
fn observe(bytes: Vec<u8>, resource: bool) -> State {
    let mut disk = MemoryBackend::from_bytes(bytes);
    let fs = HfsPlus::open(&mut disk).unwrap(); // Includes native journal replay.
    let info = volume::inspect(&mut disk).unwrap();
    assert!(matches!(info.journal, volume::Journal::Clean { .. }));
    let fragmented = fs.catalog_record("/fragmented").ok();
    if fragmented.is_some() {
        let mut content = Vec::new();
        if resource {
            fs.open_resource_fork_reader(&mut disk, "/fragmented")
                .unwrap()
                .read_to_end(&mut content)
                .unwrap();
        } else {
            fs.open_file_reader(&mut disk, "/fragmented")
                .unwrap()
                .read_to_end(&mut content)
                .unwrap();
        }
        assert_eq!(content, vec![0x53; 9 * 4096]);
    }
    let keep = (0..9)
        .map(|index| {
            let path = format!("/keep{index}");
            let mut content = Vec::new();
            fs.open_file_reader(&mut disk, &path)
                .unwrap()
                .read_to_end(&mut content)
                .unwrap();
            assert_eq!(content, vec![0x42; 4096]);
            fs.catalog_record(&path).unwrap()
        })
        .collect();
    let mut fill = Vec::new();
    fs.open_file_reader(&mut disk, "/fill")
        .unwrap()
        .read_to_end(&mut fill)
        .unwrap();
    assert!(!fill.is_empty() && fill.iter().all(|byte| *byte == 0x64));
    State {
        free: info.header.free_blocks,
        files: info.header.files,
        bitmap: fork_bytes(disk.as_slice(), 112),
        extents: fork_bytes(disk.as_slice(), 192),
        fragmented,
        keep,
    }
}
fn erase(fs: &mut HfsPlus, disk: &mut dyn BlockDevice) -> fstool::Result<()> {
    fs.remove(disk, "/fragmented")?;
    fs.flush(disk)
}
fn retain(name: &str, bytes: &[u8]) {
    if let Some(dir) = std::env::var_os("HFS_BTREE_ARTIFACT_DIR") {
        let mut f = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(Path::new(&dir).join(name))
            .unwrap();
        f.write_all(bytes).unwrap();
        f.sync_all().unwrap();
    }
}

#[test]
fn freed_extents_nodes_and_their_map_survive_commit_and_replay_interruption_together() {
    let mut commits = 0;
    let mut replays = 0;
    for resource in [false, true] {
        let before = fixture(resource);
        let old = observe(before.clone(), resource);
        let mut complete = fault::Disk::new(&before);
        let journal = match volume::inspect(&mut complete).unwrap().journal {
            volume::Journal::Clean { offset, .. } => offset as usize,
            _ => panic!("journal required"),
        };
        let mut fs = HfsPlus::open(&mut complete).unwrap();
        complete.arm(None);
        erase(&mut fs, &mut complete).unwrap();
        let calls = complete.0.lock().unwrap().calls;
        let after = complete.snapshot(1, journal);
        let new = observe(after.clone(), resource);
        assert!(new.fragmented.is_none());
        assert_eq!(new.free, old.free + 9);
        let ns = volume::be16(&new.extents, 32) as usize;
        assert!(new.extents[ns..].iter().all(|byte| *byte == 0));
        retain(&format!("reclaim-{resource}-before.img"), &before);
        retain(&format!("reclaim-{resource}-after.img"), &after);
        let mut pending = None;
        for failure in 0..calls {
            let mut disk = fault::Disk::new(&before);
            let mut fs = HfsPlus::open(&mut disk).unwrap();
            disk.arm(Some(failure));
            assert!(erase(&mut fs, &mut disk).is_err());
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
                let actual = observe(bytes, resource);
                assert!(
                    actual == old || actual == new,
                    "partial reclaim {resource}/{failure}/{policy}"
                );
                commits += 1;
            }
        }
        let pending = pending.expect("A journal commit must be observable");
        retain(&format!("reclaim-{resource}-pending.img"), &pending);
        let mut complete = fault::Disk::new(&pending);
        HfsPlus::open(&mut complete).unwrap();
        let calls = complete.0.lock().unwrap().calls;
        for failure in 0..calls {
            let mut disk = fault::Disk::new(&pending);
            disk.arm(Some(failure));
            assert!(HfsPlus::open(&mut disk).is_err());
            for policy in 0..6 {
                assert_eq!(observe(disk.snapshot(policy, journal), resource), new);
                replays += 1;
            }
        }
    }
    println!("BTREE_RECLAIM: {commits} commit + {replays} replay snapshots; 2 scenarios");
}
