//! Independent wire-layout audit of localized catalog changes.
use fstool::block::{BlockDevice, MemoryBackend};
use fstool::fs::hfs_plus::{FormatOpts, HfsPlus};
use hfs_bridge::volume;
#[path = "support/catalog_wire.rs"]
mod catalog_wire;
use catalog_wire::{audit, fork};
use std::io::{self, Read, Seek, SeekFrom, Write};

struct Disk {
    memory: MemoryBackend,
    writes: Vec<(u64, usize)>,
}
impl Read for Disk {
    fn read(&mut self, data: &mut [u8]) -> io::Result<usize> {
        self.memory.read(data)
    }
}
impl Seek for Disk {
    fn seek(&mut self, at: SeekFrom) -> io::Result<u64> {
        self.memory.seek(at)
    }
}
impl Write for Disk {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        let offset = self.memory.stream_position()?;
        let count = self.memory.write(data)?;
        self.writes.push((offset, count));
        Ok(count)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.memory.flush()
    }
}
impl BlockDevice for Disk {
    fn block_size(&self) -> u32 {
        512
    }
    fn total_size(&self) -> u64 {
        self.memory.total_size()
    }
    fn sync(&mut self) -> fstool::Result<()> {
        Ok(self.flush()?)
    }
}
fn u16be(bytes: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes(bytes[offset..offset + 2].try_into().unwrap())
}
fn put32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
}
fn headers(bytes: &mut [u8]) {
    let end = bytes.len() - 1024;
    let header = bytes[1024..1536].to_vec();
    bytes[end..end + 512].copy_from_slice(&header);
}
fn fixture(journaled: bool, size: u32, capacity: u32, siblings: usize) -> Disk {
    let mut memory = MemoryBackend::new(64 * 1024 * 1024);
    HfsPlus::format(
        &mut memory,
        &FormatOpts {
            journaled,
            node_size: size,
            catalog_nodes: capacity,
            ..Default::default()
        },
    )
    .unwrap();
    let mut bytes = memory.into_bytes();
    let attributes = volume::be32(&bytes, 1028);
    put32(&mut bytes, 1028, attributes & !(1 << 13));
    headers(&mut bytes);
    let mut memory = MemoryBackend::from_bytes(bytes);
    let mut fs = HfsPlus::open(&mut memory).unwrap();
    for index in 0..siblings {
        fs.create_dir(&mut memory, &format!("/sibling-{index:05}"), 0o755, 0, 0, 0)
            .unwrap();
    }
    fs.flush(&mut memory).unwrap();
    let mut bytes = memory.into_bytes();
    put32(&mut bytes, 1028, attributes);
    headers(&mut bytes);
    Disk {
        memory: MemoryBackend::from_bytes(bytes),
        writes: Vec::new(),
    }
}

fn retain(disk: &Disk, name: &str) {
    if let Some(directory) = std::env::var_os("HFS_CRASH_ARTIFACT_DIR") {
        let mut file = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(std::path::Path::new(&directory).join(name))
            .unwrap();
        file.write_all(disk.memory.as_slice()).unwrap();
        file.sync_all().unwrap();
    }
}

#[test]
fn localized_create_rename_delete_preserve_unrelated_large_catalog_nodes() {
    for journaled in [false, true] {
        let label = if journaled { "journaled" } else { "plain" };
        let mut disk = fixture(journaled, 8192, 256, 2000);
        let original = audit(disk.memory.as_slice());
        assert!(original.leaves > 50);
        let mut fs = HfsPlus::open(&mut disk).unwrap();
        for operation in 0..3 {
            let before = fork(disk.memory.as_slice());
            disk.writes.clear();
            match operation {
                0 => {
                    fs.create_dir(&mut disk, "/sibling-01000-new", 0o755, 0, 0, 0)
                        .unwrap();
                }
                1 => fs
                    .rename(&mut disk, "/sibling-01000-new", "/sibling-01999-renamed")
                    .unwrap(),
                _ => fs.remove(&mut disk, "/sibling-01999-renamed").unwrap(),
            }
            fs.flush(&mut disk).unwrap();
            let after = fork(disk.memory.as_slice());
            let changed = before
                .as_chunks::<8192>()
                .0
                .iter()
                .zip(after.as_chunks::<8192>().0.iter())
                .filter(|(a, b)| a != b)
                .count();
            let written: usize = disk.writes.iter().map(|(_, count)| count).sum();
            assert!(
                changed <= 12,
                "operation {operation} changed {changed} nodes"
            );
            assert!(
                written < 192 * 1024,
                "operation {operation} wrote {written} bytes"
            );
            audit(disk.memory.as_slice());
            println!(
                "CATALOG_EFFICIENCY: {label}; operation={operation}; siblings=2000; changed_nodes={changed}; total_written={written}"
            );
            retain(&disk, &format!("catalog-{operation}-{label}.img"));
        }
        assert_eq!(audit(disk.memory.as_slice()).total, original.total);
    }
}

#[test]
fn repeated_splits_growth_merges_and_root_collapse_reuse_free_nodes() {
    for journaled in [false, true] {
        let label = if journaled { "journaled" } else { "plain" };
        let mut disk = fixture(journaled, 2048, 4, 0);
        let first = audit(disk.memory.as_slice());
        let mut fs = HfsPlus::open(&mut disk).unwrap();
        let names: Vec<_> = (0..180)
            .map(|i| format!("/entry-{i:04}-{}", "x".repeat(90)))
            .collect();
        for name in &names {
            fs.create_dir(&mut disk, name, 0o755, 0, 0, 0).unwrap();
            fs.flush(&mut disk).unwrap();
            audit(disk.memory.as_slice());
        }
        let expanded = audit(disk.memory.as_slice());
        assert!(expanded.depth >= 3 && expanded.total > first.total);
        retain(&disk, &format!("catalog-deep-{label}.img"));
        // Alternating low/high deletion exercises both rebalance directions.
        for index in (0..names.len() / 2).flat_map(|i| [i, names.len() - 1 - i]) {
            fs.remove(&mut disk, &names[index]).unwrap();
            fs.flush(&mut disk).unwrap();
            audit(disk.memory.as_slice());
        }
        let collapsed = audit(disk.memory.as_slice());
        assert_eq!(collapsed.depth, 1);
        assert_eq!(collapsed.leaves, 1);
        assert_eq!(collapsed.total, expanded.total);
        assert_eq!(collapsed.free, collapsed.total - 2);
        retain(&disk, &format!("catalog-collapsed-{label}.img"));
        for name in &names[..80] {
            fs.create_dir(&mut disk, name, 0o755, 0, 0, 0).unwrap();
            fs.flush(&mut disk).unwrap();
        }
        let reused = audit(disk.memory.as_slice());
        assert_eq!(reused.total, expanded.total);
        assert!(reused.free < collapsed.free);
        retain(&disk, &format!("catalog-reused-{label}.img"));
    }
}

#[test]
fn invalid_node_maps_and_index_boundaries_refuse_before_publication() {
    let original = fixture(true, 8192, 256, 2000).memory.into_bytes();
    let start = volume::be32(&original, 1312) as usize * 4096;
    let root = volume::be32(&original, start + 16) as usize;
    for fault in 0..6 {
        let mut bytes = original.clone();
        match fault {
            0 => bytes[start + 248] &= 0x7f,
            1 => put32(&mut bytes, start + 40, 0),
            2 => put32(&mut bytes, start, root as u32),
            3 => bytes[start + root * 8192 + 14 + 8] ^= 1,
            4 => put32(&mut bytes, start + root * 8192, 1),
            _ => bytes[start + 8192 - 8..start + 8192 - 6].copy_from_slice(&8182u16.to_be_bytes()),
        }
        let mut disk = Disk {
            memory: MemoryBackend::from_bytes(bytes),
            writes: Vec::new(),
        };
        let mut fs = HfsPlus::open(&mut disk).unwrap();
        fs.create_dir(&mut disk, "/sibling-01000-new", 0o755, 0, 0, 0)
            .unwrap();
        assert!(fs.flush(&mut disk).is_err(), "fault {fault} accepted");
        assert!(disk.writes.is_empty(), "fault {fault} wrote before refusal");
        assert!(fs.flush(&mut disk).is_err());
    }
}

// Independently encode a legal sparse tree that fills the header's 14,336
// node-map bits. One further split must create a continuation map node.
fn sparse_full_catalog() -> Disk {
    let mut disk = fixture(true, 2048, 14_336, 7200);
    let old = fork(disk.memory.as_slice());
    let mut all = Vec::new();
    let mut id = volume::be32(&old, 24);
    while id != 0 {
        let node = &old[id as usize * 2048..(id as usize + 1) * 2048];
        all.extend(
            catalog_wire::records(node)
                .into_iter()
                .map(|record| record.to_vec()),
        );
        id = volume::be32(node, 0);
    }
    fn encode(records: &[Vec<u8>], height: u8) -> Vec<u8> {
        let mut node = vec![0; 2048];
        node[8] = if height == 1 { 255 } else { 0 };
        node[9] = height;
        node[10..12].copy_from_slice(&(records.len() as u16).to_be_bytes());
        let mut cursor = 14;
        for (index, record) in records.iter().enumerate() {
            node[2046 - index * 2..2048 - index * 2]
                .copy_from_slice(&(cursor as u16).to_be_bytes());
            node[cursor..cursor + record.len()].copy_from_slice(record);
            cursor += record.len();
        }
        node[2046 - records.len() * 2..2048 - records.len() * 2]
            .copy_from_slice(&(cursor as u16).to_be_bytes());
        assert!(cursor <= 2048 - (records.len() + 1) * 2);
        node
    }
    let leaf_count = 13_886;
    let paired = all.len() - leaf_count;
    assert!(paired * 2 <= all.len());
    let mut groups: Vec<Vec<Vec<u8>>> = all[..paired * 2]
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| pair.to_vec())
        .collect();
    groups.extend(all[paired * 2..].iter().map(|record| vec![record.clone()]));
    let mut built = vec![old[..2048].to_vec()];
    let mut height = 1;
    loop {
        let first_id = built.len() as u32;
        let mut pointers = Vec::new();
        for (index, records) in groups.iter().enumerate() {
            let id = first_id + index as u32;
            let mut node = encode(records, height);
            put32(&mut node, 4, if index == 0 { 0 } else { id - 1 });
            put32(
                &mut node,
                0,
                if index + 1 == groups.len() { 0 } else { id + 1 },
            );
            let key_len = u16be(&records[0], 0) as usize + 2;
            let mut pointer = records[0][..key_len].to_vec();
            pointer.extend_from_slice(&id.to_be_bytes());
            pointers.push(pointer);
            built.push(node);
        }
        if pointers.len() == 1 {
            break;
        }
        groups = pointers.chunks(32).map(|chunk| chunk.to_vec()).collect();
        if groups.last().unwrap().len() == 1 {
            let last = groups.len() - 1;
            let record = groups[last - 1].pop().unwrap();
            groups[last].insert(0, record);
        }
        height += 1;
    }
    assert_eq!(built.len(), 14_336);
    built[0][14..16].copy_from_slice(&(height as u16).to_be_bytes());
    put32(&mut built[0], 16, 14_335);
    put32(&mut built[0], 20, all.len() as u32);
    put32(&mut built[0], 24, 1);
    put32(&mut built[0], 28, leaf_count as u32);
    put32(&mut built[0], 40, 0);
    built[0][248..2040].fill(255);
    let mut bytes = disk.memory.into_bytes();
    let start = volume::be32(&bytes, 1312) as usize * 4096;
    for (index, node) in built.iter().enumerate() {
        bytes[start + index * 2048..start + (index + 1) * 2048].copy_from_slice(node);
    }
    disk.memory = MemoryBackend::from_bytes(bytes);
    assert_eq!(audit(disk.memory.as_slice()).free, 0);
    disk
}

#[test]
fn full_header_map_grows_into_a_continuation_and_reopens_for_later_changes() {
    let mut disk = sparse_full_catalog();
    retain(&disk, "catalog-full-header-map.img");
    let mut fs = HfsPlus::open(&mut disk).unwrap();
    let names: Vec<_> = (0..8)
        .map(|i| format!("/zzzz-{i:04}-{}", "x".repeat(235)))
        .collect();
    for name in &names {
        fs.create_dir(&mut disk, name, 0o755, 0, 0, 0).unwrap();
    }
    fs.flush(&mut disk).unwrap();
    let expanded = audit(disk.memory.as_slice());
    assert!(expanded.total > 14_336);
    assert_eq!(volume::be32(&fork(disk.memory.as_slice()), 0), 14_336);
    retain(&disk, "catalog-map-continuation.img");
    drop(fs);
    let mut fs = HfsPlus::open(&mut disk).unwrap();
    fs.rename(&mut disk, &names[0], "/zzzz-renamed").unwrap();
    fs.remove(&mut disk, &names[1]).unwrap();
    fs.flush(&mut disk).unwrap();
    audit(disk.memory.as_slice());
    retain(&disk, "catalog-map-reopened.img");
}
