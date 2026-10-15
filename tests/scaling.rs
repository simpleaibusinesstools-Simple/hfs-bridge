use fstool::block::{BlockDevice, MemoryBackend};
use fstool::fs::{
    Filesystem, OpenFlags,
    hfs_plus::{FormatOpts, HfsPlus},
};
use hfs_bridge::volume;
use std::io::{self, Read, Seek, SeekFrom, Write};

const FILE_SIZE: usize = 8 * 1024 * 1024;
const BS: usize = 4096;

struct CountDisk {
    memory: MemoryBackend,
    writes: Vec<(u64, usize)>,
}
impl Read for CountDisk {
    fn read(&mut self, data: &mut [u8]) -> io::Result<usize> {
        self.memory.read(data)
    }
}
impl Seek for CountDisk {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        self.memory.seek(position)
    }
}
impl Write for CountDisk {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        let offset = self.memory.stream_position()?;
        let written = self.memory.write(data)?;
        self.writes.push((offset, written));
        Ok(written)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.memory.flush()
    }
}
impl BlockDevice for CountDisk {
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

fn data() -> Vec<u8> {
    (0..FILE_SIZE)
        .map(|i| ((i * 31 + i / 251) % 256) as u8)
        .collect()
}

fn fixture(journaled: bool, siblings: usize) -> CountDisk {
    let mut memory = MemoryBackend::new(64 * 1024 * 1024);
    HfsPlus::format(
        &mut memory,
        &FormatOpts {
            journaled,
            catalog_nodes: 256,
            ..Default::default()
        },
    )
    .unwrap();
    // Independently construct a large synthetic catalog through the plain
    // builder, then restore journaling. The production CLI has no such switch.
    let mut bytes = memory.as_slice().to_vec();
    let attributes = volume::be32(&bytes, 1028);
    for header in [1024, bytes.len() - 1024] {
        bytes[header + 4..header + 8].copy_from_slice(&(attributes & !(1 << 13)).to_be_bytes());
    }
    memory = MemoryBackend::from_bytes(bytes);
    let mut fs = HfsPlus::open(&mut memory).unwrap();
    let payload = data();
    fs.create_file(
        &mut memory,
        "/file.bin",
        &mut &payload[..],
        payload.len() as u64,
        0o640,
        501,
        20,
        1_700_000_000,
    )
    .unwrap();
    for index in 0..siblings {
        fs.create_dir(&mut memory, &format!("/sibling-{index:05}"), 0o755, 0, 0, 0)
            .unwrap();
    }
    fs.flush(&mut memory).unwrap();
    let mut bytes = memory.as_slice().to_vec();
    for header in [1024, bytes.len() - 1024] {
        bytes[header + 4..header + 8].copy_from_slice(&attributes.to_be_bytes());
    }
    CountDisk {
        memory: MemoryBackend::from_bytes(bytes),
        writes: Vec::new(),
    }
}

fn read(fs: &mut HfsPlus, disk: &mut CountDisk) -> Vec<u8> {
    let mut bytes = Vec::new();
    fs.open_file_reader(disk, "/file.bin")
        .unwrap()
        .read_to_end(&mut bytes)
        .unwrap();
    bytes
}

// Decode wire descriptors independently of the handle's run manipulation.
fn blocks(body: &[u8]) -> Vec<u32> {
    let mut blocks = Vec::new();
    for index in 0..8 {
        let start = volume::be32(body, 104 + index * 8);
        let count = volume::be32(body, 108 + index * 8);
        blocks.extend(start..start + count);
    }
    assert_eq!(blocks.len(), volume::be32(body, 100) as usize);
    blocks
}

fn save(disk: &CountDisk, name: &str) {
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
fn tiny_cross_block_edit_scales_with_touched_blocks_in_a_large_catalog() {
    for journaled in [false, true] {
        let label = if journaled { "journaled" } else { "plain" };
        let mut disk = fixture(journaled, 2000);
        let before = disk.memory.as_slice().to_vec();
        let mut fs = HfsPlus::open(&mut disk).unwrap();
        let original = fs.catalog_record("/file.bin").unwrap();
        let old_blocks = blocks(&original);
        let cat_start = volume::be32(&before, 1024 + 272 + 16) as usize * BS;
        let cat_size = volume::be64(&before, 1024 + 272) as usize;
        disk.writes.clear();
        {
            let mut file = fs
                .open_file_rw(
                    &mut disk,
                    std::path::Path::new("/file.bin"),
                    OpenFlags::default(),
                    None,
                )
                .unwrap();
            file.seek(SeekFrom::Start(4095)).unwrap();
            file.write_all(b"XY").unwrap();
            file.sync().unwrap();
        }
        let written: usize = disk.writes.iter().map(|(_, count)| count).sum();
        let cat_written: usize = disk
            .writes
            .iter()
            .filter(|(offset, _)| {
                (*offset as usize) >= cat_start && (*offset as usize) < cat_start + cat_size
            })
            .map(|(_, count)| count)
            .sum();
        let mut fs = HfsPlus::open(&mut disk).unwrap();
        let after = fs.catalog_record("/file.bin").unwrap();
        let new_blocks = blocks(&after);
        let changed: Vec<_> = old_blocks
            .iter()
            .zip(&new_blocks)
            .enumerate()
            .filter(|(_, (old, new))| old != new)
            .map(|(index, _)| index)
            .collect();
        assert_eq!(changed, [0, 1]);
        assert_eq!(&after[..88], &original[..88]);
        assert_eq!(&after[168..], &original[168..]);
        let payload_written: usize = disk
            .writes
            .iter()
            .filter(|(offset, _)| {
                let block = (*offset as usize / BS) as u32;
                new_blocks[..2].contains(&block)
            })
            .map(|(_, count)| count)
            .sum();
        assert_eq!(payload_written, 8194);
        assert!(
            written < 64 * 1024,
            "unexpected write amplification: {written}"
        );
        assert!(
            cat_written <= if journaled { 1024 } else { 8192 },
            "catalog rewritten: {cat_written}"
        );
        for block in &old_blocks {
            let start = *block as usize * BS;
            assert!(disk.memory.as_slice()[start..start + BS] == before[start..start + BS]);
        }
        let changed_nodes = before[cat_start..cat_start + cat_size]
            .as_chunks::<8192>()
            .0
            .iter()
            .zip(
                disk.memory.as_slice()[cat_start..cat_start + cat_size]
                    .as_chunks::<8192>()
                    .0
                    .iter(),
            )
            .filter(|(old, new)| old != new)
            .count();
        assert_eq!(changed_nodes, 1);
        assert!(
            before[cat_start..cat_start + 8192]
                == disk.memory.as_slice()[cat_start..cat_start + 8192]
        );
        let mut expected = data();
        expected[4095..4097].copy_from_slice(b"XY");
        assert!(read(&mut fs, &mut disk) == expected);
        assert_eq!(
            fs.list(&mut disk, std::path::Path::new("/")).unwrap().len(),
            2001 + if journaled { 2 } else { 0 }
        );
        println!(
            "WRITE_EFFICIENCY: {label}; file_bytes={FILE_SIZE}; siblings=2000; replaced_blocks=2; payload_written={payload_written}; catalog_written={cat_written}; total_written={written}"
        );
        save(&disk, &format!("efficient-patch-{label}.img"));
    }
}

#[test]
fn one_free_block_is_enough_for_a_small_edit_of_a_large_file() {
    for journaled in [false, true] {
        let mut disk = fixture(journaled, 0);
        let mut fs = HfsPlus::open(&mut disk).unwrap();
        let free = volume::inspect(&mut disk).unwrap().header.free_blocks;
        fs.create_file(
            &mut disk,
            "/fill.bin",
            &mut std::io::repeat(0),
            u64::from(free - 1) * BS as u64,
            0o644,
            0,
            0,
            0,
        )
        .unwrap();
        fs.flush(&mut disk).unwrap();
        assert_eq!(volume::inspect(&mut disk).unwrap().header.free_blocks, 1);
        let mut fs = HfsPlus::open(&mut disk).unwrap();
        let original = fs.catalog_record("/file.bin").unwrap();
        {
            let mut file = fs
                .open_file_rw(
                    &mut disk,
                    std::path::Path::new("/file.bin"),
                    OpenFlags::default(),
                    None,
                )
                .unwrap();
            file.seek(SeekFrom::Start(123)).unwrap();
            file.write_all(b"!").unwrap();
            file.sync().unwrap();
        }
        let mut fs = HfsPlus::open(&mut disk).unwrap();
        let new = blocks(&fs.catalog_record("/file.bin").unwrap());
        assert_eq!(
            blocks(&original)
                .iter()
                .zip(&new)
                .filter(|(a, b)| a != b)
                .count(),
            1
        );
        assert_eq!(volume::inspect(&mut disk).unwrap().header.free_blocks, 1);
        let mut expected = data();
        expected[123] = b'!';
        assert!(read(&mut fs, &mut disk) == expected);
        disk.writes.clear();
        {
            let mut file = fs
                .open_file_rw(
                    &mut disk,
                    std::path::Path::new("/file.bin"),
                    OpenFlags::default(),
                    None,
                )
                .unwrap();
            assert!(file.set_len(FILE_SIZE as u64 + 2 * BS as u64).is_err());
            assert!(file.sync().is_err());
        }
        assert!(disk.writes.is_empty());
        let mut fs = HfsPlus::open(&mut disk).unwrap();
        assert!(read(&mut fs, &mut disk) == expected);
        save(
            &disk,
            &format!(
                "near-full-edit-{}.img",
                if journaled { "journaled" } else { "plain" }
            ),
        );
    }
}

#[test]
fn repeated_writes_in_one_block_copy_once_and_each_sync_establishes_a_new_baseline() {
    let mut disk = fixture(true, 0);
    let mut fs = HfsPlus::open(&mut disk).unwrap();
    let original = blocks(&fs.catalog_record("/file.bin").unwrap());
    let free = volume::inspect(&mut disk).unwrap().header.free_blocks;
    let mut expected = data();
    for round in 0..3 {
        {
            let mut file = fs
                .open_file_rw(
                    &mut disk,
                    std::path::Path::new("/file.bin"),
                    OpenFlags::default(),
                    None,
                )
                .unwrap();
            for position in [200, 800, 2000] {
                file.seek(SeekFrom::Start(position as u64)).unwrap();
                file.write_all(&[round + 40]).unwrap();
                expected[position] = round + 40;
            }
            file.sync().unwrap();
        }
        let current = blocks(&fs.catalog_record("/file.bin").unwrap());
        assert_eq!(&current[1..], &original[1..]);
        assert_eq!(volume::inspect(&mut disk).unwrap().header.free_blocks, free);
        assert!(read(&mut fs, &mut disk) == expected);
    }
    let mut reopened = HfsPlus::open(&mut disk).unwrap();
    assert!(read(&mut reopened, &mut disk) == expected);
}

#[test]
fn changed_catalog_node_layout_is_refused_before_journal_publication() {
    let mut disk = fixture(true, 0);
    let before = disk.memory.as_slice().to_vec();
    let cat = volume::be32(&before, 1024 + 272 + 16) as usize * BS;
    let first = volume::be32(&before, cat + 14 + 10) as usize;
    let marker = cat + first * 8192 + 8;
    let mut fs = HfsPlus::open(&mut disk).unwrap();
    disk.memory.seek(SeekFrom::Start(marker as u64)).unwrap();
    disk.memory.write_all(&[0]).unwrap();
    {
        let mut file = fs
            .open_file_rw(
                &mut disk,
                std::path::Path::new("/file.bin"),
                OpenFlags::default(),
                None,
            )
            .unwrap();
        file.seek(SeekFrom::Start(200)).unwrap();
        file.write_all(b"x").unwrap();
        let error = file.sync().unwrap_err().to_string();
        assert!(error.contains("stale catalog record position"), "{error}");
        assert!(file.sync().is_err());
    }
    let journal_info = volume::be32(&before, 1036) as usize * BS;
    let journal = volume::be64(&before, journal_info + 36) as usize;
    assert!(before[journal..journal + 512] == disk.memory.as_slice()[journal..journal + 512]);
    assert!(before[1024..1536] == disk.memory.as_slice()[1024..1536]);
    disk.memory.seek(SeekFrom::Start(marker as u64)).unwrap();
    disk.memory.write_all(&[before[marker]]).unwrap();
    let mut reopened = HfsPlus::open(&mut disk).unwrap();
    assert!(read(&mut reopened, &mut disk) == data());
}
