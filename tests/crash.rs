//! Model-based fault tests, deliberately independent of upstream CrashInject.
//! A successful sync persists all bytes. Between syncs, six chosen sector
//! persistence policies simulate lost, partial, or reordered cache writes.
//! This assumes atomic 512-byte sectors, not arbitrary hardware torn writes.
use fstool::block::BlockDevice;
use fstool::fs::{
    Filesystem,
    hfs_plus::{FormatOpts, HfsPlus},
};
use hfs_bridge::volume;
use std::io::{self, Cursor, Read, Seek, SeekFrom, Write};
use std::time::{SystemTime, UNIX_EPOCH};

#[path = "support/catalog_wire.rs"]
mod catalog_wire;

#[path = "support/journal_geometry.rs"]
mod journal_geometry;

#[test]
fn four_k_journal_create_and_mkdir_crash_preserve_header_neighbors() {
    let mut checkpoints = 0;
    for logical_sector in [512, 4096] {
        for little in [false, true] {
            for wrap in [false, true] {
                for operation in [Change::Mkdir, Change::Create] {
                    let mut bytes = baseline(little, false);
                    journal_geometry::convert_empty(&mut bytes, 4096, little, wrap);
                    journal_geometry::seed_header_neighbors(&mut bytes);
                    let neighbors = journal_geometry::header_neighbors(&bytes);
                    let j = journal_offset(&bytes);
                    let mut full = Disk::new(&bytes, None);
                    full.logical_sector = logical_sector;
                    change(&mut full, operation).unwrap();
                    verify_committed(&mut full, operation).unwrap();
                    assert_eq!(journal_geometry::header_neighbors(&full.durable), neighbors);
                    for stop in 0..full.trace.len() {
                        let mut interrupted = Disk::new(&bytes, Some(stop));
                        interrupted.logical_sector = logical_sector;
                        assert!(change(&mut interrupted, operation).is_err());
                        for (policy, name) in POLICIES.iter().enumerate() {
                            let snapshot = interrupted.snapshot(policy, j);
                            let dirty = snapshot[j + 8..j + 16] != snapshot[j + 16..j + 24];
                            let mut recovered = Disk::new(&snapshot, None);
                            recovered.logical_sector = logical_sector;
                            verify(&mut recovered, operation).unwrap_or_else(|error| {
                            panic!(
                                "{operation:?} device={logical_sector} LE={little} wrap={wrap} step={stop} {name}: {error}"
                            )
                        });
                            if dirty {
                                verify_committed(&mut recovered, operation).unwrap();
                            }
                            assert_eq!(
                                journal_geometry::header_neighbors(&recovered.durable),
                                neighbors
                            );
                            checkpoints += 1;
                        }
                    }
                }
            }
        }
    }
    println!("JOURNAL_4K: {checkpoints} interruption checkpoints passed; 16 scenarios");
}

#[test]
fn four_k_header_sector_read_failure_cannot_publish_metadata_or_zero_neighbors() {
    let mut bytes = baseline(false, false);
    journal_geometry::convert_empty(&mut bytes, 4096, false, false);
    journal_geometry::seed_header_neighbors(&mut bytes);
    for target in [0, SIZE as u64 - 4096] {
        let mut disk = Disk::new(&bytes, None);
        disk.logical_sector = 4096;
        let mut fs = HfsPlus::open(&mut disk).unwrap();
        fs.create_dir(&mut disk, "/Transfer/New", 0o755, 0, 0, 0)
            .unwrap();
        disk.trace.clear();
        disk.fail_header_read = Some(target);
        assert!(
            fs.flush(&mut disk)
                .unwrap_err()
                .to_string()
                .contains("sector read failure")
        );
        assert!(
            disk.trace.is_empty(),
            "metadata was published despite a failed sector read"
        );
        assert_eq!(disk.visible.get_ref(), &bytes);
    }
}

const SIZE: usize = 32 * 1024 * 1024;
const HELLO: &[u8] = b"Existing data must survive every interrupted transaction.\n";
const VICTIM: &[u8] = b"Delete this file atomically.\n";
const UNICODE_MOVE_NAME: &str = "Cafe\u{301}-\u{1100}\u{1161}\u{11A8}.bin";
const POLICIES: [&str; 6] = [
    "lost-cache",
    "all-cache",
    "last-write",
    "first-sector",
    "last-sector",
    "header-first",
];

struct Disk {
    visible: Cursor<Vec<u8>>,
    durable: Vec<u8>,
    pending: Vec<(usize, usize)>,
    trace: Vec<String>,
    fail_at: Option<usize>,
    fail_header_read: Option<u64>,
    logical_sector: u32,
    dead: bool,
}
impl Disk {
    fn new(bytes: &[u8], fail_at: Option<usize>) -> Self {
        Self {
            visible: Cursor::new(bytes.to_vec()),
            durable: bytes.to_vec(),
            pending: Vec::new(),
            trace: Vec::new(),
            fail_at,
            fail_header_read: None,
            logical_sector: 512,
            dead: false,
        }
    }
    fn boundary(&mut self, description: String) -> io::Result<()> {
        if self.dead || self.fail_at == Some(self.trace.len()) {
            self.dead = true;
            return Err(io::Error::other("simulated power loss"));
        }
        self.trace.push(description);
        Ok(())
    }
    fn snapshot(&self, policy: usize, journal_offset: usize) -> Vec<u8> {
        let mut bytes = self.durable.clone();
        let visible = self.visible.get_ref();
        let range = match policy {
            0 => None,
            1 => {
                return visible.clone();
            }
            2 => self.pending.last().copied(),
            3 => self.pending.first().map(|(off, _)| (off / 512 * 512, 512)),
            4 => self
                .pending
                .last()
                .map(|(off, len)| ((off + len - 1) / 512 * 512, 512)),
            5 => self
                .pending
                .iter()
                .rev()
                .find(|(off, _)| *off == journal_offset)
                .copied(),
            _ => unreachable!(),
        };
        if let Some((off, len)) = range {
            bytes[off..off + len].copy_from_slice(&visible[off..off + len]);
        }
        bytes
    }
}
impl Read for Disk {
    fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
        if self.fail_header_read == Some(self.visible.position()) && b.len() == 4096 {
            return Err(io::Error::other(
                "injected volume-header sector read failure",
            ));
        }
        self.visible.read(b)
    }
}
impl Seek for Disk {
    fn seek(&mut self, p: SeekFrom) -> io::Result<u64> {
        self.visible.seek(p)
    }
}
impl Write for Disk {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        let off = self.visible.position() as usize;
        self.boundary(format!("write:{off}:{}", b.len()))?;
        if off
            .checked_add(b.len())
            .is_none_or(|end| end > self.durable.len())
        {
            return Err(io::Error::other("out of bounds"));
        }
        let count = self.visible.write(b)?;
        if count > 0 {
            self.pending.push((off, count));
        }
        Ok(count)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.boundary("sync".into())?;
        self.durable.copy_from_slice(self.visible.get_ref());
        self.pending.clear();
        Ok(())
    }
}
impl BlockDevice for Disk {
    fn block_size(&self) -> u32 {
        self.logical_sector
    }
    fn total_size(&self) -> u64 {
        self.durable.len() as u64
    }
    fn sync(&mut self) -> fstool::Result<()> {
        Ok(self.flush()?)
    }
}
fn report(kind: &str, status: &str, message: &str) {
    if let Some(path) = std::env::var_os("HFS_PROGRESS_LOG") {
        let at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis();
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .unwrap();
        // All messages generated by this test use printable ASCII.
        writeln!(
            file,
            "{{\"at\":{at},\"kind\":\"{kind}\",\"status\":\"{status}\",\"message\":{message:?}}}"
        )
        .unwrap();
    }
}
fn payload() -> Vec<u8> {
    (0..10_003)
        .map(|i| ((i * 31 + i / 251) % 256) as u8)
        .collect()
}
fn add(fs: &mut HfsPlus, disk: &mut Disk, path: &str, bytes: &[u8]) -> fstool::Result<()> {
    fs.create_file(
        disk,
        path,
        &mut &bytes[..],
        bytes.len() as u64,
        0o644,
        0,
        0,
        1_700_000_000,
    )
    .map(|_| ())
}
fn journal_offset(bytes: &[u8]) -> usize {
    let info = volume::be32(bytes, 1024 + 12) as usize * volume::be32(bytes, 1024 + 40) as usize;
    volume::be64(bytes, info + 36) as usize
}
fn baseline(little: bool, wrap: bool) -> Vec<u8> {
    baseline_with_victim(little, wrap, VICTIM)
}
fn baseline_with_victim(little: bool, wrap: bool, victim: &[u8]) -> Vec<u8> {
    baseline_with_catalog(little, wrap, victim, 8192, false, None)
}
fn catalog_name(index: usize) -> String {
    format!("/Transfer/structural-{index:04}-{}", "x".repeat(100))
}
fn baseline_with_catalog(
    little: bool,
    wrap: bool,
    victim: &[u8],
    node_size: u32,
    populated: bool,
    resource: Option<Vec<u8>>,
) -> Vec<u8> {
    let mut disk = Disk::new(&vec![0; SIZE], None);
    let mut fs = HfsPlus::format(
        &mut disk,
        &FormatOpts {
            journaled: true,
            node_size,
            catalog_nodes: if node_size == 2048 { 4 } else { 32 },
            ..Default::default()
        },
    )
    .unwrap();
    fs.create_dir(&mut disk, "/Transfer", 0o755, 0, 0, 0)
        .unwrap();
    fs.create_dir(&mut disk, "/Destination", 0o755, 0, 0, 0)
        .unwrap();
    add(&mut fs, &mut disk, "/Transfer/hello.txt", HELLO).unwrap();
    add(&mut fs, &mut disk, "/Transfer/victim.bin", victim).unwrap();
    if let Some(resource) = resource.filter(|r| !r.is_empty()) {
        let mut file = fs
            .open_resource_fork_rw(&mut disk, std::path::Path::new("/Transfer/victim.bin"))
            .unwrap();
        file.write_all(&resource).unwrap();
        file.sync().unwrap();
    }
    if populated {
        for index in 0..32 {
            fs.create_dir(&mut disk, &catalog_name(index), 0o755, 0, 0, 0)
                .unwrap();
        }
    }
    fs.flush(&mut disk).unwrap();
    drop(fs);
    // Independent reproduction of the correct TN1150 JIB flag. This allows
    // this same test to run on the upstream formatter before its flag fix.
    let bytes = disk.visible.get_mut();
    let info = volume::be32(bytes, 1024 + 12) as usize * volume::be32(bytes, 1024 + 40) as usize;
    bytes[info..info + 4].copy_from_slice(&1u32.to_be_bytes());
    let j = journal_offset(bytes);
    let size = volume::be64(bytes, j + 24);
    let cursor = if wrap { size - 512 } else { 512 };
    // Convert only an empty journal header. Never byte-swap payload records.
    for (off, width) in [
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
        if little {
            bytes[j + off..j + off + width].reverse();
        }
    }
    bytes[j + 8..j + 16].copy_from_slice(&if little {
        cursor.to_le_bytes()
    } else {
        cursor.to_be_bytes()
    });
    bytes[j + 16..j + 24].copy_from_slice(&if little {
        cursor.to_le_bytes()
    } else {
        cursor.to_be_bytes()
    });
    bytes[j + 36..j + 40].fill(0);
    let checksum = volume::journal_checksum(&bytes[j..j + 44]);
    bytes[j + 36..j + 40].copy_from_slice(&if little {
        checksum.to_le_bytes()
    } else {
        checksum.to_be_bytes()
    });
    disk.sync().unwrap();
    disk.durable
}
#[derive(Clone, Copy, Debug)]
enum Change {
    Create,
    Delete,
    Mkdir,
    MoveFile,
    UnicodeMove,
    MoveFolder,
    Overwrite,
    Truncate,
    Patch,
    BlockPatch,
    ShrinkRegrow,
    CatalogSplit,
    CatalogMerge,
    Allocation,
    AllocationTruncate,
    BasicAttributes,
    Replace,
    ResourceCreate,
    ResourceOverwrite,
    ResourcePatch,
    ResourceTruncate,
}
fn change(disk: &mut Disk, change: Change) -> fstool::Result<()> {
    let mut fs = HfsPlus::open(disk)?;
    match change {
        Change::Create => add(&mut fs, disk, "/Transfer/payload.bin", &payload())?,
        Change::ResourceCreate
        | Change::ResourceOverwrite
        | Change::ResourcePatch
        | Change::ResourceTruncate => {
            let mut file =
                fs.open_resource_fork_rw(disk, std::path::Path::new("/Transfer/victim.bin"))?;
            match change {
                Change::ResourceCreate => file.write_all(&payload())?,
                Change::ResourceOverwrite => {
                    file.set_len(0)?;
                    file.write_all(b"new resource\0\xff")?;
                }
                Change::ResourcePatch => {
                    file.seek(SeekFrom::Start(4094))?;
                    file.write_all(b"resources")?;
                }
                Change::ResourceTruncate => file.set_len(0)?,
                _ => unreachable!(),
            }
            return file.sync();
        }
        Change::Delete => fs.remove(disk, "/Transfer/victim.bin")?,
        Change::Mkdir => {
            fs.create_dir(disk, "/Transfer/New", 0o755, 0, 0, 0)?;
        }
        Change::MoveFile => fs.rename(disk, "/Transfer/victim.bin", "/victim-moved.bin")?,
        Change::UnicodeMove => fs.rename(disk, "/Transfer/victim.bin", "/Café-각.bin")?,
        Change::MoveFolder => fs.rename(disk, "/Transfer", "/Destination/Moved")?,
        Change::Allocation | Change::AllocationTruncate => {
            return fs.set_data_allocation(
                disk,
                std::path::Path::new("/Transfer/victim.bin"),
                if matches!(change, Change::Allocation) {
                    16384
                } else {
                    0
                },
                false,
            );
        }
        Change::BasicAttributes => {
            let cnid = volume::be32(&fs.catalog_record("/Transfer/victim.bin")?, 8);
            fs.set_catalog_windows_info(
                cnid,
                [None, None, Some(3_000_000_000), Some(3_000_000_000)],
                Some(2),
            )?;
        }
        Change::Replace => {
            fs.remove(disk, "/Transfer/victim.bin")?;
            fs.rename(disk, "/Transfer/hello.txt", "/Transfer/victim.bin")?;
        }
        Change::CatalogSplit | Change::CatalogMerge => {
            for index in 0..32 {
                if matches!(change, Change::CatalogSplit) {
                    fs.create_dir(disk, &catalog_name(index), 0o755, 0, 0, 0)?;
                } else {
                    fs.remove(disk, &catalog_name(index))?;
                }
            }
        }
        Change::Overwrite
        | Change::Truncate
        | Change::Patch
        | Change::BlockPatch
        | Change::ShrinkRegrow => {
            let mut handle = fs.open_file_rw(
                disk,
                std::path::Path::new("/Transfer/victim.bin"),
                fstool::fs::OpenFlags::default(),
                None,
            )?;
            match change {
                Change::Overwrite => {
                    handle.set_len(0)?;
                    handle.write_all(&payload())?;
                }
                Change::Truncate => handle.set_len(5)?,
                Change::Patch => {
                    handle.seek(SeekFrom::Start(8191))?;
                    handle.write_all(b"offset write")?;
                }
                Change::BlockPatch => {
                    handle.seek(SeekFrom::Start(4094))?;
                    handle.write_all(b"blocks")?;
                    handle.seek(SeekFrom::Start(4095))?;
                    handle.write_all(b"XYZ")?;
                }
                Change::ShrinkRegrow => {
                    handle.set_len(4097)?;
                    handle.set_len(12_003)?;
                    handle.seek(SeekFrom::Start(4095))?;
                    handle.write_all(b"tail")?;
                }
                _ => unreachable!(),
            }
            return handle.sync();
        }
    }
    fs.flush(disk)
}
fn content(fs: &mut HfsPlus, disk: &mut Disk, path: &str) -> hfs_bridge::Result<Vec<u8>> {
    let mut reader = Filesystem::read_file(fs, disk, std::path::Path::new(path))?;
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes)?;
    Ok(bytes)
}
fn verify(disk: &mut Disk, change: Change) -> hfs_bridge::Result<()> {
    // Replay is allowed only in this memory simulator; production still
    // refuses pending journals through open_checked's read-only preflight.
    let mut fs = HfsPlus::open(disk)?;
    let inspected = volume::inspect(disk)?;
    volume::require_engine_access(&inspected)?;
    // Independent index/leaf links, key boundaries, node maps and valences.
    let tree = catalog_wire::audit(disk.visible.get_ref());
    assert!(tree.depth > 0 && tree.leaves > 0 && tree.free < tree.total);
    let root = fs.list(disk, std::path::Path::new("/"))?;
    let at_root = |name: &str| root.iter().any(|e| e.name == name);
    let destination = fs.list(disk, std::path::Path::new("/Destination"))?;
    let folder_moved = destination.iter().any(|e| e.name == "Moved");
    if volume::be32(&fs.catalog_record("/Destination")?, 4) != destination.len() as u32 {
        return Err("destination folder child count disagrees".into());
    }
    let directory = if matches!(change, Change::MoveFolder) {
        if at_root("Transfer") == folder_moved {
            return Err("directory move lost or duplicated the source".into());
        }
        if folder_moved {
            "/Destination/Moved"
        } else {
            "/Transfer"
        }
    } else {
        "/Transfer"
    };
    let hello_exists = fs.catalog_record(&format!("{directory}/hello.txt")).is_ok();
    if (!matches!(change, Change::Replace) || hello_exists)
        && content(&mut fs, disk, &format!("{directory}/hello.txt"))? != HELLO
    {
        return Err("existing file changed".into());
    }
    let entries = fs.list(disk, std::path::Path::new(directory))?;
    let exists = |name: &str| entries.iter().any(|e| e.name == name);
    if volume::be32(&fs.catalog_record(directory)?, 4) != entries.len() as u32 {
        return Err("source/moved folder child count disagrees".into());
    }
    let move_name = if matches!(change, Change::UnicodeMove) {
        UNICODE_MOVE_NAME
    } else {
        "victim-moved.bin"
    };
    let victim_moved =
        matches!(change, Change::MoveFile | Change::UnicodeMove) && at_root(move_name);
    if matches!(change, Change::MoveFile | Change::UnicodeMove)
        && exists("victim.bin") == victim_moved
    {
        return Err("file move lost or duplicated the source".into());
    }
    if exists("victim.bin") {
        let bytes = content(&mut fs, disk, &format!("{directory}/victim.bin"))?;
        if bytes != original_victim(change) && bytes != edited_victim(change) {
            return Err("existing file is neither its original nor complete edited version".into());
        }
        if matches!(change, Change::Replace) && bytes != if hello_exists { VICTIM } else { HELLO } {
            return Err("replacement deletion and rename were not atomic".into());
        }
        let body = fs.catalog_record(&format!("{directory}/victim.bin"))?;
        if is_resource(change) {
            let mut actual = Vec::new();
            if fs
                .resource_fork_size(disk, "/Transfer/victim.bin")?
                .is_some()
            {
                fs.open_resource_fork_reader(disk, "/Transfer/victim.bin")?
                    .read_to_end(&mut actual)?;
            }
            if actual != original_resource(change) && actual != edited_resource(change) {
                return Err("resource fork partially committed".into());
            }
            let data_block = volume::be32(&body, 104);
            let bytes = disk.visible.get_ref();
            let allocation = volume::be32(bytes, 1152) as usize * 4096;
            if bytes[allocation + data_block as usize / 8] & (0x80 >> (data_block % 8)) == 0 {
                return Err("resource edit retired the data allocation".into());
            }
        }
        if matches!(change, Change::Allocation) && ![1, 4].contains(&volume::be32(&body, 100)) {
            return Err("reservation is neither old nor complete new allocation".into());
        }
        if matches!(change, Change::AllocationTruncate)
            && ((bytes.is_empty() && volume::be32(&body, 100) != 0)
                || (!bytes.is_empty() && volume::be32(&body, 100) != 1))
        {
            return Err("allocation truncation did not publish EOF and blocks together".into());
        }
        if matches!(change, Change::BasicAttributes) {
            let actual = (
                volume::be32(&body, 16),
                volume::be32(&body, 20),
                volume::be32(&body, 28),
                volume::be16(&body, 56),
            );
            let old = (3_782_844_800, 3_782_844_800, 0, 0);
            let new = (3_000_000_000, 3_000_000_000, 3_000_000_000, 0x4000);
            if actual != old && actual != new {
                return Err("basic metadata fields partially committed".into());
            }
        }
    }
    if victim_moved && content(&mut fs, disk, &format!("/{move_name}"))? != VICTIM {
        return Err("moved file contents changed".into());
    }
    if !matches!(change, Change::Delete) && !exists("victim.bin") && !victim_moved {
        return Err("unrelated file disappeared".into());
    }
    if exists("payload.bin") && content(&mut fs, disk, "/Transfer/payload.bin")? != payload() {
        return Err("new file partially committed".into());
    }
    let expected_files =
        3 + u32::from(exists("victim.bin") || victim_moved) + u32::from(exists("payload.bin"))
            - u32::from(matches!(change, Change::Replace) && !hello_exists); // 2 journal files plus hello.
    let structural = entries
        .iter()
        .filter(|entry| entry.name.starts_with("structural-"))
        .count();
    if structural != 0 && structural != 32 {
        return Err("structural catalog operation partially committed".into());
    }
    let expected_folders = 2 + u32::from(exists("New")) + structural as u32;
    if inspected.header.files != expected_files || inspected.header.folders != expected_folders {
        return Err("catalog/header counts disagree".into());
    }
    // The allocation count is checked by decoding the bitmap independently.
    let bytes = disk.visible.get_ref();
    let allocation =
        volume::be32(bytes, 1024 + 112 + 16) as usize * inspected.header.block_size as usize;
    let used = (0..inspected.header.total_blocks as usize)
        .filter(|i| bytes[allocation + i / 8] & (0x80 >> (i % 8)) != 0)
        .count() as u32;
    if inspected.header.free_blocks != inspected.header.total_blocks - used {
        return Err("bitmap/header free block count disagrees".into());
    }
    Ok(())
}
fn verify_committed(disk: &mut Disk, change: Change) -> hfs_bridge::Result<()> {
    let mut fs = HfsPlus::open(disk)?;
    if matches!(change, Change::MoveFolder) {
        let entries = fs.list(disk, std::path::Path::new("/Destination"))?;
        if !entries.iter().any(|e| e.name == "Moved") || fs.catalog_record("/Transfer").is_ok() {
            return Err("acknowledged directory move did not persist".into());
        }
        return Ok(());
    }
    let entries = fs.list(disk, std::path::Path::new("/Transfer"))?;
    let exists = |name: &str| entries.iter().any(|e| e.name == name);
    let committed = match change {
        Change::ResourceCreate
        | Change::ResourceOverwrite
        | Change::ResourcePatch
        | Change::ResourceTruncate => {
            let mut actual = Vec::new();
            if fs
                .resource_fork_size(disk, "/Transfer/victim.bin")?
                .is_some()
            {
                fs.open_resource_fork_reader(disk, "/Transfer/victim.bin")?
                    .read_to_end(&mut actual)?;
            }
            actual == edited_resource(change)
        }
        Change::Create => exists("payload.bin"),
        Change::Delete => !exists("victim.bin"),
        Change::Mkdir => exists("New"),
        Change::MoveFile => {
            !exists("victim.bin")
                && fs
                    .list(disk, std::path::Path::new("/"))?
                    .iter()
                    .any(|e| e.name == "victim-moved.bin")
        }
        Change::UnicodeMove => {
            !exists("victim.bin")
                && fs
                    .list(disk, std::path::Path::new("/"))?
                    .iter()
                    .any(|entry| entry.name == UNICODE_MOVE_NAME)
        }
        Change::MoveFolder => unreachable!(),
        Change::Allocation => volume::be32(&fs.catalog_record("/Transfer/victim.bin")?, 100) == 4,
        Change::AllocationTruncate => {
            volume::be64(&fs.catalog_record("/Transfer/victim.bin")?, 88) == 0
        }
        Change::BasicAttributes => {
            let body = fs.catalog_record("/Transfer/victim.bin")?;
            volume::be32(&body, 28) == 3_000_000_000 && volume::be16(&body, 56) == 0x4000
        }
        Change::Replace => {
            !exists("hello.txt") && content(&mut fs, disk, "/Transfer/victim.bin")? == HELLO
        }
        Change::CatalogSplit => {
            entries
                .iter()
                .filter(|entry| entry.name.starts_with("structural-"))
                .count()
                == 32
        }
        Change::CatalogMerge => !entries
            .iter()
            .any(|entry| entry.name.starts_with("structural-")),
        Change::Overwrite
        | Change::Truncate
        | Change::Patch
        | Change::BlockPatch
        | Change::ShrinkRegrow => {
            content(&mut fs, disk, "/Transfer/victim.bin")? == edited_victim(change)
        }
    };
    if !committed {
        return Err("acknowledged transaction did not persist its requested change".into());
    }
    Ok(())
}
fn edited_victim(change: Change) -> Vec<u8> {
    match change {
        Change::Overwrite => payload(),
        Change::AllocationTruncate => Vec::new(),
        Change::Replace => HELLO.to_vec(),
        Change::Truncate => VICTIM[..5].to_vec(),
        Change::Patch => {
            let mut bytes = VICTIM.to_vec();
            bytes.resize(8191, 0);
            bytes.extend_from_slice(b"offset write");
            bytes
        }
        Change::BlockPatch => {
            let mut bytes = payload();
            bytes[4094..4100].copy_from_slice(b"blocks");
            bytes[4095..4098].copy_from_slice(b"XYZ");
            bytes
        }
        Change::ShrinkRegrow => {
            let mut bytes = payload();
            bytes.truncate(4097);
            bytes.resize(12_003, 0);
            bytes[4095..4099].copy_from_slice(b"tail");
            bytes
        }
        _ => VICTIM.to_vec(),
    }
}
fn original_victim(change: Change) -> Vec<u8> {
    if matches!(change, Change::BlockPatch | Change::ShrinkRegrow) {
        payload()
    } else {
        VICTIM.to_vec()
    }
}
fn is_resource(change: Change) -> bool {
    matches!(
        change,
        Change::ResourceCreate
            | Change::ResourceOverwrite
            | Change::ResourcePatch
            | Change::ResourceTruncate
    )
}
fn original_resource(change: Change) -> Vec<u8> {
    if matches!(change, Change::ResourceCreate) {
        Vec::new()
    } else {
        payload()
    }
}
fn edited_resource(change: Change) -> Vec<u8> {
    match change {
        Change::ResourceCreate => payload(),
        Change::ResourceOverwrite => b"new resource\0\xff".to_vec(),
        Change::ResourcePatch => {
            let mut bytes = payload();
            bytes[4094..4103].copy_from_slice(b"resources");
            bytes
        }
        Change::ResourceTruncate => Vec::new(),
        _ => unreachable!(),
    }
}
#[test]
fn journal_crash_matrix() {
    let mut checkpoints = 0;
    let mut replay_checkpoints = 0;
    for little in [false, true] {
        for wrap in [false, true] {
            for operation in [
                Change::Create,
                Change::Delete,
                Change::Mkdir,
                Change::MoveFile,
                Change::UnicodeMove,
                Change::MoveFolder,
                Change::Overwrite,
                Change::Truncate,
                Change::Patch,
                Change::BlockPatch,
                Change::ShrinkRegrow,
                Change::CatalogSplit,
                Change::CatalogMerge,
                Change::Allocation,
                Change::AllocationTruncate,
                Change::BasicAttributes,
                Change::Replace,
                Change::ResourceCreate,
                Change::ResourceOverwrite,
                Change::ResourcePatch,
                Change::ResourceTruncate,
            ] {
                let bytes = if matches!(operation, Change::CatalogSplit | Change::CatalogMerge) {
                    baseline_with_catalog(
                        little,
                        wrap,
                        VICTIM,
                        2048,
                        matches!(operation, Change::CatalogMerge),
                        None,
                    )
                } else if is_resource(operation) {
                    baseline_with_catalog(
                        little,
                        wrap,
                        VICTIM,
                        8192,
                        false,
                        Some(original_resource(operation)),
                    )
                } else {
                    baseline_with_victim(little, wrap, &original_victim(operation))
                };
                let j = journal_offset(&bytes);
                let label = format!(
                    "{operation:?} {} {}",
                    if little { "LE" } else { "BE" },
                    if wrap { "wrap" } else { "linear" }
                );
                let mut full = Disk::new(&bytes, None);
                change(&mut full, operation).unwrap();
                verify(&mut full, operation).unwrap();
                verify_committed(&mut full, operation).unwrap();
                let steps = full.trace.len();
                let mut pending_sample = None;
                for stop in 0..steps {
                    let mut interrupted = Disk::new(&bytes, Some(stop));
                    assert!(
                        change(&mut interrupted, operation)
                            .unwrap_err()
                            .to_string()
                            .contains("simulated power loss")
                    );
                    for (policy, name) in POLICIES.iter().enumerate() {
                        let snapshot = interrupted.snapshot(policy, j);
                        let dirty = snapshot[j + 8..j + 16] != snapshot[j + 16..j + 24];
                        if dirty && pending_sample.is_none() {
                            pending_sample = Some(snapshot.clone());
                        }
                        let mut recovered = Disk::new(&snapshot, None);
                        let message = format!("{label}: checkpoint {stop}/{steps}, {name}");
                        let result = verify(&mut recovered, operation).and_then(|()| {
                            if dirty {
                                verify_committed(&mut recovered, operation)
                            } else {
                                Ok(())
                            }
                        });
                        if let Err(error) = result {
                            report("checkpoint", "fail", &message);
                            panic!("{message}: {error}; trace={:?}", interrupted.trace);
                        }
                        report("checkpoint", "pass", &message);
                        checkpoints += 1;
                    }
                }
                // Interrupt replay itself and reopen again to prove it is restartable.
                let pending =
                    pending_sample.expect("commit must expose an outstanding transaction");
                let mut full_replay = Disk::new(&pending, None);
                verify(&mut full_replay, operation).unwrap();
                verify_committed(&mut full_replay, operation).unwrap();
                if let Some(directory) = std::env::var_os("HFS_CRASH_ARTIFACT_DIR") {
                    let name = format!(
                        "recovered-{operation:?}-{}-{}.img",
                        if little { "le" } else { "be" },
                        if wrap { "wrap" } else { "linear" }
                    );
                    let path = std::path::Path::new(&directory).join(name);
                    let mut file = std::fs::OpenOptions::new()
                        .create_new(true)
                        .write(true)
                        .open(path)
                        .unwrap();
                    file.write_all(&full_replay.durable).unwrap();
                    file.sync_all().unwrap();
                }
                for stop in 0..full_replay.trace.len() {
                    let mut interrupted = Disk::new(&pending, Some(stop));
                    assert!(HfsPlus::open(&mut interrupted).is_err());
                    for (policy, name) in POLICIES.iter().enumerate() {
                        let mut recovered = Disk::new(&interrupted.snapshot(policy, j), None);
                        let message = format!("{label}: replay checkpoint {stop}, {name}");
                        let result = verify(&mut recovered, operation)
                            .and_then(|()| verify_committed(&mut recovered, operation));
                        if let Err(error) = result {
                            report("checkpoint", "fail", &message);
                            panic!("{message}: {error}");
                        }
                        report("checkpoint", "pass", &message);
                        replay_checkpoints += 1;
                    }
                }
                report(
                    "scenario",
                    "pass",
                    &format!("{label}: all write, flush, and replay boundaries passed"),
                );
            }
        }
    }
    println!(
        "CRASH_MATRIX: {checkpoints} commit checkpoints + {replay_checkpoints} replay checkpoints passed; 84 scenarios"
    );
}

fn pending_transaction() -> Vec<u8> {
    let bytes = baseline(false, false);
    let j = journal_offset(&bytes);
    let mut full = Disk::new(&bytes, None);
    change(&mut full, Change::Create).unwrap();
    for stop in 0..full.trace.len() {
        let mut interrupted = Disk::new(&bytes, Some(stop));
        assert!(change(&mut interrupted, Change::Create).is_err());
        let snapshot = interrupted.snapshot(0, j);
        if snapshot[j + 8..j + 16] != snapshot[j + 16..j + 24] {
            return snapshot;
        }
    }
    panic!("no committed pending transaction found");
}
#[test]
fn corrupt_late_payload_is_rejected_before_any_replay_write() {
    let mut bytes = pending_transaction();
    let j = journal_offset(&bytes);
    let start = volume::be64(&bytes, j + 8) as usize;
    let used = volume::be32(&bytes, j + start + 4) as usize;
    bytes[j + start + used - 1] ^= 1;
    let mut disk = Disk::new(&bytes, None);
    let error = HfsPlus::open(&mut disk).err().unwrap().to_string();
    assert!(error.contains("data checksum"), "{error}");
    assert!(
        disk.trace.is_empty(),
        "corrupt log caused writes: {:?}",
        disk.trace
    );
    assert_eq!(disk.visible.get_ref(), &bytes);
}
#[test]
fn journal_cannot_replay_onto_itself_or_past_the_committed_end() {
    let bytes = pending_transaction();
    let j = journal_offset(&bytes);
    let start = volume::be64(&bytes, j + 8) as usize;
    for own_journal in [true, false] {
        let mut corrupt = bytes.clone();
        if own_journal {
            // The first real block-info slot starts at fixed 16 + sentinel 16.
            corrupt[j + start + 32..j + start + 40]
                .copy_from_slice(&(j as u64 / 512).to_be_bytes());
        } else {
            corrupt[j + 16..j + 24].copy_from_slice(&(start as u64 + 512).to_be_bytes());
            corrupt[j + 36..j + 40].fill(0);
            let checksum = volume::journal_checksum(&corrupt[j..j + 44]);
            corrupt[j + 36..j + 40].copy_from_slice(&checksum.to_be_bytes());
        }
        let mut disk = Disk::new(&corrupt, None);
        assert!(HfsPlus::open(&mut disk).is_err());
        assert!(disk.trace.is_empty());
        assert_eq!(disk.visible.get_ref(), &corrupt);
    }
}
#[test]
fn invalid_journal_settings_never_fall_back_to_non_journaled_access() {
    let bytes = baseline(false, false);
    let info = volume::be32(&bytes, 1024 + 12) as usize * volume::be32(&bytes, 1024 + 40) as usize;
    for (off, replacement) in [
        (info, 2u32.to_be_bytes().to_vec()),
        (info, 4u32.to_be_bytes().to_vec()),
        (1024 + 12, vec![0; 4]),
        (info + 36, vec![0; 8]),
        (info + 44, vec![0; 8]),
    ] {
        let mut corrupt = bytes.clone();
        corrupt[off..off + replacement.len()].copy_from_slice(&replacement);
        let mut disk = Disk::new(&corrupt, None);
        assert!(HfsPlus::open(&mut disk).is_err());
        assert!(disk.trace.is_empty());
        assert_eq!(disk.visible.get_ref(), &corrupt);
    }
}
#[test]
fn oversized_metadata_batch_is_rejected_without_partial_commit() {
    let bytes = baseline(false, false);
    let mut disk = Disk::new(&bytes, None);
    let mut fs = HfsPlus::open(&mut disk).unwrap();
    for i in 0..4000 {
        fs.create_dir(
            &mut disk,
            &format!("/Transfer/Folder-{i:04}"),
            0o755,
            0,
            0,
            0,
        )
        .unwrap();
    }
    let error = fs.flush(&mut disk).unwrap_err().to_string();
    assert!(error.contains("atomic metadata batch"), "{error}");
    assert!(
        disk.trace.is_empty(),
        "rejection wrote metadata: {:?}",
        disk.trace
    );
    assert_eq!(disk.visible.get_ref(), &bytes);
    verify(&mut disk, Change::Mkdir).unwrap();
}
