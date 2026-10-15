//! Export an actual pending 4 KB directory transaction for native Apple replay.
use fstool::{
    block::{BlockDevice, MemoryBackend},
    fs::hfs_plus::{FormatOpts, HfsPlus, preflight_replay},
};
use std::io::{self, Cursor, Read, Seek, SeekFrom, Write};

#[path = "support/journal_geometry.rs"]
#[allow(dead_code)]
mod journal_geometry;

struct StopAtHeader {
    bytes: Cursor<Vec<u8>>,
    stopped: bool,
    logical_sector: u32,
}
impl Read for StopAtHeader {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.bytes.read(bytes)
    }
}
impl Seek for StopAtHeader {
    fn seek(&mut self, offset: SeekFrom) -> io::Result<u64> {
        self.bytes.seek(offset)
    }
}
impl Write for StopAtHeader {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.stopped
            || (self.bytes.position() == 1024 && bytes.len() == 512)
            || (self.bytes.position() == 0 && bytes.len() == 4096)
        {
            self.stopped = true;
            return Err(io::Error::other("stop before home volume header"));
        }
        self.bytes.write(bytes)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
impl BlockDevice for StopAtHeader {
    fn block_size(&self) -> u32 {
        self.logical_sector
    }
    fn total_size(&self) -> u64 {
        self.bytes.get_ref().len() as u64
    }
    fn sync(&mut self) -> fstool::Result<()> {
        Ok(())
    }
}

#[test]
fn pending_four_k_directory_transaction_for_native_replay() {
    check_pending(4096, "HFS_4K_NATIVE_PENDING_IMAGE");
}

#[test]
fn larger_journal_adopts_device_sectors_before_publishing_pending_transaction() {
    check_pending(512, "HFS_ADAPTED_NATIVE_PENDING_IMAGE");
}

fn check_pending(logical_sector: u32, export_variable: &str) {
    let mut source = MemoryBackend::new(32 * 1024 * 1024);
    HfsPlus::format(
        &mut source,
        &FormatOpts {
            journaled: true,
            ..Default::default()
        },
    )
    .unwrap();
    let mut original = source.as_slice().to_vec();
    journal_geometry::convert_empty(&mut original, 4096, true, false);
    let mut disk = StopAtHeader {
        bytes: Cursor::new(original.clone()),
        stopped: false,
        logical_sector,
    };
    let mut fs = HfsPlus::open(&mut disk).unwrap();
    fs.create_dir(&mut disk, "/Apple replay check", 0o755, 0, 0, 1_700_000_000)
        .unwrap();
    assert!(
        fs.flush(&mut disk)
            .unwrap_err()
            .to_string()
            .contains("stop before home volume header")
    );
    assert_eq!(&disk.bytes.get_ref()[1024..1536], &original[1024..1536]);
    assert!(preflight_replay(&mut disk).unwrap().blocks > 0);
    let bytes = disk.bytes.get_ref();
    let jib = hfs_bridge::volume::be32(bytes, 1036) as usize
        * hfs_bridge::volume::be32(bytes, 1064) as usize;
    let journal = hfs_bridge::volume::be64(bytes, jib + 36) as usize;
    let ring = hfs_bridge::volume::be64(bytes, jib + 44);
    let sector = u32::from_le_bytes(bytes[journal + 40..journal + 44].try_into().unwrap());
    assert_eq!(sector, logical_sector);
    let start = u64::from_le_bytes(bytes[journal + 8..journal + 16].try_into().unwrap()) as usize;
    let declared = u16::from_le_bytes(
        bytes[journal + start..journal + start + 2]
            .try_into()
            .unwrap(),
    );
    assert!(
        u64::from(declared) <= ring / u64::from(sector),
        "Apple rejects capacities larger than the journal sector count"
    );
    let mut replay = MemoryBackend::from_bytes(disk.bytes.get_ref().clone());
    let reopened = HfsPlus::open(&mut replay).unwrap();
    assert!(reopened.catalog_record("/Apple replay check").is_ok());
    assert_eq!(
        hfs_bridge::volume::inspect(&mut replay)
            .unwrap()
            .header
            .folders,
        1
    );
    if let Some(path) = std::env::var_os(export_variable) {
        let mut output = hfs_bridge::image::create_output(std::path::Path::new(&path)).unwrap();
        output.write_all(disk.bytes.get_ref()).unwrap();
        output.sync_all().unwrap();
        println!("Exported pending image for independent Apple replay: {path:?}");
    }
}
