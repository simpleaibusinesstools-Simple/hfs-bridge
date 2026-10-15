//! Format flags are patched independently; a rejected open must perform no I/O writes.
use fstool::{
    block::{BlockDevice, MemoryBackend},
    fs::hfs_plus::{FormatOpts, HfsPlus},
};
use hfs_bridge::{engine, volume};
use std::io::{Cursor, Read, Seek, SeekFrom, Write};

struct ReadOnly(Cursor<Vec<u8>>);
impl Read for ReadOnly {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        self.0.read(out)
    }
}
impl Seek for ReadOnly {
    fn seek(&mut self, offset: SeekFrom) -> std::io::Result<u64> {
        self.0.seek(offset)
    }
}
impl Write for ReadOnly {
    fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
        panic!("format preflight wrote to disk")
    }
    fn flush(&mut self) -> std::io::Result<()> {
        panic!("format preflight flushed disk")
    }
}
impl BlockDevice for ReadOnly {
    fn block_size(&self) -> u32 {
        512
    }
    fn total_size(&self) -> u64 {
        self.0.get_ref().len() as u64
    }
    fn sync(&mut self) -> fstool::Result<()> {
        panic!("format preflight synchronized disk")
    }
}
fn fixture(journaled: bool) -> (Vec<u8>, u32, u32) {
    let mut device = MemoryBackend::new(8 * 1024 * 1024);
    let mut fs = HfsPlus::format(
        &mut device,
        &FormatOpts {
            journaled,
            ..Default::default()
        },
    )
    .unwrap();
    let folder = fs
        .create_dir(&mut device, "/folder", 0o755, 501, 20, 1_700_000_000)
        .unwrap();
    let file = fs
        .create_file(
            &mut device,
            "/folder/file",
            &mut &b"payload"[..],
            7,
            0o644,
            501,
            20,
            1_700_000_000,
        )
        .unwrap();
    fs.flush(&mut device).unwrap();
    (device.into_bytes(), folder, file)
}
fn header_flags(bytes: &mut [u8], flags: u32) {
    for offset in [1024, bytes.len() - 1024] {
        let attributes = volume::be32(bytes, offset + 4) | flags;
        bytes[offset + 4..offset + 8].copy_from_slice(&attributes.to_be_bytes());
    }
}
fn mark_catalog(bytes: &mut [u8], cnid: u32, flags: u16) {
    let block = volume::be32(bytes, 1064) as usize;
    let catalog = volume::be32(bytes, 1024 + 288) as usize * block;
    let node_size = volume::be16(bytes, catalog + 32) as usize;
    let mut leaf = volume::be32(bytes, catalog + 24) as usize;
    while leaf != 0 {
        let start = catalog + leaf * node_size;
        let records = volume::be16(bytes, start + 10) as usize;
        for index in 0..records {
            let key = start + volume::be16(bytes, start + node_size - 2 * (index + 1)) as usize;
            let body = key + 2 + volume::be16(bytes, key) as usize;
            if matches!(volume::be16(bytes, body), 1 | 2) && volume::be32(bytes, body + 8) == cnid {
                let prior = volume::be16(bytes, body + 2);
                bytes[body + 2..body + 4].copy_from_slice(&(prior | flags).to_be_bytes());
                return;
            }
        }
        leaf = volume::be32(bytes, start) as usize;
    }
    panic!("test catalog identity absent");
}
fn rejected_without_writes(bytes: Vec<u8>, expected: &str) {
    let mut source = ReadOnly(Cursor::new(bytes.clone()));
    let message = match engine::open_checked(&mut source) {
        Ok(_) => panic!("unsupported format was accepted"),
        Err(error) => error.to_string(),
    };
    assert!(message.contains(expected), "{message}");
    assert_eq!(source.0.get_ref(), &bytes);
}

#[test]
fn unsupported_volume_formats_are_inspectable_but_refused_before_engine_access() {
    for journaled in [false, true] {
        let (original, _, _) = fixture(journaled);
        for flags in [1 << 29, 1 << 30, (1 << 29) | (1 << 30)] {
            let mut bytes = original.clone();
            header_flags(&mut bytes, flags);
            let report = volume::inspect(&mut ReadOnly(Cursor::new(bytes.clone()))).unwrap();
            assert!(report.alternate_compatible);
            assert!(volume::require_engine_access(&report).is_err());
            rejected_without_writes(bytes, "unsupported volume feature");
        }
    }
}

#[test]
fn standalone_expanded_catalog_dates_cannot_bypass_the_volume_guard() {
    for journaled in [false, true] {
        let (original, folder, file) = fixture(journaled);
        for cnid in [2, folder, file] {
            let mut bytes = original.clone();
            mark_catalog(&mut bytes, cnid, 0x1000);
            // Apple permits individual records to opt in independently.
            assert_eq!(volume::be32(&bytes, 1028) & (1 << 29), 0);
            rejected_without_writes(bytes, "expanded catalog timestamps");
        }
    }
}

#[test]
fn classic_dates_and_date_added_metadata_remain_supported() {
    for journaled in [false, true] {
        let (mut bytes, folder, file) = fixture(journaled);
        header_flags(&mut bytes, 1 << 31);
        for cnid in [2, folder, file] {
            mark_catalog(&mut bytes, cnid, 0x80);
        }
        let mut source = ReadOnly(Cursor::new(bytes.clone()));
        let fs = engine::open_checked(&mut source).unwrap();
        let body = fs.catalog_record_cnid(file).unwrap();
        assert_ne!(volume::be16(&body, 2) & 0x80, 0);
        assert_eq!(volume::be32(&body, 16), 1_700_000_000 + 2_082_844_800);
        assert_eq!(source.0.get_ref(), &bytes);
    }
}
