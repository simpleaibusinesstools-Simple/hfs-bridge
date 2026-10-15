//! Match the Toshiba's logical capacity without allocating a physical 2 TB file.
use fstool::{
    block::{BlockDevice, MemoryBackend},
    fs::hfs_plus::{ForkEdit, FormatOpts, HfsPlus, PublicationMetadata},
};
use hfs_bridge::volume;
use std::{
    collections::BTreeMap,
    io::{self, Read, Seek, SeekFrom, Write},
    path::Path,
};

struct Sparse {
    pages: BTreeMap<u64, Box<[u8; 4096]>>,
    position: u64,
    reads: Vec<(u64, usize)>,
}
impl Read for Sparse {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        if self.position + bytes.len() as u64 > self.total_size() {
            return Err(io::Error::other("read bounds"));
        }
        self.reads.push((self.position, bytes.len()));
        for chunk in bytes.chunks_mut(4096) {
            let mut done = 0;
            while done < chunk.len() {
                let offset = self.position % 4096;
                let count = (4096 - offset as usize).min(chunk.len() - done);
                if let Some(page) = self.pages.get(&(self.position / 4096)) {
                    chunk[done..done + count]
                        .copy_from_slice(&page[offset as usize..offset as usize + count]);
                } else {
                    chunk[done..done + count].fill(0);
                }
                self.position += count as u64;
                done += count;
            }
        }
        Ok(bytes.len())
    }
}
impl Write for Sparse {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.position + bytes.len() as u64 > self.total_size() {
            return Err(io::Error::other("write bounds"));
        }
        let mut done = 0;
        while done < bytes.len() {
            let offset = self.position % 4096;
            let count = (4096 - offset as usize).min(bytes.len() - done);
            let page = self
                .pages
                .entry(self.position / 4096)
                .or_insert_with(|| Box::new([0; 4096]));
            page[offset as usize..offset as usize + count]
                .copy_from_slice(&bytes[done..done + count]);
            self.position += count as u64;
            done += count;
        }
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
impl Seek for Sparse {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        let value = match from {
            SeekFrom::Start(at) => i128::from(at),
            SeekFrom::Current(delta) => i128::from(self.position) + i128::from(delta),
            SeekFrom::End(delta) => i128::from(self.total_size()) + i128::from(delta),
        };
        if value < 0 || value > i128::from(self.total_size()) {
            return Err(io::Error::other("seek bounds"));
        }
        self.position = value as u64;
        Ok(self.position)
    }
}
impl BlockDevice for Sparse {
    fn block_size(&self) -> u32 {
        512
    }
    fn total_size(&self) -> u64 {
        2_000_246_800_384
    }
    fn sync(&mut self) -> fstool::Result<()> {
        Ok(())
    }
}
#[test]
fn bitmap_partial_byte_and_sector_tail_keep_their_distinct_wire_rules() {
    for journaled in [false, true] {
        for blocks in [2049u32, 2055, 2056, 4096] {
            let mut disk = MemoryBackend::new(u64::from(blocks) * 4096);
            HfsPlus::format(
                &mut disk,
                &FormatOpts {
                    journaled,
                    ..Default::default()
                },
            )
            .unwrap();
            let mut header = [0; 1536];
            disk.read_at(0, &mut header).unwrap();
            let bitmap_start = u64::from(volume::be32(&header, 1152)) * 4096;
            let storage_bytes = usize::try_from(volume::be64(&header, 1136)).unwrap();
            let logical_bytes = blocks.div_ceil(8) as usize;
            assert!(storage_bytes >= logical_bytes.div_ceil(512) * 512);
            let padding = vec![0xa6; logical_bytes.div_ceil(512) * 512 - logical_bytes];
            disk.write_at(bitmap_start + logical_bytes as u64, &padding)
                .unwrap();
            let mut fs = HfsPlus::open(&mut disk).unwrap();
            let payload = vec![0x4b; 6003];
            fs.create_file(
                &mut disk,
                "/wire-file",
                &mut payload.as_slice(),
                payload.len() as u64,
                0o644,
                501,
                20,
                1_700_000_000,
            )
            .unwrap();
            fs.flush(&mut disk).unwrap();
            let mut last = [0];
            disk.read_at(bitmap_start + logical_bytes as u64 - 1, &mut last)
                .unwrap();
            let valid = blocks % 8;
            if valid != 0 {
                assert_eq!(last[0] & ((1u8 << (8 - valid)) - 1), 0);
            }
            let mut retained = vec![0; padding.len()];
            disk.read_at(bitmap_start + logical_bytes as u64, &mut retained)
                .unwrap();
            assert_eq!(retained, padding);
            let fs = HfsPlus::open(&mut disk).unwrap();
            let mut actual = Vec::new();
            fs.open_file_reader(&mut disk, "/wire-file")
                .unwrap()
                .read_to_end(&mut actual)
                .unwrap();
            assert_eq!(actual, payload);
        }
    }
}
#[test]
#[ignore = "explicit exact-Toshiba-capacity memory timing diagnostic"]
fn profile_inline_publication_at_toshiba_bitmap_size() {
    use hfs_bridge::windows::{Access, Adapter, Kind, OpenRequest};
    use std::time::Instant;
    let mut disk = Sparse {
        pages: BTreeMap::new(),
        position: 0,
        reads: vec![],
    };
    HfsPlus::format(
        &mut disk,
        &FormatOpts {
            journaled: true,
            ..Default::default()
        },
    )
    .unwrap();
    let mut header = [0; 1536];
    disk.read_at(0, &mut header).unwrap();
    assert_eq!(volume::be64(&header, 1136), 61_042_688);
    let mut adapter = Adapter::from_device(disk).unwrap();
    let handle = adapter
        .create(
            "\\profile-copy",
            Kind::File,
            OpenRequest {
                access: Access::ALL,
                ..Default::default()
            },
        )
        .unwrap();
    adapter
        .set_allocation_size(handle, 16 * 1024 * 1024)
        .unwrap();
    adapter.set_size(handle, 16 * 1024 * 1024).unwrap();
    let payload = vec![0x5c; 1024 * 1024];
    for part in 0..8 {
        let clock = Instant::now();
        assert_eq!(
            adapter
                .write(handle, part * payload.len() as u64, &payload, false, false)
                .unwrap(),
            payload.len()
        );
        println!(
            "TOSHIBA_BITMAP_CALLBACK part={part} stage=write elapsed_ns={}",
            clock.elapsed().as_nanos()
        );
        let clock = Instant::now();
        assert_eq!(
            adapter.file_info_with_ea(handle).unwrap().size,
            16 * 1024 * 1024
        );
        println!(
            "TOSHIBA_BITMAP_CALLBACK part={part} stage=file-info-ea elapsed_ns={}",
            clock.elapsed().as_nanos()
        );
    }
    let mut actual = vec![0; 16 * 1024 * 1024];
    assert_eq!(adapter.read(handle, 0, &mut actual).unwrap(), actual.len());
    assert!(actual[..8 * 1024 * 1024].iter().all(|&byte| byte == 0x5c));
    assert!(actual[8 * 1024 * 1024..].iter().all(|&byte| byte == 0));
    adapter.cleanup(handle, false).unwrap();
    adapter.close(handle).unwrap();
    adapter.shutdown().unwrap();
    println!(
        "TOSHIBA_BITMAP_SCOPE: exact2TB logical capacity,61MB bitmap, memory only; payload and zero-tail verified, NOT physical throughput"
    );
}
#[test]
fn bitmap_reads_follow_changed_sectors_and_committed_baseline() {
    for journaled in [false, true] {
        for reopened in [false, true] {
            let mut disk = Sparse {
                pages: BTreeMap::new(),
                position: 0,
                reads: vec![],
            };
            let mut fs = HfsPlus::format(
                &mut disk,
                &FormatOpts {
                    journaled,
                    ..Default::default()
                },
            )
            .unwrap();
            let mut expected = vec![0x51; 6003];
            fs.create_file(
                &mut disk,
                "/file",
                &mut expected.as_slice(),
                expected.len() as u64,
                0o644,
                501,
                20,
                1_700_000_000,
            )
            .unwrap();
            fs.flush(&mut disk).unwrap();
            fs.set_data_allocation(&mut disk, Path::new("/file"), 65536, false)
                .unwrap();
            if reopened {
                fs = HfsPlus::open(&mut disk).unwrap();
                // Initialize the lazy editor before measuring flush reads.
                fs.set_data_allocation(&mut disk, Path::new("/file"), 65536, false)
                    .unwrap();
            }
            let mut header = [0; 1536];
            disk.read_at(0, &mut header).unwrap();
            let bitmap_start = u64::from(volume::be32(&header, 1152)) * 4096;
            let bitmap_bytes = volume::be64(&header, 1136);
            assert_eq!(bitmap_bytes, 61_042_688);
            for iteration in 0..3 {
                disk.reads.clear();
                let patch = vec![0x70 + iteration; 4097];
                fs.edit_fork_with_publication(
                    &mut disk,
                    Path::new("/file"),
                    false,
                    ForkEdit::Write {
                        offset: expected.len() as u64,
                        bytes: &patch,
                    },
                    PublicationMetadata::default(),
                )
                .unwrap();
                expected.extend_from_slice(&patch);
                let map_read: usize = disk
                    .reads
                    .iter()
                    .filter(|(at, n)| {
                        *at >= bitmap_start && *at + *n as u64 <= bitmap_start + bitmap_bytes
                    })
                    .map(|(_, n)| *n)
                    .sum();
                assert!(
                    map_read <= 4096,
                    "entire allocation map reread: {map_read} bytes"
                );
                disk.reads.clear();
                fs.set_catalog_times(
                    2,
                    [None, None, Some(3_800_000_000 + u32::from(iteration)), None],
                )
                .unwrap();
                fs.flush(&mut disk).unwrap();
                assert!(
                    !disk
                        .reads
                        .iter()
                        .any(|(at, _)| *at >= bitmap_start && *at < bitmap_start + bitmap_bytes),
                    "successful flush did not advance bitmap baseline"
                );
            }
            let fs = HfsPlus::open(&mut disk).unwrap();
            let mut actual = vec![];
            fs.open_file_reader(&mut disk, "/file")
                .unwrap()
                .read_to_end(&mut actual)
                .unwrap();
            assert_eq!(actual, expected);
            volume::require_engine_access(&volume::inspect(&mut disk).unwrap()).unwrap();
        }
    }
}
