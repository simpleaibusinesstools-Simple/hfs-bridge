//! Large COW edits retain untouched bytes while copying adjacent source blocks
//! in bounded batches. The old per-allocation-block path fails the I/O bound.
use fstool::{
    block::{BlockDevice, MemoryBackend},
    fs::{
        Filesystem, OpenFlags,
        hfs_plus::{ForkEdit, FormatOpts, HfsPlus, PublicationMetadata},
    },
};
use hfs_bridge::volume;
use std::sync::{Arc, Mutex};
use std::{
    io::{self, Read, Seek, SeekFrom, Write},
    path::Path,
};
#[path = "support/fault_disk.rs"]
mod fault;

struct Counted {
    inner: MemoryBackend,
    reads: Vec<(u64, usize)>,
}
impl Read for Counted {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let offset = self.inner.stream_position()?;
        let size = self.inner.read(out)?;
        self.reads.push((offset, size));
        Ok(size)
    }
}
impl Write for Counted {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.inner.write(bytes)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}
impl Seek for Counted {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.inner.seek(pos)
    }
}
impl BlockDevice for Counted {
    fn block_size(&self) -> u32 {
        self.inner.block_size()
    }
    fn total_size(&self) -> u64 {
        self.inner.total_size()
    }
    fn sync(&mut self) -> fstool::Result<()> {
        self.inner.sync()
    }
}

struct CappedIo {
    inner: MemoryBackend,
    cap: usize,
    calls: Arc<Mutex<Vec<usize>>>,
}
impl Read for CappedIo {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        assert!(bytes.len() <= self.cap);
        assert_eq!(bytes.as_ptr() as usize % 4096, 0);
        self.calls.lock().unwrap().push(bytes.len());
        self.inner.read(bytes)
    }
}
impl Write for CappedIo {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        assert!(bytes.len() <= self.cap);
        assert_eq!(bytes.as_ptr() as usize % 4096, 0);
        self.calls.lock().unwrap().push(bytes.len());
        self.inner.write(bytes)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
impl Seek for CappedIo {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.inner.seek(pos)
    }
}
impl hfs_bridge::sector_device::DurableIo for CappedIo {
    fn sync_all(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn larger_copy_requests_preserve_verified_small_device_transfer_caps() {
    use hfs_bridge::sector_device::SectorSlice;
    for sector in [512, 4096] {
        for cap in [4096, 65536] {
            let calls = Arc::new(Mutex::new(Vec::new()));
            let io = CappedIo {
                inner: MemoryBackend::new(16 * 1024 * 1024),
                cap,
                calls: calls.clone(),
            };
            let mut disk =
                SectorSlice::new(io, 16 * 1024 * 1024, 0, 16 * 1024 * 1024, sector, true)
                    .unwrap()
                    .with_transfer_limit(cap)
                    .unwrap();
            let mut fs = HfsPlus::format(
                &mut disk,
                &FormatOpts {
                    journaled: true,
                    ..Default::default()
                },
            )
            .unwrap();
            let mut original = vec![0x51; 2 * 1024 * 1024 + 17];
            fs.create_file(
                &mut disk,
                "/file",
                &mut original.as_slice(),
                original.len() as u64,
                0o644,
                501,
                20,
                0,
            )
            .unwrap();
            fs.flush(&mut disk).unwrap();
            calls.lock().unwrap().clear();
            let payload = vec![0xB3; 1024 * 1024 + 37];
            fs.edit_fork_with_publication(
                &mut disk,
                Path::new("/file"),
                false,
                ForkEdit::Write {
                    offset: 7,
                    bytes: &payload,
                },
                PublicationMetadata::default(),
            )
            .unwrap();
            assert!(calls.lock().unwrap().contains(&cap));
            original[7..7 + payload.len()].copy_from_slice(&payload);
            let fs = HfsPlus::open(&mut disk).unwrap();
            let mut actual = Vec::new();
            fs.open_file_reader(&mut disk, "/file")
                .unwrap()
                .read_to_end(&mut actual)
                .unwrap();
            assert_eq!(actual, original);
        }
    }
}

#[test]
fn batched_committed_edits_preserve_prefix_suffix_and_gap() {
    for block in [512, 4096] {
        for journaled in [false, true] {
            let mut device = Counted {
                inner: MemoryBackend::new(16 * 1024 * 1024),
                reads: vec![],
            };
            let mut fs = HfsPlus::format(
                &mut device,
                &FormatOpts {
                    block_size: block,
                    journaled,
                    ..Default::default()
                },
            )
            .unwrap();
            let original: Vec<u8> = (0..1024 * 1024).map(|i| (i % 251) as u8).collect();
            fs.create_file(
                &mut device,
                "/large",
                &mut original.as_slice(),
                original.len() as u64,
                0o644,
                501,
                20,
                1_700_000_000,
            )
            .unwrap();
            fs.flush(&mut device).unwrap();
            let body = fs.catalog_record("/large").unwrap();
            let source = u64::from(volume::be32(&body, 104)) * u64::from(block);
            let blocks = volume::be32(&body, 108);
            assert!(u64::from(blocks) * u64::from(block) >= original.len() as u64);
            device.reads.clear();
            let offset = 7usize;
            let payload = vec![0xDC; 512 * 1024 + 37];
            fs.edit_fork_with_publication(
                &mut device,
                Path::new("/large"),
                false,
                ForkEdit::Write {
                    offset: offset as u64,
                    bytes: &payload,
                },
                PublicationMetadata::default(),
            )
            .unwrap();
            let source_end = source + original.len() as u64;
            let source_reads: Vec<_> = device
                .reads
                .iter()
                .filter(|(at, size)| *at >= source && *at + *size as u64 <= source_end)
                .collect();
            let touched = (offset + payload.len()).div_ceil(block as usize);
            assert!(
                source_reads.len() < touched / 4,
                "per-block reads were not batched: block={block}, calls={}, touched={touched}",
                source_reads.len()
            );
            assert!(source_reads.iter().all(|(_, size)| *size <= 1024 * 1024));
            assert_eq!(
                source_reads.len(),
                2,
                "only the two partial edge blocks require old bytes"
            );
            assert_eq!(
                source_reads.iter().map(|(_, size)| *size).sum::<usize>(),
                2 * block as usize
            );
            let mut expected = original.clone();
            expected[offset..offset + payload.len()].copy_from_slice(&payload);
            let mut actual = vec![];
            fs.open_file_reader(&mut device, "/large")
                .unwrap()
                .read_to_end(&mut actual)
                .unwrap();
            assert_eq!(actual, expected);
            fs.edit_fork_with_publication(
                &mut device,
                Path::new("/large"),
                false,
                ForkEdit::Write {
                    offset: expected.len() as u64 + 65_539,
                    bytes: b"tail",
                },
                PublicationMetadata::default(),
            )
            .unwrap();
            expected.resize(expected.len() + 65_539, 0);
            expected.extend_from_slice(b"tail");
            let mut actual = vec![];
            fs.open_file_reader(&mut device, "/large")
                .unwrap()
                .read_to_end(&mut actual)
                .unwrap();
            assert_eq!(actual, expected);
        }
    }
}

#[test]
fn fully_supplied_committed_blocks_need_no_old_payload_reads() {
    for block in [512, 4096] {
        let mut disk = Counted {
            inner: MemoryBackend::new(8 * 1024 * 1024),
            reads: vec![],
        };
        let mut fs = HfsPlus::format(
            &mut disk,
            &FormatOpts {
                block_size: block,
                journaled: true,
                ..Default::default()
            },
        )
        .unwrap();
        let mut expected = (0..4 * block as usize)
            .map(|i| (i % 251) as u8)
            .collect::<Vec<_>>();
        fs.create_file(
            &mut disk,
            "/file",
            &mut expected.as_slice(),
            expected.len() as u64,
            0o644,
            501,
            20,
            0,
        )
        .unwrap();
        fs.flush(&mut disk).unwrap();
        let body = fs.catalog_record("/file").unwrap();
        let old_start = u64::from(volume::be32(&body, 104)) * u64::from(block);
        disk.reads.clear();
        let payload = vec![0xD4; 2 * block as usize];
        fs.edit_fork_with_publication(
            &mut disk,
            Path::new("/file"),
            false,
            ForkEdit::Write {
                offset: u64::from(block),
                bytes: &payload,
            },
            PublicationMetadata::default(),
        )
        .unwrap();
        assert!(
            !disk
                .reads
                .iter()
                .any(|&(start, size)| start < old_start + u64::from(3 * block)
                    && start + size as u64 > old_start + u64::from(block)),
            "fully replaced old blocks should never be copied"
        );
        expected[block as usize..3 * block as usize].copy_from_slice(&payload);
        let mut actual = vec![];
        fs.open_file_reader(&mut disk, "/file")
            .unwrap()
            .read_to_end(&mut actual)
            .unwrap();
        assert_eq!(actual, expected);
    }
}

#[test]
fn full_block_replacement_stays_atomic_at_every_write_and_sync_failure() {
    let mut snapshots = 0;
    for block in [512, 4096] {
        let mut fixture = MemoryBackend::new(8 * 1024 * 1024);
        let mut fs = HfsPlus::format(
            &mut fixture,
            &FormatOpts {
                block_size: block,
                journaled: true,
                ..Default::default()
            },
        )
        .unwrap();
        let old = (0..4 * block as usize)
            .map(|i| (i % 251) as u8)
            .collect::<Vec<_>>();
        fs.create_file(
            &mut fixture,
            "/file",
            &mut old.as_slice(),
            old.len() as u64,
            0o644,
            501,
            20,
            0,
        )
        .unwrap();
        fs.flush(&mut fixture).unwrap();
        let before = fixture.into_bytes();
        let info = volume::be32(&before, 1036) as usize * block as usize;
        let journal = volume::be64(&before, info + 36) as usize;
        let payload = vec![0xD4; 2 * block as usize];
        let mut new = old.clone();
        new[block as usize..3 * block as usize].copy_from_slice(&payload);
        let attempt = |failure| {
            let mut disk = fault::Disk::new(&before);
            let observer = disk.clone();
            let mut fs = HfsPlus::open(&mut disk).unwrap();
            observer.arm(failure);
            let pass = fs
                .edit_fork_with_publication(
                    &mut disk,
                    Path::new("/file"),
                    false,
                    ForkEdit::Write {
                        offset: u64::from(block),
                        bytes: &payload,
                    },
                    PublicationMetadata::default(),
                )
                .is_ok();
            let count = observer.0.lock().unwrap().calls;
            drop(fs);
            assert_eq!(
                observer.0.lock().unwrap().calls,
                count,
                "failed replacement was retried on close"
            );
            (pass, observer, count)
        };
        let (pass, _, count) = attempt(None);
        assert!(pass);
        for failure in 0..count {
            let (pass, disk, _) = attempt(Some(failure));
            assert!(!pass);
            for policy in 0..6 {
                let mut recovered = MemoryBackend::from_bytes(disk.snapshot(policy, journal));
                let fs = HfsPlus::open(&mut recovered).unwrap();
                let mut actual = vec![];
                fs.open_file_reader(&mut recovered, "/file")
                    .unwrap()
                    .read_to_end(&mut actual)
                    .unwrap();
                assert!(
                    actual == old || actual == new,
                    "torn full-block replacement: block={block} failure={failure} policy={policy}"
                );
                snapshots += 1;
            }
        }
    }
    println!(
        "FULL_BLOCK_REPLACEMENT: {snapshots} persistence snapshots; old or complete new payload only"
    );
}

#[test]
fn reserved_tail_append_only_copies_the_partial_committed_eof_block() {
    for block in [512, 4096] {
        for journaled in [false, true] {
            let mut device = Counted {
                inner: MemoryBackend::new(16 * 1024 * 1024),
                reads: vec![],
            };
            let mut fs = HfsPlus::format(
                &mut device,
                &FormatOpts {
                    block_size: block,
                    journaled,
                    ..Default::default()
                },
            )
            .unwrap();
            let original: Vec<u8> = (0..6003).map(|i| (i % 251) as u8).collect();
            fs.create_file(
                &mut device,
                "/reserved",
                &mut original.as_slice(),
                original.len() as u64,
                0o644,
                501,
                20,
                1_700_000_000,
            )
            .unwrap();
            fs.flush(&mut device).unwrap();
            fs.set_data_allocation(&mut device, Path::new("/reserved"), 1024 * 1024, false)
                .unwrap();
            let body = fs.catalog_record("/reserved").unwrap();
            let source = u64::from(volume::be32(&body, 104)) * u64::from(block);
            let source_end = source + u64::from(volume::be32(&body, 108)) * u64::from(block);
            device.reads.clear();
            let payload = vec![0xB7; 131_113];
            fs.edit_fork_with_publication(
                &mut device,
                Path::new("/reserved"),
                false,
                ForkEdit::Write {
                    offset: original.len() as u64,
                    bytes: &payload,
                },
                PublicationMetadata::default(),
            )
            .unwrap();
            let reads: Vec<_> = device
                .reads
                .iter()
                .filter(|(at, size)| *at >= source && *at + *size as u64 <= source_end)
                .collect();
            assert_eq!(
                reads.iter().map(|(_, size)| *size).sum::<usize>(),
                block as usize,
                "reserved tail was copied despite lying above committed EOF"
            );
            let mut expected = original;
            expected.extend_from_slice(&payload);
            let mut actual = vec![];
            fs.open_file_reader(&mut device, "/reserved")
                .unwrap()
                .read_to_end(&mut actual)
                .unwrap();
            assert_eq!(actual, expected);
            // A subsequent growth must zero the reserved gap, including bytes
            // that may have been used by a previous interrupted tail write.
            fs.edit_fork_with_publication(
                &mut device,
                Path::new("/reserved"),
                false,
                ForkEdit::Write {
                    offset: expected.len() as u64 + 70_017,
                    bytes: b"end",
                },
                PublicationMetadata::default(),
            )
            .unwrap();
            expected.resize(expected.len() + 70_017, 0);
            expected.extend_from_slice(b"end");
            let mut actual = vec![];
            fs.open_file_reader(&mut device, "/reserved")
                .unwrap()
                .read_to_end(&mut actual)
                .unwrap();
            assert_eq!(actual, expected);
        }
    }
}

// Exercise the retained editor's publication boundary, not just one fresh
// callback. Losing power must expose a complete old or complete new logical
// payload even when reserved blocks have been filled before publication.
#[test]
fn reserved_tail_interruptions_preserve_committed_bytes_across_sync_and_shrink() {
    let mut snapshots = 0;
    for block in [512, 4096] {
        let mut fixture = MemoryBackend::new(8 * 1024 * 1024);
        let mut fs = HfsPlus::format(
            &mut fixture,
            &FormatOpts {
                block_size: block,
                journaled: true,
                ..Default::default()
            },
        )
        .unwrap();
        let original: Vec<u8> = (0..6003).map(|i| (i % 251) as u8).collect();
        fs.create_file(
            &mut fixture,
            "/reserved",
            &mut original.as_slice(),
            original.len() as u64,
            0o644,
            501,
            20,
            1_700_000_000,
        )
        .unwrap();
        fs.flush(&mut fixture).unwrap();
        fs.set_data_allocation(&mut fixture, Path::new("/reserved"), 128 * 1024, false)
            .unwrap();
        let before = fixture.as_slice().to_vec();
        let info = volume::be32(&before, 1036) as usize * block as usize;
        let journal = volume::be64(&before, info + 36) as usize;
        for scenario in 0..3 {
            let attempt = |failure| {
                let mut disk = fault::Disk::new(&before);
                let observer = disk.clone();
                let mut fs = HfsPlus::open(&mut disk).unwrap();
                let mut handle = fs
                    .open_file_rw(
                        &mut disk,
                        Path::new("/reserved"),
                        OpenFlags::default(),
                        None,
                    )
                    .unwrap();
                let mut old = original.clone();
                if scenario == 1 {
                    handle.seek(SeekFrom::End(0)).unwrap();
                    handle.write_all(&vec![0x93; 16_417]).unwrap();
                    handle.sync().unwrap();
                    old.extend_from_slice(&vec![0x93; 16_417]);
                }
                observer.arm(failure);
                let mut new = old.clone();
                let succeeded = (|| -> Result<(), Box<dyn std::error::Error>> {
                    match scenario {
                        0 => {
                            handle.seek(SeekFrom::End(0))?;
                            handle.write_all(&vec![0xB6; 16_417])?;
                            new.extend_from_slice(&vec![0xB6; 16_417]);
                        }
                        1 => {
                            handle.seek(SeekFrom::Start(9000))?;
                            handle.write_all(&[0xC4; 999])?;
                            new[9000..9999].fill(0xC4);
                        }
                        2 => {
                            handle.set_len(37)?;
                            handle.set_len(6003)?;
                            handle.seek(SeekFrom::Start(5800))?;
                            handle.write_all(&[0xD7; 37])?;
                            new[37..].fill(0);
                            new[5800..5837].fill(0xD7);
                        }
                        _ => unreachable!(),
                    }
                    handle.sync()?;
                    Ok(())
                })()
                .is_ok();
                let calls = observer.0.lock().unwrap().calls;
                drop(handle);
                assert_eq!(
                    observer.0.lock().unwrap().calls,
                    calls,
                    "close retried a failed publication"
                );
                (succeeded, observer, old, new)
            };
            let (succeeded, completed, old, new) = attempt(None);
            assert!(succeeded);
            let count = completed.0.lock().unwrap().calls;
            for failure in 0..count {
                let (succeeded, disk, observed_old, _) = attempt(Some(failure));
                assert!(!succeeded);
                assert_eq!(observed_old, old);
                for policy in 0..6 {
                    let mut recovered = MemoryBackend::from_bytes(disk.snapshot(policy, journal));
                    let fs = HfsPlus::open(&mut recovered).unwrap();
                    let mut actual = Vec::new();
                    fs.open_file_reader(&mut recovered, "/reserved")
                        .unwrap()
                        .read_to_end(&mut actual)
                        .unwrap();
                    assert!(
                        actual == old || actual == new,
                        "partial reserved payload: block={block} scenario={scenario} failure={failure} policy={policy}"
                    );
                    snapshots += 1;
                }
            }
        }
    }
    println!("RESERVED_TAIL_RECOVERY: {snapshots} crash snapshots; six retained-editor scenarios");
}
