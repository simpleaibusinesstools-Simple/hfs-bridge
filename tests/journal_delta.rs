use fstool::block::{BlockDevice, MemoryBackend};
use fstool::fs::hfs_plus::{FormatOpts, HfsPlus, JournalLog};
use hfs_bridge::volume;
use std::io::{self, Read, Seek, SeekFrom, Write};

#[path = "support/journal_geometry.rs"]
mod journal_geometry;

#[test]
fn larger_journal_sectors_preserve_both_volume_header_neighbors() {
    for sector in [512, 1024, 2048, 4096] {
        for little in [false, true] {
            for wrap in [false, true] {
                let mut bytes = fixture().as_slice().to_vec();
                journal_geometry::convert_empty(&mut bytes, sector, little, wrap);
                journal_geometry::seed_header_neighbors(&mut bytes);
                let neighbors = journal_geometry::header_neighbors(&bytes);
                let mut disk = MemoryBackend::with_block_size(bytes.len() as u64, sector as u32);
                disk.write_all(&bytes).unwrap();
                let before = volume::inspect(&mut disk).unwrap().header;
                let mut fs = HfsPlus::open(&mut disk).unwrap();
                fs.create_dir(&mut disk, "/New Folder", 0o755, 0, 0, 1_700_000_000)
                    .unwrap();
                fs.flush(&mut disk).unwrap();
                assert_eq!(
                    journal_geometry::header_neighbors(disk.as_slice()),
                    neighbors
                );
                let after = volume::inspect(&mut disk).unwrap();
                assert_eq!(after.header.folders, before.folders + 1);
                assert_eq!(after.header.write_count, before.write_count + 1);
                assert!(after.alternate_matches);
                assert!(matches!(after.journal, volume::Journal::Clean { .. }));
                let reopened = HfsPlus::open(&mut disk).unwrap();
                assert!(reopened.catalog_record("/New Folder").is_ok());
            }
        }
    }
}

fn fixture() -> MemoryBackend {
    let mut disk = MemoryBackend::new(32 * 1024 * 1024);
    HfsPlus::format(
        &mut disk,
        &FormatOpts {
            journaled: true,
            ..Default::default()
        },
    )
    .unwrap();
    disk
}

#[test]
fn later_overlapping_writes_restore_original_sectors_without_publishing_earlier_data() {
    let mut disk = fixture();
    let header = volume::inspect(&mut disk).unwrap().header;
    let vh = fstool::fs::hfs_plus::volume_header::VolumeHeader::decode(
        disk.as_slice()[1024..1536].try_into().unwrap(),
    )
    .unwrap();
    let target = 16 * 1024 * 1024u64;
    let original = disk.as_slice()[target as usize..target as usize + 1024].to_vec();
    let mut log = JournalLog::load(&mut disk, &vh).unwrap().unwrap();
    assert!(
        log.add_changed_writes(
            &mut disk,
            vec![
                (target, vec![0x55; 1024]),
                (target + 512, original[512..].to_vec()),
            ]
        )
        .unwrap()
    );
    log.commit(&mut disk).unwrap();
    assert_eq!(
        &disk.as_slice()[target as usize..target as usize + 512],
        &[0x55; 512]
    );
    assert_eq!(
        &disk.as_slice()[target as usize + 512..target as usize + 1024],
        &original[512..]
    );
    assert_eq!(
        volume::inspect(&mut disk).unwrap().header.free_blocks,
        header.free_blocks
    );
}

#[test]
fn unchanged_final_batch_does_not_advance_or_rewrite_the_journal() {
    let mut disk = fixture();
    let before = disk.as_slice().to_vec();
    let vh = fstool::fs::hfs_plus::volume_header::VolumeHeader::decode(
        before[1024..1536].try_into().unwrap(),
    )
    .unwrap();
    let target = 16 * 1024 * 1024u64;
    let mut log = JournalLog::load(&mut disk, &vh).unwrap().unwrap();
    assert!(
        !log.add_changed_writes(
            &mut disk,
            vec![
                (target, vec![0x55; 512]),
                (
                    target,
                    before[target as usize..target as usize + 512].to_vec()
                ),
            ]
        )
        .unwrap()
    );
    log.commit(&mut disk).unwrap();
    assert!(disk.as_slice() == before);

    // A valid committed record made pending again must be replayed before
    // comparing even an otherwise unchanged final batch.
    assert!(
        log.add_changed_writes(&mut disk, vec![(target, vec![0x99; 512])])
            .unwrap()
    );
    log.commit(&mut disk).unwrap();
    let mut pending = disk.as_slice().to_vec();
    let jib = volume::be32(&pending, 1036) as usize * volume::be32(&pending, 1064) as usize;
    let journal = volume::be64(&pending, jib + 36) as usize;
    pending[journal + 8..journal + 16].copy_from_slice(&512u64.to_be_bytes());
    pending[journal + 36..journal + 40].fill(0);
    let checksum = volume::journal_checksum(&pending[journal..journal + 44]);
    pending[journal + 36..journal + 40].copy_from_slice(&checksum.to_be_bytes());
    let mut disk = MemoryBackend::from_bytes(pending.clone());
    let mut log = JournalLog::load(&mut disk, &vh).unwrap().unwrap();
    assert!(log.is_dirty());
    assert!(
        log.add_changed_writes(&mut disk, vec![(target, vec![0x99; 512])])
            .is_err()
    );
    assert!(disk.as_slice() == pending);
}

#[test]
fn unchanged_bytes_cannot_hide_unaligned_out_of_bounds_or_journal_targets() {
    let mut disk = fixture();
    let before = disk.as_slice().to_vec();
    let vh = fstool::fs::hfs_plus::volume_header::VolumeHeader::decode(
        before[1024..1536].try_into().unwrap(),
    )
    .unwrap();
    let jib = volume::be32(&before, 1036) as usize * volume::be32(&before, 1064) as usize;
    let journal = volume::be64(&before, jib + 36) as usize;
    for (offset, bytes) in [
        (16 * 1024 * 1024 + 1, vec![0; 512]),
        (16 * 1024 * 1024, vec![0; 511]),
        (before.len() as u64, vec![0; 512]),
        (u64::MAX - 511, vec![0; 512]),
        (journal as u64, before[journal..journal + 512].to_vec()),
    ] {
        let mut log = JournalLog::load(&mut disk, &vh).unwrap().unwrap();
        assert!(
            log.add_changed_writes(&mut disk, vec![(offset, bytes)])
                .is_err()
        );
        assert!(disk.as_slice() == before);
    }
}

struct ComparisonDisk {
    disk: MemoryBackend,
    reads: usize,
    largest_read: usize,
    writes: usize,
    fail_read: Option<usize>,
}
impl Read for ComparisonDisk {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.reads += 1;
        self.largest_read = self.largest_read.max(bytes.len());
        if self.fail_read == Some(self.reads) {
            return Err(io::Error::other("injected comparison read failure"));
        }
        self.disk.read(bytes)
    }
}
impl Write for ComparisonDisk {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.writes += 1;
        self.disk.write(bytes)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.disk.flush()
    }
}
impl Seek for ComparisonDisk {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        self.disk.seek(position)
    }
}
impl BlockDevice for ComparisonDisk {
    fn block_size(&self) -> u32 {
        self.disk.block_size()
    }
    fn total_size(&self) -> u64 {
        self.disk.total_size()
    }
    fn sync(&mut self) -> fstool::Result<()> {
        self.disk.sync()
    }
}

#[test]
fn large_metadata_comparison_has_bounded_reads_and_preserves_sector_deltas() {
    for sector in [512, 4096] {
        for little in [false, true] {
            for wrap in [false, true] {
                let mut bytes = fixture().as_slice().to_vec();
                journal_geometry::convert_empty(&mut bytes, sector, little, wrap);
                let vh = fstool::fs::hfs_plus::volume_header::VolumeHeader::decode(
                    bytes[1024..1536].try_into().unwrap(),
                )
                .unwrap();
                let mut disk = ComparisonDisk {
                    disk: MemoryBackend::from_bytes(bytes),
                    reads: 0,
                    largest_read: 0,
                    writes: 0,
                    fail_read: None,
                };
                let target = 16 * 1024 * 1024u64;
                let length = 1024 * 1024 + 3 * sector;
                let original =
                    disk.disk.as_slice()[target as usize..target as usize + length].to_vec();
                let mut expected = original.clone();
                for index in [
                    0,
                    65536 - sector,
                    65536,
                    65536 + sector,
                    131072 + 5 * sector,
                    length - sector,
                ] {
                    expected[index..index + sector].fill(0x53);
                }
                let mut log = JournalLog::load(&mut disk, &vh).unwrap().unwrap();
                disk.reads = 0;
                disk.largest_read = 0;
                // Later overlap restores one changed sector to its old bytes.
                let desired = expected.clone();
                expected[65536..65536 + sector].copy_from_slice(&original[65536..65536 + sector]);
                assert!(
                    log.add_changed_writes(
                        &mut disk,
                        vec![
                            (target, desired),
                            (target + 65536, original[65536..65536 + sector].to_vec()),
                        ]
                    )
                    .unwrap()
                );
                assert_eq!(disk.writes, 0, "comparison must not publish anything");
                assert!(
                    disk.reads <= 32,
                    "one MiB metadata needed {} device reads",
                    disk.reads
                );
                eprintln!(
                    "JOURNAL_COMPARE: sector={sector} little={little} wrap={wrap} bytes={length} reads={}",
                    disk.reads
                );
                assert!(
                    disk.largest_read <= 64 * 1024,
                    "comparison scratch must stay bounded"
                );
                log.commit(&mut disk).unwrap();
                assert_eq!(
                    &disk.disk.as_slice()[target as usize..target as usize + length],
                    expected.as_slice()
                );
                let after = disk.disk.as_slice().to_vec();
                let mut log = JournalLog::load(&mut disk, &vh).unwrap().unwrap();
                disk.reads = 0;
                assert!(
                    !log.add_changed_writes(&mut disk, vec![(target, expected)])
                        .unwrap()
                );
                assert!(disk.reads <= 32);
                log.commit(&mut disk).unwrap();
                assert_eq!(disk.disk.as_slice(), after);
            }
        }
    }
}

#[test]
fn failed_large_metadata_comparison_never_writes_partial_results() {
    let source = fixture().as_slice().to_vec();
    let vh = fstool::fs::hfs_plus::volume_header::VolumeHeader::decode(
        source[1024..1536].try_into().unwrap(),
    )
    .unwrap();
    for failure in [1, 2, 3] {
        let mut disk = ComparisonDisk {
            disk: MemoryBackend::from_bytes(source.clone()),
            reads: 0,
            largest_read: 0,
            writes: 0,
            fail_read: None,
        };
        let mut log = JournalLog::load(&mut disk, &vh).unwrap().unwrap();
        disk.reads = 0;
        disk.fail_read = Some(failure);
        assert!(
            log.add_changed_writes(&mut disk, vec![(16 * 1024 * 1024, vec![0x17; 3 * 65536])])
                .is_err()
        );
        assert_eq!(disk.writes, 0);
        assert_eq!(disk.disk.as_slice(), source);
    }
}
