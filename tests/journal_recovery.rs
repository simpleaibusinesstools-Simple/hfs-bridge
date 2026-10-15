//! Independent wire encoders and explicit no-write guards for recovery.
use fstool::{
    block::{BlockDevice, MemoryBackend},
    fs::hfs_plus::{FormatOpts, HfsPlus, preflight_replay, replay_journal},
};
use hfs_bridge::{recovery, volume};
use std::io::{self, Cursor, Read, Seek, SeekFrom, Write};

const SIZE: usize = 32 * 1024 * 1024;
const TARGET: usize = 24 * 1024 * 1024;
const BLHDR: usize = 8192;

struct Disk {
    data: Cursor<Vec<u8>>,
    writes: usize,
    syncs: usize,
    max_read: usize,
    deny_write: bool,
    fail_at: Option<usize>,
}
impl Disk {
    fn new(bytes: Vec<u8>, deny_write: bool) -> Self {
        Self {
            data: Cursor::new(bytes),
            writes: 0,
            syncs: 0,
            max_read: 0,
            deny_write,
            fail_at: None,
        }
    }
    fn boundary(&mut self) -> io::Result<()> {
        if self.fail_at == Some(self.writes + self.syncs) {
            return Err(io::Error::other("injected recovery interruption"));
        }
        Ok(())
    }
}
impl Read for Disk {
    fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
        self.max_read = self.max_read.max(b.len());
        self.data.read(b)
    }
}
impl Seek for Disk {
    fn seek(&mut self, p: SeekFrom) -> io::Result<u64> {
        self.data.seek(p)
    }
}
impl Write for Disk {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        self.boundary()?;
        self.writes += 1;
        if self.deny_write {
            return Err(io::Error::other("writes forbidden"));
        }
        self.data.write(b)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.boundary()?;
        self.syncs += 1;
        if self.deny_write {
            return Err(io::Error::other("sync forbidden"));
        }
        Ok(())
    }
}
impl BlockDevice for Disk {
    fn block_size(&self) -> u32 {
        512
    }
    fn total_size(&self) -> u64 {
        self.data.get_ref().len() as u64
    }
    fn sync(&mut self) -> fstool::Result<()> {
        Ok(self.flush()?)
    }
}

struct Wire {
    bytes: Vec<u8>,
    journal: usize,
    jib: usize,
    ring: usize,
    little: bool,
}
impl Wire {
    fn new(little: bool) -> Self {
        let mut device = MemoryBackend::new(SIZE as u64);
        HfsPlus::format(
            &mut device,
            &FormatOpts {
                journaled: true,
                ..Default::default()
            },
        )
        .unwrap();
        let bytes = device.as_slice().to_vec();
        let jib = volume::be32(&bytes, 1036) as usize * volume::be32(&bytes, 1064) as usize;
        let journal = volume::be64(&bytes, jib + 36) as usize;
        let ring = volume::be64(&bytes, jib + 44) as usize;
        Self {
            bytes,
            journal,
            jib,
            ring,
            little,
        }
    }
    fn number(&mut self, off: usize, value: u64, width: usize) {
        let encoded = if self.little {
            value.to_le_bytes()
        } else {
            value.to_be_bytes()
        };
        self.bytes[off..off + width].copy_from_slice(if self.little {
            &encoded[..width]
        } else {
            &encoded[8 - width..]
        });
    }
    fn header(&mut self, start: usize, end: usize) {
        self.bytes[self.journal..self.journal + 512].fill(0);
        for (off, n, width) in [
            (0, 0x4a4e4c78, 4),
            (4, 0x12345678, 4),
            (8, start as u64, 8),
            (16, end as u64, 8),
            (24, self.ring as u64, 8),
            (32, BLHDR as u64, 4),
            (40, 512, 4),
            (44, 8, 4),
        ] {
            self.number(self.journal + off, n, width);
        }
        let c = volume::journal_checksum(&self.bytes[self.journal..self.journal + 44]);
        self.number(self.journal + 36, u64::from(c), 4);
    }
    fn advance(&self, off: usize, by: usize) -> usize {
        512 + (off - 512 + by) % (self.ring - 512)
    }
    fn tx(&mut self, at: usize, sequence: u32, flags: u32, blocks: &[(u64, Vec<u8>)]) -> usize {
        let total = BLHDR + blocks.iter().map(|(_, b)| b.len()).sum::<usize>();
        let mut tx = vec![0; total];
        let put = |buf: &mut [u8], off: usize, value: u64, width: usize| {
            let b = if self.little {
                value.to_le_bytes()
            } else {
                value.to_be_bytes()
            };
            buf[off..off + width].copy_from_slice(if self.little {
                &b[..width]
            } else {
                &b[8 - width..]
            });
        };
        put(&mut tx, 0, (BLHDR / 16 - 1) as u64, 2);
        put(&mut tx, 2, (blocks.len() + 1) as u64, 2);
        put(&mut tx, 4, total as u64, 4);
        put(&mut tx, 12, u64::from(flags), 4);
        put(&mut tx, 28, u64::from(sequence), 4);
        let mut payload = BLHDR;
        for (i, (target, data)) in blocks.iter().enumerate() {
            let off = 32 + i * 16;
            put(&mut tx, off, *target, 8);
            put(&mut tx, off + 8, data.len() as u64, 4);
            put(
                &mut tx,
                off + 12,
                u64::from(volume::journal_checksum(data)),
                4,
            );
            tx[payload..payload + data.len()].copy_from_slice(data);
            payload += data.len();
        }
        let c = volume::journal_checksum(&tx[..32]);
        put(&mut tx, 8, u64::from(c), 4);
        for (i, b) in tx.into_iter().enumerate() {
            let off = self.advance(at, i);
            self.bytes[self.journal + off] = b;
        }
        self.advance(at, total)
    }
    fn fix_list_checksum(&mut self, at: usize) {
        let off = self.journal + at;
        self.number(off + 8, 0, 4);
        let c = volume::journal_checksum(&self.bytes[off..off + 32]);
        self.number(off + 8, u64::from(c), 4);
    }
    fn pending(little: bool, wrap: bool) -> Self {
        let mut wire = Self::new(little);
        let start = if wrap { wire.ring - 4096 } else { 512 };
        let next = wire.tx(
            start,
            7,
            3,
            &[
                (TARGET as u64 / 512, vec![0x44; 512]),
                (u64::MAX, vec![0x77; 512]),
            ],
        );
        let end = wire.tx(
            next,
            8,
            3,
            &[
                (TARGET as u64 / 512, vec![0x99; 512]),
                ((TARGET + 512) as u64 / 512, vec![0x66; 512]),
            ],
        );
        wire.header(start, end);
        wire
    }
}

#[test]
fn preflight_and_replay_are_bounded_read_only_then_ordered_and_idempotent() {
    for little in [false, true] {
        for wrap in [false, true] {
            let wire = Wire::pending(little, wrap);
            let original = wire.bytes;
            let mut disk = Disk::new(original.clone(), true);
            let summary = preflight_replay(&mut disk).unwrap();
            assert_eq!(
                (summary.block_lists, summary.blocks, summary.payload_bytes),
                (2, 3, 2048)
            );
            assert_eq!((disk.writes, disk.syncs), (0, 0));
            assert_eq!(disk.data.get_ref(), &original);
            disk.deny_write = false;
            assert_eq!(replay_journal(&mut disk).unwrap(), summary);
            assert_eq!(&disk.data.get_ref()[TARGET..TARGET + 512], &[0x99; 512]);
            assert_eq!(
                &disk.data.get_ref()[TARGET + 512..TARGET + 1024],
                &[0x66; 512]
            );
            assert_eq!((disk.writes, disk.syncs), (4, 2));
            let replayed = disk.data.get_ref().clone();
            let counts = (disk.writes, disk.syncs);
            assert_eq!(replay_journal(&mut disk).unwrap().blocks, 0);
            assert_eq!((disk.writes, disk.syncs), counts);
            assert_eq!(disk.data.get_ref(), &replayed);
            assert!(disk.max_read <= BLHDR);
        }
    }
}

#[test]
fn a_corrupt_late_payload_does_not_apply_earlier_blocks() {
    for little in [false, true] {
        for wrap in [false, true] {
            let mut wire = Wire::pending(little, wrap);
            let end = if little {
                u64::from_le_bytes(
                    wire.bytes[wire.journal + 16..wire.journal + 24]
                        .try_into()
                        .unwrap(),
                )
            } else {
                volume::be64(&wire.bytes, wire.journal + 16)
            } as usize;
            let last = 512 + (end - 512 + wire.ring - 512 - 1) % (wire.ring - 512);
            wire.bytes[wire.journal + last] ^= 1;
            let mut disk = Disk::new(wire.bytes.clone(), false);
            assert!(
                preflight_replay(&mut disk)
                    .unwrap_err()
                    .to_string()
                    .contains("checksum")
            );
            assert!(replay_journal(&mut disk).is_err());
            assert_eq!((disk.writes, disk.syncs), (0, 0));
            assert_eq!(disk.data.get_ref(), &wire.bytes);
        }
    }
}

#[test]
fn malformed_lists_and_dangerous_targets_fail_before_any_write() {
    for case in 0..12 {
        let mut wire = Wire::pending(false, false);
        let at = 512 + BLHDR + 1024;
        let off = wire.journal + at;
        match case {
            0 => wire.number(off, 0, 2),
            1 => wire.number(off + 2, 600, 2),
            2 => wire.number(off + 12, 4, 4),
            3 => wire.number(off + 28, 99, 4),
            4 => wire.number(off + 4, 512, 4),
            5 => wire.number(off + 40, 511, 4),
            6 => wire.number(off + 40, 0, 4),
            7 => wire.number(off + 32, SIZE as u64 / 512, 8),
            8 => wire.number(off + 32, u64::MAX - 1, 8),
            9 => wire.number(off + 32, wire.journal as u64 / 512, 8),
            10 => wire.number(off + 32, wire.jib as u64 / 512, 8),
            11 => wire.number(off + 2, 2, 2), // unaccounted final payload
            _ => unreachable!(),
        }
        wire.fix_list_checksum(at);
        let mut disk = Disk::new(wire.bytes.clone(), false);
        assert!(preflight_replay(&mut disk).is_err(), "case {case}");
        assert!(replay_journal(&mut disk).is_err(), "case {case}");
        assert_eq!((disk.writes, disk.syncs), (0, 0), "case {case}");
        assert_eq!(disk.data.get_ref(), &wire.bytes);
    }
}

#[test]
fn interrupted_replay_keeps_the_committed_window_until_home_sync_and_can_restart() {
    let wire = Wire::pending(false, true);
    let mut complete = Disk::new(wire.bytes.clone(), false);
    replay_journal(&mut complete).unwrap();
    let expected = complete.data.into_inner();
    for fail_at in 0..6 {
        let mut disk = Disk::new(wire.bytes.clone(), false);
        disk.fail_at = Some(fail_at);
        assert!(replay_journal(&mut disk).is_err());
        disk.fail_at = None;
        replay_journal(&mut disk).unwrap();
        assert_eq!(disk.data.get_ref(), &expected);
    }
}

#[test]
fn recovery_copy_refuses_corruption_before_creation_and_preserves_source_and_existing_output() {
    let folder = std::env::temp_dir().join(format!(
        "hfs-journal-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&folder).unwrap();
    let wire = Wire::pending(false, false);
    let source = folder.join("source.img");
    let output = folder.join("recovered.img");
    std::fs::write(&source, &wire.bytes).unwrap();
    let result = recovery::recover_copy(&source, &output, 0, None).unwrap();
    assert_eq!(result.replay.blocks, 3);
    assert!(result.engine_accessible);
    assert_eq!(std::fs::read(&source).unwrap(), wire.bytes);
    let recovered = std::fs::read(&output).unwrap();
    assert!(recovery::recover_copy(&source, &output, 0, None).is_err());
    assert_eq!(std::fs::read(&output).unwrap(), recovered);
    let mut corrupt = wire.bytes;
    corrupt[wire.journal + 512 + BLHDR + 1024 + BLHDR] ^= 1;
    let bad = folder.join("bad.img");
    let absent = folder.join("absent.img");
    std::fs::write(&bad, &corrupt).unwrap();
    assert!(recovery::recover_copy(&bad, &absent, 0, None).is_err());
    assert!(!absent.exists());
    assert_eq!(std::fs::read(&bad).unwrap(), corrupt);
}

#[test]
fn oversized_payload_or_headers_are_refused_before_allocating_them() {
    for header in [false, true] {
        let mut wire = Wire::new(false);
        wire.journal = 8 * 1024 * 1024;
        wire.ring = 23 * 1024 * 1024;
        wire.bytes[wire.jib + 36..wire.jib + 44]
            .copy_from_slice(&(wire.journal as u64).to_be_bytes());
        wire.bytes[wire.jib + 44..wire.jib + 52].copy_from_slice(&(wire.ring as u64).to_be_bytes());
        let used = BLHDR + 16 * 1024 * 1024 + 512;
        wire.tx(512, 7, 3, &[(TARGET as u64 / 512, vec![0x55; 512])]);
        wire.header(512, 512 + used);
        if header {
            wire.number(wire.journal + 32, 2 * 1024 * 1024, 4);
            wire.number(wire.journal + 36, 0, 4);
            let c = volume::journal_checksum(&wire.bytes[wire.journal..wire.journal + 44]);
            wire.number(wire.journal + 36, u64::from(c), 4);
        } else {
            wire.number(wire.journal + 512 + 4, used as u64, 4);
            wire.fix_list_checksum(512);
        }
        let mut disk = Disk::new(wire.bytes, false);
        assert!(
            preflight_replay(&mut disk)
                .unwrap_err()
                .to_string()
                .contains("limit")
        );
        assert_eq!((disk.writes, disk.syncs), (0, 0));
        assert!(disk.max_read <= BLHDR);
    }
}

#[test]
fn equivalent_empty_cursors_and_native_legacy_checksums_are_handled_without_false_recovery() {
    for little in [false, true] {
        let mut wire = Wire::new(little);
        wire.header(wire.ring, 512);
        let mut disk = Disk::new(wire.bytes.clone(), true);
        assert!(matches!(
            volume::inspect(&mut disk).unwrap().journal,
            volume::Journal::Clean { .. }
        ));
        assert_eq!(replay_journal(&mut disk).unwrap().blocks, 0);
        let vh = fstool::fs::hfs_plus::volume_header::read_volume_header(&mut disk).unwrap();
        assert!(
            !fstool::fs::hfs_plus::JournalLog::load(&mut disk, &vh)
                .unwrap()
                .unwrap()
                .is_dirty()
        );
        assert_eq!((disk.writes, disk.syncs), (0, 0));
        assert_eq!(disk.data.get_ref(), &wire.bytes);

        // Apple treats a stored per-block checksum of zero as unavailable.
        // Such payloads retain all geometry/target/accounting checks.
        let mut legacy = Wire::pending(little, false);
        legacy.number(legacy.journal + 512 + 44, 0, 4);
        let mut disk = Disk::new(legacy.bytes, false);
        assert_eq!(replay_journal(&mut disk).unwrap().blocks, 3);
        assert_eq!(&disk.data.get_ref()[TARGET..TARGET + 512], &[0x99; 512]);
    }
}

#[test]
fn recovery_preserves_unclean_flags_and_normal_access_remains_refused() {
    let folder = std::env::temp_dir().join(format!(
        "hfs-unclean-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&folder).unwrap();
    let mut wire = Wire::pending(true, true);
    for offset in [1024, SIZE - 1024] {
        let flags = volume::be32(&wire.bytes, offset + 4) & !volume::UNMOUNTED;
        wire.bytes[offset + 4..offset + 8].copy_from_slice(&flags.to_be_bytes());
    }
    let source = folder.join("source.img");
    let output = folder.join("recovered.img");
    std::fs::write(&source, &wire.bytes).unwrap();
    let result = recovery::recover_copy(&source, &output, 0, None).unwrap();
    assert!(!result.engine_accessible);
    let mut recovered = hfs_bridge::image::Image::read_only(&output, 0, None).unwrap();
    let inspection = volume::inspect(&mut recovered).unwrap();
    assert!(matches!(inspection.journal, volume::Journal::Clean { .. }));
    assert_eq!(inspection.header.attributes & volume::UNMOUNTED, 0);
    assert!(hfs_bridge::engine::open_checked(&mut recovered).is_err());
    assert_eq!(std::fs::read(&source).unwrap(), wire.bytes);
}

#[test]
fn sliced_recovery_preserves_outer_bytes_and_rejects_unsupported_sources() {
    let folder = std::env::temp_dir().join(format!(
        "hfs-sliced-recovery-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&folder).unwrap();
    let wire = Wire::pending(false, true);
    let mut container = vec![0x5a; 4096];
    container.extend_from_slice(&wire.bytes);
    container.extend_from_slice(&[0xa5; 8192]);
    let source = folder.join("container.img");
    let output = folder.join("recovered.img");
    std::fs::write(&source, &container).unwrap();
    assert!(
        recovery::recover_copy(&source, &output, 4096, Some(SIZE as u64))
            .unwrap()
            .engine_accessible
    );
    let copied = std::fs::read(&output).unwrap();
    assert_eq!(&copied[..4096], &[0x5a; 4096]);
    assert_eq!(&copied[4096 + SIZE..], &[0xa5; 8192]);
    assert_eq!(std::fs::read(&source).unwrap(), container);
    for inconsistent in [0, 1 << 11, 1 << 14, 1 << 29, 1 << 30] {
        let mut bytes = wire.bytes.clone();
        for offset in [1024, SIZE - 1024] {
            let original = volume::be32(&bytes, offset + 4);
            let flags = if inconsistent != 0 {
                original | inconsistent
            } else {
                original & !volume::JOURNALED
            };
            bytes[offset + 4..offset + 8].copy_from_slice(&flags.to_be_bytes());
        }
        let input = folder.join(format!("refused-{inconsistent}.img"));
        let absent = folder.join(format!("absent-{inconsistent}.img"));
        std::fs::write(&input, &bytes).unwrap();
        assert!(recovery::recover_copy(&input, &absent, 0, None).is_err());
        assert!(!absent.exists());
        assert_eq!(std::fs::read(&input).unwrap(), bytes);
    }
}
