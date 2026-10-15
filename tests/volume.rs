use fstool::block::BlockDevice;
use hfs_bridge::volume::{self, JOURNALED, Journal, UNMOUNTED};
use std::io::{Cursor, Read, Seek, SeekFrom, Write};

// Independently assembled TN1150 bytes, not produced by the candidate engine.
struct Bytes(Cursor<Vec<u8>>);
impl Read for Bytes {
    fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
        self.0.read(b)
    }
}
impl Write for Bytes {
    fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
        panic!("inspection attempted a write")
    }
    fn flush(&mut self) -> std::io::Result<()> {
        panic!("inspection attempted a flush")
    }
}
impl Seek for Bytes {
    fn seek(&mut self, p: SeekFrom) -> std::io::Result<u64> {
        self.0.seek(p)
    }
}
impl BlockDevice for Bytes {
    fn block_size(&self) -> u32 {
        512
    }
    fn total_size(&self) -> u64 {
        self.0.get_ref().len() as u64
    }
    fn sync(&mut self) -> fstool::Result<()> {
        panic!("inspection attempted sync")
    }
}

fn manual_image(little: bool, pending: bool) -> Bytes {
    let mut bytes = vec![0; 65536];
    let mut header = [0u8; 512];
    header[..2].copy_from_slice(b"H+");
    header[2..4].copy_from_slice(&4u16.to_be_bytes());
    header[4..8].copy_from_slice(&(UNMOUNTED | JOURNALED).to_be_bytes());
    header[12..16].copy_from_slice(&1u32.to_be_bytes());
    header[40..44].copy_from_slice(&4096u32.to_be_bytes());
    header[44..48].copy_from_slice(&16u32.to_be_bytes());
    header[48..52].copy_from_slice(&8u32.to_be_bytes());
    bytes[1024..1536].copy_from_slice(&header);
    bytes[64512..65024].copy_from_slice(&header);
    bytes[4096..4100].copy_from_slice(&1u32.to_be_bytes());
    bytes[4132..4140].copy_from_slice(&8192u64.to_be_bytes());
    bytes[4140..4148].copy_from_slice(&16384u64.to_be_bytes());
    let journal = &mut bytes[8192..8240];
    let u32_bytes = |value: u32| {
        if little {
            value.to_le_bytes()
        } else {
            value.to_be_bytes()
        }
    };
    let u64_bytes = |value: u64| {
        if little {
            value.to_le_bytes()
        } else {
            value.to_be_bytes()
        }
    };
    journal[0..4].copy_from_slice(&u32_bytes(0x4a4e4c78));
    journal[4..8].copy_from_slice(&u32_bytes(0x12345678));
    journal[8..16].copy_from_slice(&u64_bytes(512));
    journal[16..24].copy_from_slice(&u64_bytes(if pending { 1024 } else { 512 }));
    journal[24..32].copy_from_slice(&u64_bytes(16384));
    journal[32..36].copy_from_slice(&u32_bytes(4096));
    journal[40..44].copy_from_slice(&u32_bytes(512));
    let checksum = volume::journal_checksum(&journal[..44]);
    journal[36..40].copy_from_slice(&u32_bytes(checksum));
    Bytes(Cursor::new(bytes))
}

#[test]
fn independently_encoded_big_and_little_endian_journals() {
    for little in [false, true] {
        let report = volume::inspect(&mut manual_image(little, false)).unwrap();
        assert_eq!(
            report.journal,
            Journal::Clean {
                offset: 8192,
                size: 16384,
                little_endian: little
            }
        );
        volume::require_engine_access(&report).unwrap();
    }
}
#[test]
fn pending_journal_is_reported_without_replay_and_refuses_engine_open() {
    let mut image = manual_image(true, true);
    let before = image.0.get_ref().clone();
    let report = volume::inspect(&mut image).unwrap();
    assert!(matches!(report.journal, Journal::Pending { .. }));
    assert!(
        hfs_bridge::engine::open_checked(&mut image)
            .err()
            .expect("pending journal must be refused")
            .to_string()
            .contains("pending")
    );
    assert_eq!(&before, image.0.get_ref());
}
#[test]
fn external_uninitialized_and_unknown_journal_flags_are_rejected() {
    for flags in [0u32, 2, 3, 4, 5, 8] {
        let mut image = manual_image(false, false);
        image.0.get_mut()[4096..4100].copy_from_slice(&flags.to_be_bytes());
        assert!(
            volume::inspect(&mut image)
                .unwrap_err()
                .to_string()
                .contains("flags")
        );
    }
}
#[test]
fn checksum_corruption_is_rejected() {
    let mut image = manual_image(true, false);
    image.0.get_mut()[8192 + 36] ^= 1;
    assert!(
        volume::inspect(&mut image)
            .unwrap_err()
            .to_string()
            .contains("checksum")
    );
}
#[test]
fn header_mismatch_dirty_and_inconsistent_volumes_are_not_opened() {
    let mut image = manual_image(false, false);
    image.0.get_mut()[64512 + 16] = 1;
    let report = volume::inspect(&mut image).unwrap();
    assert!(!report.alternate_matches);
    assert!(volume::require_engine_access(&report).is_err());
    for attributes in [
        JOURNALED,
        UNMOUNTED | JOURNALED | (1 << 11),
        UNMOUNTED | JOURNALED | (1 << 14),
    ] {
        let mut report = volume::inspect(&mut manual_image(false, false)).unwrap();
        report.header.attributes = attributes;
        assert!(volume::require_engine_access(&report).is_err());
    }
}
#[test]
fn macos_stale_alternate_bookkeeping_is_accepted_without_changing_bytes() {
    for offset in [8, 20, 24, 32, 36, 48, 52, 56, 60, 64, 68, 72, 76] {
        let mut image = manual_image(false, false);
        image.0.get_mut()[1024 + offset + 3] = 1;
        let before = image.0.get_ref().clone();
        let report = volume::inspect(&mut image).unwrap();
        assert!(!report.alternate_matches);
        assert!(report.alternate_compatible);
        volume::require_engine_access(&report).unwrap();
        assert_eq!(image.0.get_ref(), &before);
    }
    let mut image = manual_image(false, false);
    image.0.get_mut()[64512 + 6] ^= 1;
    let report = volume::inspect(&mut image).unwrap();
    assert!(report.alternate_compatible);
    volume::require_engine_access(&report).unwrap();
}
#[test]
fn mac_catalog_maintenance_flag_is_bookkeeping_but_other_attribute_bits_are_not() {
    for header in [1024, 64512] {
        for bit in [1u8, 2, 4, 8, 16, 32, 64, 128] {
            let mut image = manual_image(false, false);
            image.0.get_mut()[header + 4] ^= bit;
            let before = image.0.get_ref().clone();
            let report = volume::inspect(&mut image).unwrap();
            assert_eq!(report.alternate_compatible, bit == 128);
            assert_eq!(volume::require_engine_access(&report).is_ok(), bit == 128);
            assert_eq!(image.0.get_ref(), &before);
        }
    }
}
#[test]
fn structural_alternate_mismatches_and_invalid_alternates_are_refused() {
    for offset in [0, 4, 12, 16, 28, 40, 44, 80, 112, 192, 272, 352, 432] {
        let mut image = manual_image(false, false);
        image.0.get_mut()[64512 + offset + 3] ^= 1;
        let before = image.0.get_ref().clone();
        if let Ok(report) = volume::inspect(&mut image) {
            assert!(!report.alternate_compatible, "offset {offset}");
            assert!(volume::require_engine_access(&report).is_err());
        }
        assert_eq!(image.0.get_ref(), &before);
    }
}
#[test]
fn malformed_volume_geometry_and_forks_are_rejected() {
    let image = manual_image(false, false);
    let original = &image.0.get_ref()[1024..1536];
    for (offset, value) in [
        (40, 0u32),
        (40, 513),
        (44, u32::MAX),
        (48, 17),
        (112 + 12, 17),
        (112 + 12, 0),
    ] {
        let mut header = original.to_vec();
        header[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
        if offset == 112 + 12 && value == 0 {
            header[112..120].copy_from_slice(&1u64.to_be_bytes());
        }
        assert!(volume::parse_header(&header, 65536).is_err());
    }
    assert!(volume::parse_header(&original[..100], 65536).is_err());
    assert!(volume::parse_header(original, 131072).is_err());
}
#[test]
fn hfsx_version_pair_is_checked() {
    let image = manual_image(false, false);
    let mut header = image.0.get_ref()[1024..1536].to_vec();
    header[..2].copy_from_slice(b"HX");
    assert!(volume::parse_header(&header, 65536).is_err());
    header[2..4].copy_from_slice(&5u16.to_be_bytes());
    assert_eq!(
        volume::parse_header(&header, 65536).unwrap().signature,
        0x4858
    );
}
