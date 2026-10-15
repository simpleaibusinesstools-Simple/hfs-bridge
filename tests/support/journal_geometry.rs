//! Independent fixture conversion: only a generated, clean journal is changed.
//! No device I/O. TN1150 header fields and checksum are encoded here.
use hfs_bridge::volume;

pub fn convert_empty(bytes: &mut [u8], sector: usize, little: bool, wrap: bool) {
    let jib = volume::be32(bytes, 1036) as usize * volume::be32(bytes, 1064) as usize;
    let journal = volume::be64(bytes, jib + 36) as usize;
    let size = volume::be64(bytes, jib + 44) as usize;
    assert_eq!(
        &bytes[journal + 8..journal + 16],
        &bytes[journal + 16..journal + 24]
    );
    assert!(sector >= 512 && sector.is_power_of_two());
    assert!(journal.is_multiple_of(sector) && size.is_multiple_of(sector));
    let cursor = if wrap { size - sector } else { sector };
    bytes[journal..journal + sector].fill(0);
    for (offset, value, width) in [
        (0, 0x4a4e4c78, 4),
        (4, 0x12345678, 4),
        (8, cursor as u64, 8),
        (16, cursor as u64, 8),
        (24, size as u64, 8),
        (32, 8192, 4),
        (40, sector as u64, 4),
        (44, 1, 4),
    ] {
        put(bytes, journal + offset, value, width, little);
    }
    let checksum = volume::journal_checksum(&bytes[journal..journal + 44]);
    put(bytes, journal + 36, checksum as u64, 4, little);
}

fn put(bytes: &mut [u8], offset: usize, value: u64, width: usize, little: bool) {
    let encoded = if little {
        value.to_le_bytes()
    } else {
        value.to_be_bytes()
    };
    bytes[offset..offset + width].copy_from_slice(if little {
        &encoded[..width]
    } else {
        &encoded[8 - width..]
    });
}

pub fn header_neighbors(bytes: &[u8]) -> Vec<u8> {
    let end = bytes.len();
    [
        &bytes[..1024],
        &bytes[1536..4096],
        &bytes[end - 4096..end - 1024],
        &bytes[end - 512..],
    ]
    .concat()
}

pub fn seed_header_neighbors(bytes: &mut [u8]) {
    let end = bytes.len();
    for (start, stop) in [
        (0, 1024),
        (1536, 4096),
        (end - 4096, end - 1024),
        (end - 512, end),
    ] {
        for (index, byte) in bytes[start..stop].iter_mut().enumerate() {
            *byte = ((index * 17 + 53) % 251) as u8;
        }
    }
}
