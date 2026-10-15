//! Independent decoding of Apple's TN1150 structures, without engine open/replay.
use crate::Result;
use fstool::block::BlockDevice;
pub const JOURNALED: u32 = 1 << 13;
pub const UNMOUNTED: u32 = 1 << 8;
pub const INCONSISTENT: u32 = (1 << 11) | (1 << 14);
pub const EXPANDED_TIMES: u32 = 1 << 29;
pub const CONTENT_PROTECTION: u32 = 1 << 30;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub signature: u16,
    pub version: u16,
    pub attributes: u32,
    pub journal_info_block: u32,
    pub block_size: u32,
    pub total_blocks: u32,
    pub free_blocks: u32,
    pub files: u32,
    pub folders: u32,
    pub write_count: u32,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Journal {
    Absent,
    Clean {
        offset: u64,
        size: u64,
        little_endian: bool,
    },
    Pending {
        start: u64,
        end: u64,
    },
}
#[derive(Debug)]
pub struct Inspection {
    pub header: Header,
    pub alternate_matches: bool,
    pub alternate_compatible: bool,
    pub journal: Journal,
}
pub fn be16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes(bytes[offset..offset + 2].try_into().unwrap())
}
pub fn be32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes(bytes[offset..offset + 4].try_into().unwrap())
}
pub fn be64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_be_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

pub fn parse_header(bytes: &[u8], capacity: u64) -> Result<Header> {
    if bytes.len() != 512 {
        return Err("volume header must contain 512 bytes".into());
    }
    let signature = be16(bytes, 0);
    let version = be16(bytes, 2);
    if !matches!((signature, version), (0x482b, 4) | (0x4858, 5)) {
        return Err("expected HFS+ (H+, version 4) or HFSX (HX, version 5); specify the correct raw-volume offset/length".into());
    }
    let block_size = be32(bytes, 40);
    let total_blocks = be32(bytes, 44);
    let free_blocks = be32(bytes, 48);
    let occupied = u64::from(block_size) * u64::from(total_blocks);
    if block_size < 512
        || !block_size.is_power_of_two()
        || occupied < 2048
        || occupied > capacity
        || capacity - occupied >= u64::from(block_size)
        || free_blocks > total_blocks
    {
        return Err("invalid allocation geometry or wrong volume slice".into());
    }
    // Overflow extents are permitted, but every inline range must be in-volume.
    for offset in [112, 192, 272, 352, 432] {
        let logical = be64(bytes, offset);
        let allocated = be32(bytes, offset + 12);
        if allocated > total_blocks || logical > u64::from(allocated) * u64::from(block_size) {
            return Err("special-file fork exceeds allocation capacity".into());
        }
        let mut sum = 0u64;
        let mut ended = false;
        for extent in 0..8 {
            let start = be32(bytes, offset + 16 + extent * 8);
            let count = be32(bytes, offset + 20 + extent * 8);
            if count == 0 {
                ended = true;
                continue;
            }
            if ended || u64::from(start) + u64::from(count) > u64::from(total_blocks) {
                return Err("invalid special-file inline extent".into());
            }
            sum += u64::from(count);
        }
        if sum > u64::from(allocated) {
            return Err("inline extents exceed fork allocation".into());
        }
    }
    Ok(Header {
        signature,
        version,
        attributes: be32(bytes, 4),
        journal_info_block: be32(bytes, 12),
        block_size,
        total_blocks,
        free_blocks,
        files: be32(bytes, 32),
        folders: be32(bytes, 36),
        write_count: be32(bytes, 68),
    })
}
pub fn inspect(device: &mut dyn BlockDevice) -> Result<Inspection> {
    let mut primary = [0u8; 512];
    device.read_at(1024, &mut primary)?;
    let header = parse_header(&primary, device.total_size())?;
    let mut alternate = [0u8; 512];
    device.read_at(device.total_size() - 1024, &mut alternate)?;
    let alternate_matches = primary == alternate;
    // macOS flushes the alternate only for selected changes. Ordinary counts,
    // allocation cursors and mount bookkeeping can legitimately be older.
    // Keep geometry, identity, journal location and special forks identical;
    // no fallback or recovery from either header is attempted here.
    // macOS may record kHFSUnusedNodeFixMask (bit 31: unused catalog nodes
    // zero-filled) only in the primary. This maintenance flag does not change
    // the format. Other attribute differences remain incompatible.
    parse_header(&alternate, device.total_size())?;
    let alternate_compatible = (0..512).all(|offset| {
        matches!(offset, 8..=11 | 20..=27 | 32..=39 | 48..=79)
            || primary[offset] == alternate[offset]
            || (offset == 6 && primary[offset] ^ alternate[offset] == 1)
            || (offset == 4 && primary[offset] ^ alternate[offset] == 0x80)
    });
    let journal = read_journal(device, &header)?;
    Ok(Inspection {
        header,
        alternate_matches,
        alternate_compatible,
        journal,
    })
}
/// Inspection may describe these formats, but the engine must not interpret or
/// rewrite their dates or protected contents using ordinary HFS+ semantics.
pub fn require_supported_features(header: &Header) -> Result<()> {
    if header.attributes & EXPANDED_TIMES != 0 {
        return Err("unsupported volume feature: expanded HFS+ timestamps".into());
    }
    if header.attributes & CONTENT_PROTECTION != 0 {
        return Err("unsupported volume feature: HFS+ content protection".into());
    }
    Ok(())
}
pub fn require_engine_access(inspection: &Inspection) -> Result<()> {
    require_supported_features(&inspection.header)?;
    if !inspection.alternate_compatible {
        return Err("primary/alternate volume headers have incompatible structural fields; recovery is not implemented".into());
    }
    if inspection.header.attributes & UNMOUNTED == 0
        || inspection.header.attributes & INCONSISTENT != 0
    {
        return Err("volume was not cleanly unmounted or is inconsistent; native checking/recovery is required".into());
    }
    if matches!(inspection.journal, Journal::Pending { .. }) {
        return Err(
            "journal contains pending transactions; this milestone refuses automatic replay".into(),
        );
    }
    Ok(())
}
/// Versioned, read-only preflight report shared by image and disk inspection.
/// Passing these checks is not a complete filesystem consistency check.
pub fn inspection_json(report: &Inspection) -> String {
    let h = &report.header;
    let journal = match report.journal {
        Journal::Absent => "absent",
        Journal::Clean { .. } => "clean",
        Journal::Pending { .. } => "pending",
    };
    format!(
        "{{\"schema\":1,\"operation\":\"read-only volume inspection\",\"signature\":{},\"version\":{},\"attributes\":{},\"blockSize\":{},\"totalBlocks\":{},\"freeBlocks\":{},\"files\":{},\"folders\":{},\"writeCount\":{},\"alternateMatches\":{},\"alternateCompatible\":{},\"journal\":\"{}\",\"engineAccess\":{},\"physicalWrites\":false}}",
        h.signature,
        h.version,
        h.attributes,
        h.block_size,
        h.total_blocks,
        h.free_blocks,
        h.files,
        h.folders,
        h.write_count,
        report.alternate_matches,
        report.alternate_compatible,
        journal,
        require_engine_access(report).is_ok()
    )
}
fn read_journal(device: &mut dyn BlockDevice, header: &Header) -> Result<Journal> {
    if header.attributes & JOURNALED == 0 {
        return Ok(Journal::Absent);
    }
    if header.journal_info_block == 0 || header.journal_info_block >= header.total_blocks {
        return Err("invalid journal-info block pointer".into());
    }
    let mut info = [0u8; 52];
    device.read_at(
        u64::from(header.journal_info_block) * u64::from(header.block_size),
        &mut info,
    )?;
    // TN1150: in-filesystem = 1, external device = 2, needs init = 4.
    if be32(&info, 0) != 1 {
        return Err(format!(
            "unsupported journal-info flags {:#x}; expected an initialized in-volume journal (0x1)",
            be32(&info, 0)
        )
        .into());
    }
    let offset = be64(&info, 36);
    let size = be64(&info, 44);
    let capacity = u64::from(header.total_blocks) * u64::from(header.block_size);
    if offset < 1536 || size < 1024 || offset.checked_add(size).is_none_or(|end| end > capacity) {
        return Err("journal range lies outside volume".into());
    }
    let mut raw = [0u8; 48];
    device.read_at(offset, &mut raw)?;
    let little = match &raw[0..8] {
        [0x4a, 0x4e, 0x4c, 0x78, 0x12, 0x34, 0x56, 0x78] => false,
        [0x78, 0x4c, 0x4e, 0x4a, 0x78, 0x56, 0x34, 0x12] => true,
        _ => return Err("invalid journal magic/byte order".into()),
    };
    let u32_at = |off| {
        let value: [u8; 4] = raw[off..off + 4].try_into().unwrap();
        if little {
            u32::from_le_bytes(value)
        } else {
            u32::from_be_bytes(value)
        }
    };
    let u64_at = |off| {
        let value: [u8; 8] = raw[off..off + 8].try_into().unwrap();
        if little {
            u64::from_le_bytes(value)
        } else {
            u64::from_be_bytes(value)
        }
    };
    let start = u64_at(8);
    let end = u64_at(16);
    let sector = u64::from(u32_at(40));
    let block_list = u64::from(u32_at(32));
    if u64_at(24) != size
        || sector < 512
        || !sector.is_power_of_two()
        || sector >= size
        || block_list < 32
        || block_list > size - sector
        || block_list % sector != 0
        || start < sector
        || end < sector
        || start > size
        || end > size
        || start % sector != 0
        || end % sector != 0
    {
        return Err("invalid journal ring geometry".into());
    }
    let stored = u32_at(36);
    let mut checked = raw[..44].to_vec();
    checked[36..40].fill(0);
    if journal_checksum(&checked) != stored {
        return Err("journal header checksum mismatch".into());
    }
    // A cursor at the ring end denotes the first byte after its header.
    let start = if start == size { sector } else { start };
    let end = if end == size { sector } else { end };
    if start == end {
        Ok(Journal::Clean {
            offset,
            size,
            little_endian: little,
        })
    } else {
        Ok(Journal::Pending { start, end })
    }
}
pub fn journal_checksum(bytes: &[u8]) -> u32 {
    let mut checksum = 0u32;
    for byte in bytes {
        checksum = (checksum << 8) ^ checksum.wrapping_add(u32::from(*byte));
    }
    !checksum
}
