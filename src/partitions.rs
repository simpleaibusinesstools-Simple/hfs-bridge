//! Bounded, read-only disk-layout discovery. Never repairs or selects a volume
//! implicitly. A recognized but inconsistent map is an error, not a raw volume.
use std::io::{self, Read, Seek, SeekFrom};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    Raw,
    Gpt,
    Apple,
    Mbr,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Partition {
    /// On-disk, one-based slot; zero identifies an unpartitioned HFS volume.
    pub number: u32,
    pub name: String,
    pub offset: u64,
    pub length: u64,
    pub hfs_candidate: bool,
    pub writable: bool,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Layout {
    pub scheme: Scheme,
    pub block_size: u32,
    pub partitions: Vec<Partition>,
}
impl Layout {
    pub fn select(&self, number: u32, writing: bool) -> io::Result<&Partition> {
        let partition = self
            .partitions
            .iter()
            .find(|p| p.number == number)
            .ok_or_else(|| invalid("partition number is absent"))?;
        if !partition.hfs_candidate {
            return Err(invalid("selected partition is not an HFS candidate"));
        }
        if writing && !partition.writable {
            return Err(invalid(
                "partition map does not permit writing this partition",
            ));
        }
        Ok(partition)
    }
}
fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
fn le32(b: &[u8], n: usize) -> u32 {
    u32::from_le_bytes(b[n..n + 4].try_into().unwrap())
}
fn le64(b: &[u8], n: usize) -> u64 {
    u64::from_le_bytes(b[n..n + 8].try_into().unwrap())
}
fn be32(b: &[u8], n: usize) -> u32 {
    u32::from_be_bytes(b[n..n + 4].try_into().unwrap())
}
fn read_at<R: Read + Seek>(
    input: &mut R,
    size: u64,
    offset: u64,
    count: usize,
) -> io::Result<Vec<u8>> {
    if offset
        .checked_add(count as u64)
        .is_none_or(|end| end > size)
    {
        return Err(invalid("partition metadata exceeds image bounds"));
    }
    let mut bytes = vec![0; count];
    input.seek(SeekFrom::Start(offset))?;
    input.read_exact(&mut bytes)?;
    Ok(bytes)
}
fn range(start: u64, blocks: u64, block_size: u32, size: u64) -> io::Result<(u64, u64)> {
    let offset = start
        .checked_mul(block_size as u64)
        .ok_or_else(|| invalid("partition offset overflow"))?;
    let length = blocks
        .checked_mul(block_size as u64)
        .ok_or_else(|| invalid("partition length overflow"))?;
    if blocks == 0 || offset.checked_add(length).is_none_or(|end| end > size) {
        return Err(invalid("empty or out-of-bounds partition"));
    }
    Ok((offset, length))
}
fn no_overlap(partitions: &[Partition]) -> io::Result<()> {
    let mut ranges: Vec<_> = partitions
        .iter()
        .map(|p| (p.offset, p.offset + p.length))
        .collect();
    ranges.sort_unstable();
    if ranges.windows(2).any(|p| p[0].1 > p[1].0) {
        return Err(invalid("overlapping partitions"));
    }
    Ok(())
}
/// IEEE CRC-32, reflected polynomial, as specified for GPT.
fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &byte in bytes {
        crc ^= byte as u32;
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xedb88320 & 0u32.wrapping_sub(crc & 1));
        }
    }
    !crc
}
const HFS_GUID: [u8; 16] = [
    0x00, 0x53, 0x46, 0x48, 0x00, 0x00, 0xaa, 0x11, 0xaa, 0x11, 0x00, 0x30, 0x65, 0x43, 0xec, 0xac,
];
struct Gpt {
    guid: [u8; 16],
    first: u64,
    last: u64,
    count: u32,
    stride: u32,
    entries: Vec<u8>,
}
fn gpt_header<R: Read + Seek>(
    input: &mut R,
    size: u64,
    block: u32,
    lba: u64,
    other: u64,
) -> io::Result<Gpt> {
    let mut h = read_at(input, size, lba * block as u64, block as usize)?;
    let header_size = le32(&h, 12) as usize;
    if &h[..8] != b"EFI PART"
        || le32(&h, 8) != 0x10000
        || !(92..=block as usize).contains(&header_size)
        || le32(&h, 20) != 0
        || h[92..].iter().any(|&b| b != 0)
        || le64(&h, 24) != lba
        || le64(&h, 32) != other
    {
        return Err(invalid("unsupported or inconsistent GPT header"));
    }
    let expected = le32(&h, 16);
    h[16..20].fill(0);
    if crc32(&h[..header_size]) != expected {
        return Err(invalid("GPT header checksum mismatch"));
    }
    let first = le64(&h, 40);
    let last = le64(&h, 48);
    let guid: [u8; 16] = h[56..72].try_into().unwrap();
    let table = le64(&h, 72);
    let count = le32(&h, 80);
    let stride = le32(&h, 84);
    let bytes = u64::from(count) * u64::from(stride);
    if stride < 128
        || !stride.is_power_of_two()
        || !(16384..=4 * 1024 * 1024).contains(&bytes)
        || guid == [0; 16]
        || first > last
        || first < 2
        || last >= size / block as u64 - 1
    {
        return Err(invalid("unsupported GPT table geometry"));
    }
    let sectors = bytes.div_ceil(block as u64);
    let table_end = table
        .checked_add(sectors)
        .ok_or_else(|| invalid("GPT table overflow"))?;
    if (lba == 1 && (table <= 1 || table_end > first))
        || (lba != 1 && (table <= last || table_end > lba))
    {
        return Err(invalid("GPT table overlaps usable space or a header"));
    }
    let offset = table
        .checked_mul(block as u64)
        .ok_or_else(|| invalid("GPT table offset overflow"))?;
    let entries = read_at(input, size, offset, bytes as usize)?;
    if crc32(&entries) != le32(&h, 88) {
        return Err(invalid("GPT entry checksum mismatch"));
    }
    Ok(Gpt {
        guid,
        first,
        last,
        count,
        stride,
        entries,
    })
}
fn gpt<R: Read + Seek>(input: &mut R, size: u64, block: u32, mbr: &[u8]) -> io::Result<Layout> {
    let last_lba = size / block as u64 - 1;
    let used: Vec<_> = mbr[446..510]
        .as_chunks::<16>()
        .0
        .iter()
        .filter(|e| e[4] != 0)
        .collect();
    if used.len() != 1
        || used[0][0] != 0
        || used[0][4] != 0xee
        || le32(used[0], 8) != 1
        || u64::from(le32(used[0], 12)) != last_lba.min(u32::MAX as u64)
    {
        return Err(invalid("missing or hybrid GPT protective MBR"));
    }
    let primary = gpt_header(input, size, block, 1, last_lba)?;
    let backup = gpt_header(input, size, block, last_lba, 1)?;
    if primary.guid != backup.guid
        || primary.first != backup.first
        || primary.last != backup.last
        || primary.count != backup.count
        || primary.stride != backup.stride
        || primary.entries != backup.entries
    {
        return Err(invalid("primary and backup GPT disagree"));
    }
    let mut partitions = Vec::new();
    let mut ids = std::collections::HashSet::new();
    for (slot, entry) in primary
        .entries
        .chunks_exact(primary.stride as usize)
        .enumerate()
    {
        if entry[..16] == [0; 16] {
            continue;
        }
        let id: [u8; 16] = entry[16..32].try_into().unwrap();
        let start = le64(entry, 32);
        let end = le64(entry, 40);
        let attributes = le64(entry, 48);
        if id == [0; 16]
            || !ids.insert(id)
            || start < primary.first
            || end > primary.last
            || start > end
        {
            return Err(invalid("invalid GPT partition identity or bounds"));
        }
        if attributes & 0x0000fffffffffff8 != 0 || entry[128..].iter().any(|&b| b != 0) {
            return Err(invalid("unsupported GPT reserved entry fields"));
        }
        let (offset, length) = range(start, end - start + 1, block, size)?;
        let units: Vec<u16> = entry[56..128]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .take_while(|&c| c != 0)
            .collect();
        let name = String::from_utf16(&units).map_err(|_| invalid("invalid UTF-16 GPT name"))?;
        // Unknown type-specific/platform flags have no established write policy.
        partitions.push(Partition {
            number: slot as u32 + 1,
            name,
            offset,
            length,
            hfs_candidate: entry[..16] == HFS_GUID,
            writable: attributes == 0,
        });
    }
    no_overlap(&partitions)?;
    Ok(Layout {
        scheme: Scheme::Gpt,
        block_size: block,
        partitions,
    })
}
fn apple<R: Read + Seek>(input: &mut R, size: u64, driver: &[u8]) -> io::Result<Layout> {
    let block = u16::from_be_bytes(driver[2..4].try_into().unwrap()) as u32;
    if !matches!(block, 512 | 1024 | 2048 | 4096)
        || u64::from(be32(driver, 4)) * u64::from(block) != size
    {
        return Err(invalid("unsupported Apple driver-map geometry"));
    }
    let first = read_at(input, size, block as u64, 512)?;
    let count = be32(&first, 4);
    if &first[..2] != b"PM"
        || count == 0
        || count > 4096
        || u64::from(count) + 1 > size / u64::from(block)
    {
        return Err(invalid("unsupported Apple partition-map count"));
    }
    let mut partitions = Vec::new();
    let mut map_seen = false;
    for slot in 1..=count {
        let e = read_at(input, size, u64::from(slot) * u64::from(block), 512)?;
        if &e[..2] != b"PM" || be32(&e, 4) != count {
            return Err(invalid("inconsistent Apple partition-map entry"));
        }
        let start = be32(&e, 8);
        let blocks = be32(&e, 12);
        let (offset, length) = range(start.into(), blocks.into(), block, size)?;
        if start == 0 {
            return Err(invalid("Apple partition overlaps driver map"));
        }
        let text = |bytes: &[u8]| {
            String::from_utf8_lossy(
                &bytes[..bytes.iter().position(|&c| c == 0).unwrap_or(bytes.len())],
            )
            .into_owned()
        };
        let kind = text(&e[48..80]);
        if kind == "Apple_partition_map" {
            if map_seen || start != 1 || blocks < count {
                return Err(invalid("invalid Apple map reservation"));
            }
            map_seen = true;
        } else if start <= count {
            return Err(invalid("Apple partition overlaps map reservation"));
        }
        let hfs = kind == "Apple_HFS";
        if hfs && (be32(&e, 80) != 0 || be32(&e, 84) != blocks || be32(&e, 88) & 0x13 != 0x13) {
            return Err(invalid("unsupported Apple HFS logical range or read flags"));
        }
        partitions.push(Partition {
            number: slot,
            name: text(&e[16..48]),
            offset,
            length,
            hfs_candidate: hfs,
            writable: be32(&e, 88) & 0x20 != 0,
        });
    }
    if !map_seen {
        return Err(invalid("Apple partition-map reservation missing"));
    }
    no_overlap(&partitions)?;
    Ok(Layout {
        scheme: Scheme::Apple,
        block_size: block,
        partitions,
    })
}
fn mbr(size: u64, block: u32, bytes: &[u8]) -> io::Result<Layout> {
    let mut partitions = Vec::new();
    for (slot, e) in bytes[446..510].as_chunks::<16>().0.iter().enumerate() {
        if e[4] == 0 {
            if le32(e, 8) != 0 || le32(e, 12) != 0 {
                return Err(invalid("nonempty unused MBR slot"));
            }
            continue;
        }
        if !matches!(e[0], 0 | 0x80) || matches!(e[4], 0x05 | 0x0f | 0x85 | 0xee) || le32(e, 8) == 0
        {
            return Err(invalid("extended, hybrid or invalid MBR layout"));
        }
        let (offset, length) = range(le32(e, 8).into(), le32(e, 12).into(), block, size)?;
        partitions.push(Partition {
            number: slot as u32 + 1,
            name: format!("MBR type {:02X}", e[4]),
            offset,
            length,
            hfs_candidate: e[4] == 0xaf,
            writable: true,
        });
    }
    if partitions.is_empty() {
        return Err(invalid("empty MBR layout"));
    }
    no_overlap(&partitions)?;
    Ok(Layout {
        scheme: Scheme::Mbr,
        block_size: block,
        partitions,
    })
}
/// Image sector size must be supplied explicitly (512 or 4096); APM declares
/// its own block size. Image length and all arithmetic are checked before I/O.
pub fn discover<R: Read + Seek>(input: &mut R, size: u64, block: u32) -> io::Result<Layout> {
    if !matches!(block, 512 | 4096) || size < 1536 || !size.is_multiple_of(block as u64) {
        return Err(invalid("unsupported or incomplete image sector geometry"));
    }
    let zero = read_at(input, size, 0, 512)?;
    if &zero[..2] == b"ER" {
        return apple(input, size, &zero);
    }
    if zero[510..512] == [0x55, 0xaa] {
        if zero[446..510]
            .as_chunks::<16>()
            .0
            .iter()
            .any(|e| e[4] == 0xee)
        {
            return gpt(input, size, block, &zero);
        }
        return mbr(size, block, &zero);
    }
    if read_at(input, size, u64::from(block), 8)? == b"EFI PART" {
        return Err(invalid("GPT header lacks protective MBR"));
    }
    let sig = read_at(input, size, 1024, 2)?;
    if sig != b"H+" && sig != b"HX" {
        return Err(invalid("no recognized HFS volume or partition map"));
    }
    Ok(Layout {
        scheme: Scheme::Raw,
        block_size: block,
        partitions: vec![Partition {
            number: 0,
            name: "Raw HFS volume".into(),
            offset: 0,
            length: size,
            hfs_candidate: true,
            writable: true,
        }],
    })
}
