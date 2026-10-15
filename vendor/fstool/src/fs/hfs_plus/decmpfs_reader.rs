//! Bounded decmpfs reader used by the filesystem engine and reference probe.
//! Wire format derived from Apple's decmpfs_disk_header and independently
//! documented 64 KiB resource tables. This file does not enable writes.

use std::io;
#[path = "lzbitmap.rs"]
mod lzbitmap;

pub const BLOCK_BYTES: usize = 65_536;
// LZFSE framing and entropy tables can make an incompressible unit larger
// than its 64 KiB decoded payload. Keep a fixed 4 KiB overhead budget.
pub const MAX_ENCODED_BLOCK: usize = BLOCK_BYTES + 4096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Header {
    pub kind: u32,
    pub size: u64,
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

impl Header {
    pub fn parse(bytes: &[u8]) -> io::Result<Self> {
        let header = Self::metadata(bytes)?;
        if !matches!(header.kind, 1 | 3 | 4 | 7 | 8 | 9 | 10 | 11 | 12 | 13 | 14) {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "unsupported decmpfs codec",
            ));
        }
        Ok(header)
    }
    /// Unknown codecs can still expose their declared size to directory listing.
    /// Content reads must use the supported-codec parser above.
    pub fn metadata(bytes: &[u8]) -> io::Result<Self> {
        if bytes.len() < 16 || bytes[..4] != *b"fpmc" {
            return Err(invalid("invalid little-endian decmpfs header"));
        }
        let kind = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
        let size = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
        Ok(Self { kind, size })
    }
    pub fn resource(self) -> bool {
        matches!(self.kind, 4 | 8 | 10 | 12 | 14)
    }
}

/// Exact, bounded reads; callers supply a checked resource-fork reader.
pub trait ReadAt {
    fn length(&self) -> u64;
    fn read_exact_at(&mut self, offset: u64, output: &mut [u8]) -> io::Result<()>;
}

impl ReadAt for &[u8] {
    fn length(&self) -> u64 {
        self.len() as u64
    }
    fn read_exact_at(&mut self, offset: u64, output: &mut [u8]) -> io::Result<()> {
        let offset = usize::try_from(offset).map_err(|_| invalid("resource offset overflow"))?;
        let end = offset
            .checked_add(output.len())
            .ok_or_else(|| invalid("resource read overflow"))?;
        output.copy_from_slice(
            self.get(offset..end)
                .ok_or_else(|| invalid("resource read exceeds EOF"))?,
        );
        Ok(())
    }
}

fn raw(bytes: &[u8], expected: usize) -> io::Result<Vec<u8>> {
    if bytes.len() != expected {
        return Err(invalid("stored decmpfs length mismatch"));
    }
    Ok(bytes.to_vec())
}

/// One independently encoded compression unit. Never allocates declared file size.
pub fn decode_block(kind: u32, input: &[u8], expected: usize) -> io::Result<Vec<u8>> {
    if expected > BLOCK_BYTES
        || (input.is_empty() && !(kind == 1 && expected == 0))
        || input.len() > MAX_ENCODED_BLOCK
    {
        return Err(invalid("decmpfs unit exceeds bounded codec buffers"));
    }
    match kind {
        1 => raw(input, expected),
        3 | 4 if input[0] & 15 == 15 => raw(&input[1..], expected),
        7 | 8 if input[0] == 6 => raw(&input[1..], expected),
        9 | 10 if input[0] == 0xcc => raw(&input[1..], expected),
        3 | 4 => {
            // One extra byte distinguishes exact output from an expansion bomb.
            let mut output = vec![0; expected + 1];
            let mut decoder = flate2::Decompress::new(true);
            let status = decoder
                .decompress(input, &mut output, flate2::FlushDecompress::Finish)
                .map_err(|_| invalid("malformed decmpfs zlib unit"))?;
            if status != flate2::Status::StreamEnd
                || decoder.total_out() != expected as u64
                || decoder.total_in() != input.len() as u64
            {
                return Err(invalid("incomplete, excessive or trailing zlib unit"));
            }
            output.truncate(expected);
            Ok(output)
        }
        7 | 8 => {
            let mut output = vec![0; expected + 1];
            let produced = lzvn::decode_into(input, &mut output)
                .map_err(|_| invalid("malformed decmpfs LZVN unit"))?;
            if produced != expected {
                return Err(invalid("LZVN output length mismatch"));
            }
            output.truncate(expected);
            Ok(output)
        }
        13 | 14 => lzbitmap::decode(input, expected),
        11 | 12 => {
            // The ring engine writes into a fixed-size sink. Its internal buffers
            // are fixed; no Vec whose growth depends on untrusted block headers.
            let mut decoder = lzfse_rust::LzfseRingDecoder::default();
            let mut reader = input;
            let mut output = vec![0; expected + 1];
            let mut sink = io::Cursor::new(output.as_mut_slice());
            let (consumed, produced) = decoder
                .decode(&mut reader, &mut sink)
                .map_err(|_| invalid("malformed or excessive decmpfs LZFSE unit"))?;
            if consumed != input.len() as u64 || produced != expected as u64 {
                return Err(invalid("LZFSE output or input length mismatch"));
            }
            output.truncate(expected);
            Ok(output)
        }
        _ => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "unsupported decmpfs unit",
        )),
    }
}

#[derive(Clone, Copy, Debug)]
enum Table {
    Zlib { base: u64, end: u64 },
    Offsets,
}

/// Retains only table geometry, never one entry per logical block.
#[derive(Clone, Copy, Debug)]
pub struct Resource {
    header: Header,
    blocks: u64,
    fork_bytes: u64,
    table: Table,
}

impl Resource {
    pub fn open(header: Header, fork: &mut dyn ReadAt) -> io::Result<Self> {
        if !header.resource() || header.size == 0 {
            return Err(invalid("decmpfs resource has no logical units"));
        }
        let blocks = header.size.div_ceil(BLOCK_BYTES as u64);
        let fork_bytes = fork.length();
        let table = if header.kind == 4 {
            let mut bytes = [0; 16];
            fork.read_exact_at(0, &mut bytes)?;
            let field = |at| u32::from_be_bytes(bytes[at..at + 4].try_into().unwrap()) as u64;
            let (start, map, length, map_length) = (field(0), field(4), field(8), field(12));
            let end = start
                .checked_add(length)
                .ok_or_else(|| invalid("resource data overflow"))?;
            let map_end = map
                .checked_add(map_length)
                .ok_or_else(|| invalid("resource map overflow"))?;
            let required = 8u64
                .checked_add(
                    blocks
                        .checked_mul(8)
                        .ok_or_else(|| invalid("table overflow"))?,
                )
                .ok_or_else(|| invalid("table overflow"))?;
            if start < 16
                || end > fork_bytes
                || length < required
                || map < end
                || map_end > fork_bytes
            {
                return Err(invalid("invalid decmpfs resource framing"));
            }
            let mut prefix = [0; 8];
            fork.read_exact_at(start, &mut prefix)?;
            let record = u32::from_be_bytes(prefix[..4].try_into().unwrap()) as u64;
            let count = u32::from_le_bytes(prefix[4..].try_into().unwrap()) as u64;
            if count != blocks || record.checked_add(4) != Some(length) {
                return Err(invalid("decmpfs resource count or wrapper length mismatch"));
            }
            Table::Zlib {
                base: start + 4,
                end,
            }
        } else {
            let mut bytes = [0; 4];
            fork.read_exact_at(0, &mut bytes)?;
            let first = u32::from_le_bytes(bytes) as u64;
            if blocks.checked_add(1).and_then(|n| n.checked_mul(4)) != Some(first)
                || first > fork_bytes
            {
                return Err(invalid("invalid decmpfs offset-table count"));
            }
            Table::Offsets
        };
        let resource = Self {
            header,
            blocks,
            fork_bytes,
            table,
        };
        // Check every entry in bounded pages before making the file readable.
        // Padding is allowed; aliasing, overlap and backwards runs are refused.
        let mut previous_end = match table {
            Table::Zlib { base, .. } => base + 4 + blocks * 8,
            Table::Offsets => (blocks + 1) * 4,
        };
        let stride = if matches!(table, Table::Zlib { .. }) {
            8
        } else {
            4
        };
        let table_start = match table {
            Table::Zlib { base, .. } => base + 4,
            Table::Offsets => 0,
        };
        let mut page = [0; 4096];
        let per_page = (page.len() / stride - 1) as u64;
        let mut index = 0;
        while index < blocks {
            let count = (blocks - index).min(per_page);
            let bytes = count as usize * stride + if stride == 4 { 4 } else { 0 };
            fork.read_exact_at(table_start + index * stride as u64, &mut page[..bytes])?;
            for within in 0..count as usize {
                let (start, end) = resource.entry(&page[within * stride..], stride)?;
                if start < previous_end {
                    return Err(invalid("overlapping decmpfs units"));
                }
                previous_end = end;
            }
            index += count;
        }
        if matches!(table, Table::Offsets) && previous_end != fork_bytes {
            return Err(invalid("decmpfs final offset does not match resource EOF"));
        }
        Ok(resource)
    }

    fn entry(self, bytes: &[u8], stride: usize) -> io::Result<(u64, u64)> {
        let first = u32::from_le_bytes(bytes[..4].try_into().unwrap()) as u64;
        let next = u32::from_le_bytes(bytes[4..8].try_into().unwrap()) as u64;
        let (start, end, limit) = match self.table {
            Table::Zlib { base, end } => (base + first, base + first + next, end),
            Table::Offsets => (first, next, self.fork_bytes),
        };
        let length = end
            .checked_sub(start)
            .ok_or_else(|| invalid("backwards decmpfs unit"))?;
        if length == 0
            || length > MAX_ENCODED_BLOCK as u64
            || end > limit
            || (stride != 4 && stride != 8)
        {
            return Err(invalid("decmpfs unit outside bounded resource data"));
        }
        Ok((start, end))
    }

    pub fn read(&self, fork: &mut dyn ReadAt, offset: u64, output: &mut [u8]) -> io::Result<usize> {
        if fork.length() != self.fork_bytes {
            return Err(invalid("resource length changed"));
        }
        let wanted = usize::try_from(
            self.header
                .size
                .saturating_sub(offset)
                .min(output.len() as u64),
        )
        .unwrap();
        let mut copied = 0;
        let mut encoded = vec![0; MAX_ENCODED_BLOCK];
        while copied < wanted {
            let position = offset + copied as u64;
            let index = position / BLOCK_BYTES as u64;
            if index >= self.blocks {
                return Err(invalid("decmpfs seek outside table"));
            }
            let mut bytes = [0; 8];
            let (at, stride) = match self.table {
                Table::Zlib { base, .. } => (base + 4 + index * 8, 8),
                Table::Offsets => (index * 4, 4),
            };
            fork.read_exact_at(at, &mut bytes)?;
            let (start, end) = self.entry(&bytes, stride)?;
            let length = (end - start) as usize;
            fork.read_exact_at(start, &mut encoded[..length])?;
            let expected =
                (self.header.size - index * BLOCK_BYTES as u64).min(BLOCK_BYTES as u64) as usize;
            let decoded = decode_block(self.header.kind, &encoded[..length], expected)?;
            let skip = (position % BLOCK_BYTES as u64) as usize;
            let count = (wanted - copied).min(decoded.len() - skip);
            output[copied..copied + count].copy_from_slice(&decoded[skip..skip + count]);
            copied += count;
        }
        Ok(copied)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(text: &str) -> Vec<u8> {
        text.as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|s| u8::from_str_radix(std::str::from_utf8(s).unwrap(), 16).unwrap())
            .collect()
    }

    // Encoded by Node's independently linked zlib, not flate2.
    fn zeros() -> Vec<u8> {
        hex(
            "789cedc101010000008090feafee080a0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006a000f0001",
        )
    }

    #[test]
    fn little_endian_header_and_unknown_codec_refusal() {
        for kind in [1u32, 3, 4, 7, 8, 9, 10, 11, 12, 13, 14] {
            let mut bytes = b"fpmc".to_vec();
            bytes.extend(kind.to_le_bytes());
            bytes.extend(0x123456789abcdef0u64.to_le_bytes());
            assert_eq!(
                Header::parse(&bytes).unwrap(),
                Header {
                    kind,
                    size: 0x123456789abcdef0
                }
            );
            bytes[..4].copy_from_slice(b"cmpf");
            assert!(Header::parse(&bytes).is_err());
        }
        let mut bytes = b"fpmc".to_vec();
        bytes.extend(99u32.to_le_bytes());
        bytes.extend(1u64.to_le_bytes());
        assert_eq!(
            Header::parse(&bytes).unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
        assert_eq!(
            Header::metadata(&bytes).unwrap(),
            Header { kind: 99, size: 1 }
        );
        assert!(Header::parse(&bytes[..15]).is_err());
    }

    #[test]
    fn independent_zlib_and_documented_lzvn_lzfse_units_decode_exactly() {
        assert_eq!(
            decode_block(3, &hex("789ccb48cdc9c90700062c0215"), 5).unwrap(),
            b"hello"
        );
        assert_eq!(
            decode_block(4, &zeros(), BLOCK_BYTES).unwrap(),
            vec![0; BLOCK_BYTES]
        );
        // Apple's LZVN literal opcode followed by the eight-byte EOS marker.
        let mut lzvn = vec![0xe5, b'h', b'e', b'l', b'l', b'o', 6, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(decode_block(7, &lzvn, 5).unwrap(), b"hello");
        lzvn.extend([0xac; 91]); // Resource units may contain bytes after EOS.
        assert_eq!(decode_block(8, &lzvn, 5).unwrap(), b"hello");
        let mut lzfse = b"bvx-".to_vec();
        lzfse.extend(5u32.to_le_bytes());
        lzfse.extend(b"hello");
        lzfse.extend(b"bvx$");
        assert_eq!(decode_block(11, &lzfse, 5).unwrap(), b"hello");
        assert_eq!(decode_block(1, b"", 0).unwrap(), b"");
        assert_eq!(decode_block(3, b"\xffhello", 5).unwrap(), b"hello");
        assert_eq!(decode_block(7, b"\x06hello", 5).unwrap(), b"hello");
        assert_eq!(decode_block(9, b"\xcchello", 5).unwrap(), b"hello");
    }

    #[test]
    fn malformed_units_and_declared_expansion_are_bounded_and_refused() {
        let encoded = hex("789ccb48cdc9c90700062c0215");
        for expected in [0, 4, 6, BLOCK_BYTES + 1] {
            assert!(decode_block(3, &encoded, expected).is_err());
        }
        for end in 0..encoded.len() {
            assert!(decode_block(3, &encoded[..end], 5).is_err());
        }
        let mut damaged = encoded.clone();
        *damaged.last_mut().unwrap() ^= 1;
        assert!(decode_block(3, &damaged, 5).is_err());
        let mut trailing = encoded;
        trailing.push(0);
        assert!(decode_block(3, &trailing, 5).is_err());
        assert!(decode_block(7, &[0xe5, b'h'], 5).is_err());
        assert!(decode_block(7, &[0x08, 1, 6], 6).is_err()); // Match before history.
        assert!(decode_block(7, &[0x06], 1).is_err());
        let bomb = [b"bvx-".as_slice(), &u32::MAX.to_le_bytes(), b"testbvx$"].concat();
        assert!(decode_block(11, &bomb, 4).is_err());
        assert!(decode_block(4, &vec![0xff; MAX_ENCODED_BLOCK + 1], BLOCK_BYTES).is_err());
    }

    fn offset_fork() -> Vec<u8> {
        let mut first = vec![6];
        first.extend(vec![0x31; BLOCK_BYTES]);
        let last = b"\x06tail";
        let mut output = Vec::new();
        output.extend(12u32.to_le_bytes());
        output.extend((12 + first.len() as u32).to_le_bytes());
        output.extend((12 + first.len() as u32 + last.len() as u32).to_le_bytes());
        output.extend(first);
        output.extend(last);
        output
    }

    #[test]
    fn offset_resource_seeks_cross_units_and_rejects_invalid_runs() {
        let bytes = offset_fork();
        let header = Header {
            kind: 8,
            size: BLOCK_BYTES as u64 + 4,
        };
        let resource = Resource::open(header, &mut bytes.as_slice()).unwrap();
        let mut output = [0; 9];
        assert_eq!(
            resource
                .read(&mut bytes.as_slice(), BLOCK_BYTES as u64 - 2, &mut output)
                .unwrap(),
            6
        );
        assert_eq!(&output[..6], b"11tail");
        assert_eq!(
            resource
                .read(&mut bytes.as_slice(), header.size, &mut output)
                .unwrap(),
            0
        );
        assert_eq!(
            resource
                .read(&mut bytes.as_slice(), u64::MAX, &mut output)
                .unwrap(),
            0
        );
        for (at, replacement) in [
            (0, 8u32),
            (4, 8),
            (8, bytes.len() as u32 - 1),
            (8, u32::MAX),
        ] {
            let mut corrupt = bytes.clone();
            corrupt[at..at + 4].copy_from_slice(&replacement.to_le_bytes());
            assert!(Resource::open(header, &mut corrupt.as_slice()).is_err());
        }
        assert!(
            Resource::open(
                Header {
                    size: header.size + BLOCK_BYTES as u64,
                    ..header
                },
                &mut bytes.as_slice()
            )
            .is_err()
        );
    }

    struct Huge {
        blocks: u64,
        compressed: Vec<u8>,
        maximum_read: usize,
        read_bytes: u64,
    }
    impl Huge {
        fn base(&self) -> u64 {
            20
        }
        fn table_end(&self) -> u64 {
            self.base() + 4 + self.blocks * 8
        }
        fn data_end(&self) -> u64 {
            self.table_end() + self.blocks * self.compressed.len() as u64
        }
        fn byte(&self, offset: u64) -> u8 {
            if offset < 16 {
                let fields = [
                    16u32,
                    self.data_end() as u32,
                    (self.data_end() - 16) as u32,
                    0,
                ];
                return fields[offset as usize / 4].to_be_bytes()[offset as usize % 4];
            }
            if offset < 20 {
                return ((self.data_end() - 20) as u32).to_be_bytes()[(offset - 16) as usize];
            }
            if offset < 24 {
                return (self.blocks as u32).to_le_bytes()[(offset - 20) as usize];
            }
            if offset < self.table_end() {
                let index = (offset - 24) / 8;
                let within = (offset - 24) % 8;
                let start = self.table_end() - self.base() + index * self.compressed.len() as u64;
                let value = if within < 4 {
                    start as u32
                } else {
                    self.compressed.len() as u32
                };
                return value.to_le_bytes()[within as usize % 4];
            }
            self.compressed[((offset - self.table_end()) % self.compressed.len() as u64) as usize]
        }
    }
    impl ReadAt for Huge {
        fn length(&self) -> u64 {
            self.data_end()
        }
        fn read_exact_at(&mut self, offset: u64, output: &mut [u8]) -> io::Result<()> {
            if offset
                .checked_add(output.len() as u64)
                .is_none_or(|end| end > self.length())
            {
                return Err(invalid("huge fixture out of bounds"));
            }
            self.maximum_read = self.maximum_read.max(output.len());
            self.read_bytes += output.len() as u64;
            for (index, byte) in output.iter_mut().enumerate() {
                *byte = self.byte(offset + index as u64);
            }
            Ok(())
        }
    }

    #[test]
    fn five_gib_resource_uses_bounded_table_pages_and_random_reads() {
        let size = 5 * 1024 * 1024 * 1024u64;
        let mut fork = Huge {
            blocks: size / BLOCK_BYTES as u64,
            compressed: zeros(),
            maximum_read: 0,
            read_bytes: 0,
        };
        let resource = Resource::open(Header { kind: 4, size }, &mut fork).unwrap();
        assert!(fork.maximum_read <= 4096);
        assert!(fork.read_bytes < 700_000);
        let validated_bytes = fork.read_bytes;
        for offset in [0, 1u64 << 32, size - 11, size, u64::MAX] {
            let mut output = [0x71; 17];
            let got = resource.read(&mut fork, offset, &mut output).unwrap();
            assert_eq!(got, size.saturating_sub(offset).min(17) as usize);
            assert!(output[..got].iter().all(|byte| *byte == 0));
            assert!(output[got..].iter().all(|byte| *byte == 0x71));
        }
        assert!(fork.read_bytes - validated_bytes < 1024);
        assert!(fork.maximum_read <= 4096);
    }
}
