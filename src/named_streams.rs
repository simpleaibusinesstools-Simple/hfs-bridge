//! Bounded storage codec for ordinary Windows named streams.
//! Used by native callbacks. Checksums detect corruption, not
//! authenticity; private-metadata admission must be enforced by the adapter.
use crate::windows::{Error, Result, Status};
use sha2::{Digest, Sha256};
use std::cmp::Ordering;

mod mutations;

pub const ATTRIBUTE: &str = "org.hfsbridge.windows.streams";
pub const MAX_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_STREAMS: usize = 128;
const MAGIC: &[u8; 8] = b"HFSBADS1";
const HEADER: usize = 32;
const RECORD: usize = 28;
const DIGEST: usize = 32;

fn invalid(detail: &str) -> Error {
    Error {
        status: Status::InvalidParameter,
        detail: detail.into(),
    }
}

/// Stream names are not directory components: no HFS normalization, device-name
/// exclusion or trailing-dot trimming. NTFS accepts control characters and the
/// usual filename punctuation here. Separators, NUL and stream-type colons are
/// excluded. Existing special streams have a separate storage protocol.
pub fn validate_name(name: &str) -> Result<()> {
    let length = name.encode_utf16().count();
    if length == 0
        || length > 255
        || name.contains(['\0', ':', '/', '\\'])
        || ["AFP_Resource", "AFP_AfpInfo", "HFSB_Attributes"]
            .iter()
            .any(|reserved| name.eq_ignore_ascii_case(reserved))
    {
        return Err(invalid("invalid or reserved named stream"));
    }
    Ok(())
}

pub fn same_name(a: &str, b: &str) -> Result<bool> {
    validate_name(a)?;
    validate_name(b)?;
    crate::names::ordinal(
        &a.encode_utf16().collect::<Vec<_>>(),
        &b.encode_utf16().collect::<Vec<_>>(),
    )
    .map(|order| order == Ordering::Equal)
    .map_err(|_| invalid("Windows stream-name comparison failed"))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Stream {
    pub id: u64,
    pub name: String,
    pub data: Vec<u8>,
    /// Stored zero padding reserves bytes independently of logical EOF.
    pub allocation: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Store {
    /// Strictly greater than every live id. Deleting a stream must not lower it.
    pub next_id: u64,
    pub streams: Vec<Stream>,
}
impl Default for Store {
    fn default() -> Self {
        Self {
            next_id: 1,
            streams: Vec::new(),
        }
    }
}

fn validate(store: &Store) -> Result<usize> {
    if store.next_id == 0 || store.streams.len() > MAX_STREAMS {
        return Err(invalid("invalid named-stream count or next identity"));
    }
    let mut size = HEADER + DIGEST;
    for (index, stream) in store.streams.iter().enumerate() {
        validate_name(&stream.name)?;
        if stream.id == 0
            || stream.id >= store.next_id
            || stream.allocation > MAX_BYTES as u64
            || stream.data.len() as u64 > stream.allocation
        {
            return Err(invalid("invalid named-stream identity or size"));
        }
        for old in &store.streams[..index] {
            if old.id == stream.id || same_name(&old.name, &stream.name)? {
                return Err(invalid("duplicate named-stream identity or Windows name"));
            }
        }
        size = size
            .checked_add(RECORD + 2 * stream.name.encode_utf16().count())
            .and_then(|n| n.checked_add(stream.allocation as usize))
            .filter(|&n| n <= MAX_BYTES)
            .ok_or_else(|| invalid("named-stream store exceeds 16MiB"))?;
    }
    Ok(size)
}

pub fn encode(store: &Store) -> Result<Vec<u8>> {
    let size = validate(store)?;
    let mut bytes = Vec::with_capacity(size);
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&(store.streams.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&store.next_id.to_le_bytes());
    bytes.extend_from_slice(&(size as u64).to_le_bytes());
    let mut order = store.streams.iter().collect::<Vec<_>>();
    order.sort_by_key(|stream| stream.id);
    for stream in order {
        bytes.extend_from_slice(&stream.id.to_le_bytes());
        bytes.extend_from_slice(&(stream.data.len() as u64).to_le_bytes());
        bytes.extend_from_slice(&stream.allocation.to_le_bytes());
        bytes.extend_from_slice(&(stream.name.encode_utf16().count() as u16).to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend(stream.name.encode_utf16().flat_map(u16::to_le_bytes));
        bytes.extend_from_slice(&stream.data);
        bytes.resize(
            bytes.len() + stream.allocation as usize - stream.data.len(),
            0,
        );
    }
    bytes.extend_from_slice(&Sha256::digest(&bytes));
    debug_assert_eq!(bytes.len(), size);
    Ok(bytes)
}

pub fn decode(bytes: &[u8]) -> Result<Store> {
    if !(HEADER + DIGEST..=MAX_BYTES).contains(&bytes.len())
        || &bytes[..8] != MAGIC
        || bytes[12..16] != [0; 4]
        || u64::from_le_bytes(bytes[24..32].try_into().unwrap()) != bytes.len() as u64
    {
        return Err(invalid("invalid named-stream store header"));
    }
    let end = bytes.len() - DIGEST;
    if Sha256::digest(&bytes[..end]).as_slice() != &bytes[end..] {
        return Err(invalid("named-stream checksum mismatch"));
    }
    let count = u32::from_le_bytes(bytes[8..12].try_into().unwrap()) as usize;
    if count > MAX_STREAMS {
        return Err(invalid("too many named streams"));
    }
    let mut store = Store {
        next_id: u64::from_le_bytes(bytes[16..24].try_into().unwrap()),
        streams: Vec::with_capacity(count),
    };
    let mut offset = HEADER;
    let mut previous_id = 0;
    for _ in 0..count {
        let header_end = offset
            .checked_add(RECORD)
            .filter(|&n| n <= end)
            .ok_or_else(|| invalid("short named-stream record"))?;
        let record = &bytes[offset..header_end];
        let id = u64::from_le_bytes(record[..8].try_into().unwrap());
        let length = u64::from_le_bytes(record[8..16].try_into().unwrap());
        let allocation = u64::from_le_bytes(record[16..24].try_into().unwrap());
        let units = u16::from_le_bytes(record[24..26].try_into().unwrap()) as usize;
        if id <= previous_id
            || length > allocation
            || allocation > MAX_BYTES as u64
            || !(1..=255).contains(&units)
            || record[26..28] != [0; 2]
        {
            return Err(invalid("invalid named-stream record"));
        }
        let name_end = header_end
            .checked_add(units * 2)
            .filter(|&n| n <= end)
            .ok_or_else(|| invalid("short stream name"))?;
        let data_end = name_end
            .checked_add(allocation as usize)
            .filter(|&n| n <= end)
            .ok_or_else(|| invalid("short stream allocation"))?;
        let logical_end = name_end + length as usize;
        if bytes[logical_end..data_end].iter().any(|&byte| byte != 0) {
            return Err(invalid("nonzero uninitialized stream allocation"));
        }
        let name = String::from_utf16(
            &bytes[header_end..name_end]
                .as_chunks::<2>()
                .0
                .iter()
                .map(|pair| u16::from_le_bytes(*pair))
                .collect::<Vec<_>>(),
        )
        .map_err(|_| invalid("invalid stream UTF-16"))?;
        store.streams.push(Stream {
            id,
            name,
            data: bytes[name_end..logical_end].to_vec(),
            allocation,
        });
        previous_id = id;
        offset = data_end;
    }
    if offset != end {
        return Err(invalid("trailing named-stream bytes"));
    }
    validate(&store)?;
    Ok(store)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> Store {
        Store {
            next_id: 7,
            streams: vec![
                Stream {
                    id: 2,
                    name: "Zone.Identifier".into(),
                    data: b"[ZoneTransfer]\r\nZoneId=3\r\n".to_vec(),
                    allocation: 4096,
                },
                Stream {
                    id: 6,
                    name: "empty 🐟. ".into(),
                    data: Vec::new(),
                    allocation: 0,
                },
            ],
        }
    }
    fn resign(bytes: &mut [u8]) {
        let end = bytes.len() - DIGEST;
        let hash = Sha256::digest(&bytes[..end]);
        bytes[end..].copy_from_slice(&hash);
    }
    #[test]
    fn exact_bytes_empty_streams_allocation_and_monotonic_ids_roundtrip() {
        for store in [Store::default(), fixture()] {
            assert_eq!(decode(&encode(&store).unwrap()).unwrap(), store);
        }
        let mut store = fixture();
        store.streams.reverse();
        assert_eq!(encode(&store).unwrap(), encode(&fixture()).unwrap());
        store.streams.clear();
        assert_eq!(decode(&encode(&store).unwrap()).unwrap().next_id, 7);
    }
    #[test]
    fn names_match_observed_ntfs_rules_without_hfs_normalization() {
        for name in [
            "Zone.Identifier",
            ".",
            "..",
            "$DATA",
            "CON",
            "name.",
            "name ",
            "\u{1}control",
            "bad?name",
            r#"<>"|*"#,
            "é",
            "e\u{301}",
        ] {
            validate_name(name).unwrap();
        }
        validate_name(&"a".repeat(255)).unwrap();
        for name in [
            "",
            "nul\0",
            "colon:type",
            "a/b",
            "a\\b",
            "AFP_resource",
            "afp_afpinfo",
            "hfsb_attributes",
            &"a".repeat(256),
        ] {
            assert!(validate_name(name).is_err(), "{name:?}");
        }
        assert!(same_name("Zone.Identifier", "zone.identifier").unwrap());
        assert!(!same_name("é", "e\u{301}").unwrap());
        assert!(!same_name("name.", "name ").unwrap());
    }
    #[test]
    fn duplicate_names_ids_and_declared_bounds_are_refused() {
        let mut store = fixture();
        store.streams[1].name = "zone.identifier".into();
        assert!(encode(&store).is_err());
        let mut store = fixture();
        store.streams[1].id = 2;
        assert!(encode(&store).is_err());
        for next in [0, 2, 6] {
            let mut store = fixture();
            store.next_id = next;
            assert!(encode(&store).is_err());
        }
        let mut store = fixture();
        store.streams[0].allocation = 1;
        assert!(encode(&store).is_err());
        store.streams[0].allocation = u64::MAX;
        assert!(encode(&store).is_err());
        let mut store = Store {
            next_id: MAX_STREAMS as u64 + 2,
            streams: (1..=MAX_STREAMS as u64 + 1)
                .map(|id| Stream {
                    id,
                    name: format!("s{id}"),
                    data: vec![],
                    allocation: 0,
                })
                .collect(),
        };
        assert!(encode(&store).is_err());
        store.streams.pop();
        assert_eq!(
            decode(&encode(&store).unwrap()).unwrap().streams.len(),
            MAX_STREAMS
        );
    }
    #[test]
    fn every_truncation_and_single_byte_corruption_is_refused() {
        let bytes = encode(&fixture()).unwrap();
        for end in 0..bytes.len() {
            assert!(decode(&bytes[..end]).is_err());
        }
        for index in 0..bytes.len() {
            let mut bad = bytes.clone();
            bad[index] ^= 1;
            assert!(decode(&bad).is_err());
        }
    }
    #[test]
    fn checksummed_malformed_records_fail_before_exposing_data() {
        let original = encode(&fixture()).unwrap();
        for (offset, bytes) in [
            (8, (MAX_STREAMS as u32 + 1).to_le_bytes().to_vec()),
            (12, 1u32.to_le_bytes().to_vec()),
            (16, 0u64.to_le_bytes().to_vec()),
            (32, 0u64.to_le_bytes().to_vec()),
            (40, u64::MAX.to_le_bytes().to_vec()),
            (48, u64::MAX.to_le_bytes().to_vec()),
            (56, 0u16.to_le_bytes().to_vec()),
            (58, 1u16.to_le_bytes().to_vec()),
            (60, 0xd800u16.to_le_bytes().to_vec()),
            (60, 0u16.to_le_bytes().to_vec()),
            (160, vec![1]),
        ] {
            let mut bad = original.clone();
            bad[offset..offset + bytes.len()].copy_from_slice(&bytes);
            resign(&mut bad);
            assert!(decode(&bad).is_err(), "offset {offset}");
        }
    }
    #[test]
    fn total_encoded_limit_includes_names_headers_and_reserved_allocation() {
        let overhead = HEADER + RECORD + 2 + DIGEST;
        let mut store = Store {
            next_id: 2,
            streams: vec![Stream {
                id: 1,
                name: "x".into(),
                data: vec![19],
                allocation: (MAX_BYTES - overhead) as u64,
            }],
        };
        let bytes = encode(&store).unwrap();
        assert_eq!(bytes.len(), MAX_BYTES);
        assert_eq!(decode(&bytes).unwrap(), store);
        store.streams[0].allocation += 1;
        assert!(encode(&store).is_err());
    }
}
