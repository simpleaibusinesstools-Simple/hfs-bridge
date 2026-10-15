//! Bounded, exact-name attribute snapshot carried by one Windows data stream.
//! The checksum detects incomplete/corrupt transfers; it is not authentication.
use crate::windows::{Error, Result, Status};
use sha2::{Digest, Sha256};

pub const STREAM: &str = "HFSB_Attributes";
pub const MAX_VALUE_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_RECORDS: usize = 256;
pub const MAX_BYTES: usize = MAX_VALUE_BYTES + MAX_RECORDS * (8 + 254) + 56;
const MAGIC: &[u8; 8] = b"HFSBXA1\0";
fn invalid(message: &str) -> Error {
    Error {
        status: Status::InvalidParameter,
        detail: message.into(),
    }
}
fn name_units(name: &str) -> Result<Vec<u16>> {
    let units = name.encode_utf16().collect::<Vec<_>>();
    if units.is_empty()
        || units.len() > 127
        || units.contains(&0)
        || matches!(name, "com.apple.FinderInfo" | "com.apple.ResourceFork")
    {
        return Err(invalid("invalid attribute archive name"));
    }
    Ok(units)
}
pub struct Snapshot {
    pub projected: bool,
    /// None means that the value is supplied by the accompanying Windows EAs.
    pub records: Vec<(String, Option<Vec<u8>>)>,
}
pub fn encode(values: &[(String, Vec<u8>)]) -> Result<Vec<u8>> {
    encode_records(
        &values
            .iter()
            .map(|(name, value)| (name.as_str(), Some(value.as_slice())))
            .collect::<Vec<_>>(),
        false,
    )
}
pub(crate) fn encode_projected(
    eas: &[(String, Vec<u8>)],
    supplemental: &[(String, Vec<u8>)],
) -> Result<Vec<u8>> {
    let records = eas
        .iter()
        .map(|(name, _)| (name.as_str(), None))
        .chain(
            supplemental
                .iter()
                .map(|(name, value)| (name.as_str(), Some(value.as_slice()))),
        )
        .collect::<Vec<_>>();
    encode_records(&records, true)
}
fn encode_records(values: &[(&str, Option<&[u8]>)], projected: bool) -> Result<Vec<u8>> {
    if values.len() > MAX_RECORDS {
        return Err(invalid("too many archive attributes"));
    }
    let mut sorted = values
        .iter()
        .map(|(name, value)| Ok((name_units(name)?, *value)))
        .collect::<Result<Vec<_>>>()?;
    sorted.sort_by(|a, b| a.0.cmp(&b.0));
    if sorted.windows(2).any(|pair| pair[0].0 == pair[1].0) {
        return Err(invalid("duplicate archive name"));
    }
    let total_values = sorted
        .iter()
        .try_fold(0usize, |sum, (_, value)| {
            sum.checked_add(value.map_or(0, <[u8]>::len))
        })
        .ok_or_else(|| invalid("archive length overflow"))?;
    if total_values > MAX_VALUE_BYTES {
        return Err(invalid("archive values exceed 16MiB"));
    }
    let mut bytes = vec![0; 24];
    bytes[..8].copy_from_slice(MAGIC);
    bytes[8..12].copy_from_slice(&(values.len() as u32).to_le_bytes());
    bytes[12..16].copy_from_slice(&u32::from(projected).to_le_bytes());
    for (name, value) in sorted {
        bytes.extend_from_slice(&(name.len() as u16).to_le_bytes());
        bytes.extend_from_slice(&u16::from(value.is_none()).to_le_bytes());
        let value = value.unwrap_or_default();
        bytes.extend_from_slice(&(value.len() as u32).to_le_bytes());
        bytes.extend(name.into_iter().flat_map(u16::to_le_bytes));
        bytes.extend_from_slice(value);
    }
    let size = bytes.len() + 32;
    bytes[16..24].copy_from_slice(&(size as u64).to_le_bytes());
    bytes.extend_from_slice(&Sha256::digest(&bytes));
    Ok(bytes)
}
pub fn declared_size(bytes: &[u8]) -> Result<Option<usize>> {
    if bytes.len() < 24 {
        return Ok(None);
    }
    if &bytes[..8] != MAGIC || u32::from_le_bytes(bytes[12..16].try_into().unwrap()) > 1 {
        return Err(invalid("invalid attribute archive header"));
    }
    let count = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
    let size = u64::from_le_bytes(bytes[16..24].try_into().unwrap());
    if count as usize > MAX_RECORDS || !(56..=MAX_BYTES as u64).contains(&size) {
        return Err(invalid("invalid attribute archive bounds"));
    }
    Ok(Some(size as usize))
}
pub fn decode(bytes: &[u8]) -> Result<Vec<(String, Vec<u8>)>> {
    let snapshot = decode_snapshot(bytes)?;
    if snapshot.projected {
        return Err(invalid("projected archive requires accompanying EAs"));
    }
    Ok(snapshot
        .records
        .into_iter()
        .map(|(name, value)| (name, value.unwrap()))
        .collect())
}
pub fn decode_snapshot(bytes: &[u8]) -> Result<Snapshot> {
    if declared_size(bytes)? != Some(bytes.len()) {
        return Err(invalid("incomplete attribute archive"));
    }
    let end = bytes.len() - 32;
    if Sha256::digest(&bytes[..end])[..] != bytes[end..] {
        return Err(invalid("attribute archive checksum mismatch"));
    }
    let count = u32::from_le_bytes(bytes[8..12].try_into().unwrap()) as usize;
    let projected = bytes[12] == 1;
    let mut cursor = 24;
    let mut values = Vec::with_capacity(count);
    let mut previous = Vec::new();
    let mut total_values = 0usize;
    for _ in 0..count {
        let header = bytes
            .get(cursor..cursor + 8)
            .filter(|_| cursor + 8 <= end)
            .ok_or_else(|| invalid("truncated archive record"))?;
        let units = u16::from_le_bytes(header[..2].try_into().unwrap()) as usize;
        let length = u32::from_le_bytes(header[4..8].try_into().unwrap()) as usize;
        let reference = u16::from_le_bytes(header[2..4].try_into().unwrap());
        if units == 0
            || units > 127
            || reference > 1
            || (reference == 1 && (!projected || length != 0))
        {
            return Err(invalid("invalid archive name length"));
        }
        cursor += 8;
        let name_end = cursor + units * 2;
        let value_end = name_end
            .checked_add(length)
            .filter(|&n| n <= end)
            .ok_or_else(|| invalid("truncated archive value"))?;
        let raw = bytes[cursor..name_end]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u16::from_le_bytes(*pair))
            .collect::<Vec<_>>();
        if raw <= previous {
            return Err(invalid("archive names are not strictly ordered"));
        }
        let name = String::from_utf16(&raw).map_err(|_| invalid("invalid archive UTF16"))?;
        name_units(&name)?;
        previous = raw;
        total_values = total_values
            .checked_add(length)
            .filter(|&n| n <= MAX_VALUE_BYTES)
            .ok_or_else(|| invalid("archive values exceed 16MiB"))?;
        values.push((
            name,
            (reference == 0).then(|| bytes[name_end..value_end].to_vec()),
        ));
        cursor = value_end;
    }
    if cursor != end {
        return Err(invalid("trailing archive records"));
    }
    Ok(Snapshot {
        projected,
        records: values,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn archive_roundtrip_keeps_exact_names_binary_empty_and_large_values() {
        let values = vec![
            ("Case".into(), vec![7; 70019]),
            ("case".into(), vec![]),
            ("\u{1F30A}\u{301}".into(), vec![0, 255]),
            ("z".repeat(127), vec![9]),
        ];
        let bytes = encode(&values).unwrap();
        let mut expected = values;
        expected.sort_by_key(|(name, _)| name.encode_utf16().collect::<Vec<_>>());
        assert_eq!(decode(&bytes).unwrap(), expected);
        assert_eq!(decode(&encode(&[]).unwrap()).unwrap(), vec![]);
    }
    #[test]
    fn archive_refuses_incomplete_corrupt_duplicate_and_out_of_bounds_inputs() {
        let bytes = encode(&[("x".into(), vec![2; 33])]).unwrap();
        for size in 0..bytes.len() {
            assert!(decode(&bytes[..size]).is_err());
        }
        for offset in 0..bytes.len() {
            let mut bad = bytes.clone();
            bad[offset] ^= 1;
            assert!(decode(&bad).is_err());
        }
        assert!(encode(&[("x".into(), vec![]), ("x".into(), vec![1])]).is_err());
        assert!(encode(&[("x".repeat(128), vec![])]).is_err());
        assert!(encode(&[("com.apple.FinderInfo".into(), vec![0; 32])]).is_err());
        assert!(encode(&[("x".into(), vec![0; MAX_VALUE_BYTES + 1])]).is_err());
    }
    #[test]
    fn projected_references_are_distinct_from_empty_values_and_malformed_flags() {
        let bytes = encode_projected(
            &[("small".into(), vec![7])],
            &[("large".into(), vec![2; 20019]), ("empty".into(), vec![])],
        )
        .unwrap();
        let snapshot = decode_snapshot(&bytes).unwrap();
        assert!(snapshot.projected);
        assert_eq!(
            snapshot.records,
            vec![
                ("empty".into(), Some(vec![])),
                ("large".into(), Some(vec![2; 20019])),
                ("small".into(), None)
            ]
        );
        assert!(decode(&bytes).is_err());
        for variant in 0..3 {
            let mut malformed = bytes.clone();
            match variant {
                0 => malformed[12] = 0,
                1 => malformed[26] = 2,
                2 => {
                    malformed[26] = 1;
                    malformed[28] = 1;
                }
                _ => unreachable!(),
            }
            let end = malformed.len() - 32;
            let checksum = Sha256::digest(&malformed[..end]);
            malformed[end..].copy_from_slice(&checksum);
            assert!(decode_snapshot(&malformed).is_err());
        }
    }
}
