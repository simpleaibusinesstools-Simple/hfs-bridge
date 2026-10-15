//! Versioned Windows EA transport for exact, case-sensitive Mac names.
//! The digest alias is case-insensitive; the envelope retains the original
//! UTF-16 name and distinguishes an empty Mac value from EA deletion.
use crate::windows::{Error, Result, Status};
use std::collections::BTreeSet;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub name: Vec<u8>,
    pub value: Vec<u8>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Change {
    pub name: String,
    pub value: Option<Vec<u8>>,
}
pub(crate) const NATIVE_PACKET_BYTES: usize = 12288;
pub(crate) type Values = Vec<(String, Vec<u8>)>;
/// One deterministic projection, shared by EAs and their supplementary stream.
/// Keeping the representations disjoint prevents stale NTFS metadata shadows.
pub(crate) fn partition_values(mut values: Values) -> (Values, Values) {
    values.sort_by_key(|(name, _)| {
        (
            name != "com.apple.FinderInfo",
            name.encode_utf16().collect::<Vec<_>>(),
        )
    });
    let mut used = 0;
    let mut eas = Vec::new();
    let mut supplemental = Vec::new();
    for (name, value) in values {
        let length =
            (9 + 69 + 8 + name.encode_utf16().count() * 2 + value.len()).next_multiple_of(4);
        if used + length <= NATIVE_PACKET_BYTES {
            used += length;
            eas.push((name, value));
        } else {
            supplemental.push((name, value));
        }
    }
    (eas, supplemental)
}
fn invalid(message: &str) -> Error {
    Error {
        status: Status::InvalidParameter,
        detail: message.into(),
    }
}
fn units(name: &str) -> Result<Vec<u16>> {
    let units = name.encode_utf16().collect::<Vec<_>>();
    if units.is_empty() || units.len() > 127 || units.contains(&0) {
        return Err(invalid("invalid Mac attribute name"));
    }
    Ok(units)
}
pub fn alias(name: &str) -> Result<Vec<u8>> {
    let raw = units(name)?
        .into_iter()
        .flat_map(u16::to_le_bytes)
        .collect::<Vec<_>>();
    let hash = crate::engine::sha256(&mut &raw[..])
        .map_err(|_| invalid("attribute name digest failed"))?;
    Ok(format!("HFSB_{}", hash.to_ascii_uppercase()).into_bytes())
}
pub fn pack_value(name: &str, data: &[u8]) -> Result<Vec<u8>> {
    let units = units(name)?;
    if data.len() > 65535 - 8 - units.len() * 2 {
        return Err(Error {
            status: Status::Unsupported,
            detail: "Mac attribute envelope exceeds Windows EA value limit".into(),
        });
    }
    let mut bytes = Vec::with_capacity(8 + units.len() * 2 + data.len());
    bytes.extend_from_slice(b"HFSB");
    bytes.push(1);
    bytes.push(units.len() as u8);
    bytes.extend_from_slice(&[0; 2]);
    bytes.extend(units.into_iter().flat_map(u16::to_le_bytes));
    bytes.extend_from_slice(data);
    Ok(bytes)
}
fn unpack_value(bytes: &[u8]) -> Result<(String, Vec<u8>)> {
    if bytes.len() < 8 || &bytes[..4] != b"HFSB" || bytes[4] != 1 || bytes[6..8] != [0; 2] {
        return Err(invalid("invalid Mac attribute EA envelope"));
    }
    let length = usize::from(bytes[5]);
    let end = 8 + length * 2;
    if length == 0 || length > 127 || end > bytes.len() || bytes.len() > 65535 {
        return Err(invalid("invalid Mac attribute EA envelope length"));
    }
    let encoded = bytes[8..end]
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u16::from_le_bytes(*pair))
        .collect::<Vec<_>>();
    if encoded.contains(&0) {
        return Err(invalid("NUL in Mac attribute name"));
    }
    let name =
        String::from_utf16(&encoded).map_err(|_| invalid("invalid Mac attribute name UTF-16"))?;
    Ok((name, bytes[end..].to_vec()))
}
pub fn records(values: &[(String, Vec<u8>)]) -> Result<Vec<Record>> {
    values
        .iter()
        .map(|(name, value)| {
            Ok(Record {
                name: alias(name)?,
                value: pack_value(name, value)?,
            })
        })
        .collect()
}
pub fn encode(records: &[Record]) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    let mut names = BTreeSet::new();
    for (index, record) in records.iter().enumerate() {
        if record.name.is_empty()
            || record.name.len() > 254
            || !record.name.is_ascii()
            || record.name.contains(&0)
            || record.value.len() > 65535
            || !names.insert(record.name.to_ascii_uppercase())
        {
            return Err(invalid("invalid or duplicate Windows EA record"));
        }
        let length = 9 + record.name.len() + record.value.len();
        let padded = length.next_multiple_of(4);
        if bytes.len() + padded > 65535 {
            return Err(Error {
                status: Status::Unsupported,
                detail: "Windows EA transport exceeds 64 KiB".into(),
            });
        }
        let start = bytes.len();
        bytes.resize(start + padded, 0);
        bytes[start..start + 4].copy_from_slice(
            &(if index + 1 == records.len() {
                0
            } else {
                padded as u32
            })
            .to_le_bytes(),
        );
        bytes[start + 5] = record.name.len() as u8;
        bytes[start + 6..start + 8].copy_from_slice(&(record.value.len() as u16).to_le_bytes());
        bytes[start + 8..start + 8 + record.name.len()].copy_from_slice(&record.name);
        bytes[start + 9 + record.name.len()..start + length].copy_from_slice(&record.value);
    }
    Ok(bytes)
}
pub fn parse(bytes: &[u8]) -> Result<Vec<Record>> {
    if bytes.len() > 65535 {
        return Err(invalid("Windows EA buffer exceeds 64 KiB"));
    }
    let mut result = Vec::new();
    let mut offset = 0;
    let mut names = BTreeSet::new();
    while offset < bytes.len() {
        if bytes.len() - offset < 8 {
            return Err(invalid("truncated Windows EA header"));
        }
        let next = u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap()) as usize;
        if bytes[offset + 4] != 0 {
            return Err(Error {
                status: Status::Unsupported,
                detail: "FILE_NEED_EA flags need dedicated semantics".into(),
            });
        }
        let name_len = usize::from(bytes[offset + 5]);
        let value_len = usize::from(u16::from_le_bytes(
            bytes[offset + 6..offset + 8].try_into().unwrap(),
        ));
        let length = 9 + name_len + value_len;
        let end = offset + length;
        if name_len == 0 || name_len > 254 || end > bytes.len() || bytes[offset + 8 + name_len] != 0
        {
            return Err(invalid("invalid Windows EA name/value bounds"));
        }
        let name = &bytes[offset + 8..offset + 8 + name_len];
        if !name.is_ascii() || name.contains(&0) || !names.insert(name.to_ascii_uppercase()) {
            return Err(invalid("invalid or duplicate Windows EA name"));
        }
        result.push(Record {
            name: name.to_vec(),
            value: bytes[offset + 9 + name_len..end].to_vec(),
        });
        if next == 0 {
            if bytes.len() - end > 3 {
                return Err(invalid("extra data after final Windows EA record"));
            }
            break;
        }
        if !next.is_multiple_of(4)
            || next < length
            || next > bytes.len() - offset
            || offset + next == bytes.len()
        {
            return Err(invalid("invalid Windows EA next offset"));
        }
        offset += next;
    }
    Ok(result)
}
pub fn changes(bytes: &[u8], current_names: &[String]) -> Result<Vec<Change>> {
    let mut output = Vec::new();
    for record in parse(bytes)? {
        let canonical = record.name.to_ascii_uppercase();
        if canonical.len() != 69
            || &canonical[..5] != b"HFSB_"
            || !canonical[5..].iter().all(u8::is_ascii_hexdigit)
        {
            return Err(Error {
                status: Status::Unsupported,
                detail: "unsupported Windows EA namespace".into(),
            });
        }
        let (name, value) = if record.value.is_empty() {
            let mut found = None;
            for name in current_names {
                if alias(name)? == canonical {
                    found = Some(name.clone());
                    break;
                }
            }
            (
                found.ok_or(Error {
                    status: Status::NotFound,
                    detail: "deleted EA alias does not identify an existing Mac attribute".into(),
                })?,
                None,
            )
        } else {
            let (name, value) = unpack_value(&record.value)?;
            if alias(&name)? != canonical {
                return Err(invalid("EA alias does not match its exact Mac name"));
            }
            (name, Some(value))
        };
        output.push(Change { name, value });
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn transport_roundtrips_case_unicode_long_names_and_empty_values() {
        let values = vec![
            ("com.example.CASE".into(), b"UPPER\0\xff".to_vec()),
            ("com.example.case".into(), b"lower".to_vec()),
            ("é".into(), vec![]),
            ("e\u{301}".into(), vec![0x80]),
            ("com.example.large".into(), vec![0x39; 20_019]),
            ("🧭".repeat(63) + "x", vec![0x37; 3802]),
        ];
        let packet = encode(&records(&values).unwrap()).unwrap();
        let decoded = changes(&packet, &[]).unwrap();
        assert_eq!(
            decoded,
            values
                .into_iter()
                .map(|(name, value)| Change {
                    name,
                    value: Some(value)
                })
                .collect::<Vec<_>>()
        );
        let mut lower = parse(&packet).unwrap();
        for record in &mut lower {
            record.name.make_ascii_lowercase();
        }
        assert_eq!(changes(&encode(&lower).unwrap(), &[]).unwrap(), decoded);
        assert_ne!(
            alias("com.example.CASE").unwrap(),
            alias("com.example.case").unwrap()
        );
        assert_ne!(alias("é").unwrap(), alias("e\u{301}").unwrap());
    }
    #[test]
    fn deletion_uses_existing_exact_name_and_does_not_confuse_empty_values() {
        let name = "com.example.empty".to_owned();
        let packet = encode(&records(&[(name.clone(), vec![])]).unwrap()).unwrap();
        assert_eq!(changes(&packet, &[]).unwrap()[0].value, Some(vec![]));
        let deletion = encode(&[Record {
            name: alias(&name).unwrap(),
            value: vec![],
        }])
        .unwrap();
        assert_eq!(
            changes(&deletion, std::slice::from_ref(&name)).unwrap(),
            vec![Change { name, value: None }]
        );
        assert!(changes(&deletion, &[]).is_err());
    }
    #[test]
    fn malformed_or_forged_ea_batches_are_rejected_before_engine_use() {
        let packet = encode(
            &records(&[
                ("com.example.one".into(), b"value".to_vec()),
                ("com.example.two".into(), vec![]),
            ])
            .unwrap(),
        )
        .unwrap();
        for variant in 0..9 {
            let mut bad = packet.clone();
            match variant {
                0 => bad[0..4].copy_from_slice(&4u32.to_le_bytes()),
                1 => bad[0..4].copy_from_slice(&u32::MAX.to_le_bytes()),
                2 => bad[4] = 0x80,
                3 => bad[5] = 0,
                4 => bad[6..8].copy_from_slice(&65535u16.to_le_bytes()),
                5 => bad[8] = b'X',
                6 => bad[13] ^= 1,
                7 => bad[8 + 69] = 1,
                8 => bad[9 + 69 + 4] = 2,
                _ => unreachable!(),
            }
            assert!(changes(&bad, &[]).is_err(), "variant {variant}");
        }
        let duplicate = records(&[("same".into(), vec![]), ("same".into(), vec![])]).unwrap();
        assert!(encode(&duplicate).is_err());
        assert!(pack_value("name", &vec![0; 65536]).is_err());
    }
}
