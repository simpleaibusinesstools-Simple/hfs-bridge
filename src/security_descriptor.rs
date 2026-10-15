//! Bounds validation before persisted Windows security bytes reach Win32.
//! Only self-relative owner/group and ordinary allow/deny DACLs are supported.
pub const ATTRIBUTE: &str = "org.hfsbridge.windows.security";
pub const MAX_BYTES: usize = 65_536;
const MAGIC: &[u8; 8] = b"HFSSEC01";

fn u16le(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap())
}
fn u32le(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}
fn range(bytes: &[u8], offset: usize, count: usize) -> Result<&[u8], &'static str> {
    offset
        .checked_add(count)
        .and_then(|end| bytes.get(offset..end))
        .ok_or("security component exceeds descriptor bounds")
}
fn sid(bytes: &[u8], offset: usize, limit: usize) -> Result<usize, &'static str> {
    let head = range(bytes, offset, 8)?;
    if head[0] != 1 || head[1] > 15 {
        return Err("unsupported SID revision or subauthority count");
    }
    let size = 8 + usize::from(head[1]) * 4;
    range(bytes, offset, size)?;
    if offset + size > limit {
        return Err("SID exceeds enclosing component");
    }
    Ok(size)
}
fn acl(bytes: &[u8], offset: usize) -> Result<usize, &'static str> {
    let head = range(bytes, offset, 8)?;
    if !matches!(head[0], 2 | 4) || head[1] != 0 || u16le(head, 6) != 0 {
        return Err("unsupported ACL header");
    }
    let size = usize::from(u16le(head, 2));
    if size < 8 || !size.is_multiple_of(4) {
        return Err("invalid ACL size");
    }
    range(bytes, offset, size)?;
    let end = offset + size;
    let mut cursor = offset + 8;
    for _ in 0..u16le(head, 4) {
        let ace = range(bytes, cursor, 8)?;
        if !matches!(ace[0], 0 | 1) || ace[1] & !0x1f != 0 {
            return Err("only ordinary allow and deny ACEs are supported");
        }
        let length = usize::from(u16le(ace, 2));
        if length < 16 || !length.is_multiple_of(4) || cursor + length > end {
            return Err("invalid ACE size");
        }
        if 8 + sid(bytes, cursor + 8, cursor + length)? != length {
            return Err("ACE contains trailing unsupported data");
        }
        cursor += length;
    }
    if cursor > end {
        return Err("ACE count exceeds ACL");
    }
    Ok(size)
}

/// Validate every offset and SID/ACE length without dereferencing native pointers.
pub fn validate(bytes: &[u8]) -> Result<(), &'static str> {
    if !(20..=MAX_BYTES).contains(&bytes.len()) || bytes[0] != 1 {
        return Err("invalid security descriptor size or revision");
    }
    let control = u16le(bytes, 2);
    if control & 0x8000 == 0 {
        return Err("absolute security descriptors are unsupported");
    }
    if control & 0x10 != 0 || u32le(bytes, 12) != 0 {
        return Err("persistent SACLs are not yet supported");
    }
    if control & 4 == 0 && u32le(bytes, 16) != 0 {
        return Err("DACL offset without presence flag");
    }
    let mut components = Vec::new();
    for field in [4, 8, 16] {
        let offset = u32le(bytes, field) as usize;
        if offset == 0 {
            continue;
        }
        if offset < 20 || !offset.is_multiple_of(4) {
            return Err("invalid security component offset");
        }
        let length = if field == 16 {
            acl(bytes, offset)?
        } else {
            sid(bytes, offset, bytes.len())?
        };
        let span = (offset, offset + length, field);
        for &(start, end, other) in &components {
            if offset < end
                && start < offset + length
                && !(field != 16 && other != 16 && (start, end) == (span.0, span.1))
            {
                return Err("overlapping security components");
            }
        }
        components.push(span);
    }
    Ok(())
}
pub fn encode(bytes: &[u8]) -> Result<Vec<u8>, &'static str> {
    validate(bytes)?;
    let mut result = MAGIC.to_vec();
    result.extend_from_slice(bytes);
    Ok(result)
}
pub fn decode(record: &[u8]) -> Result<&[u8], &'static str> {
    if record.len() < 8 || &record[..8] != MAGIC {
        return Err("unrecognized Windows security record");
    }
    validate(&record[8..])?;
    Ok(&record[8..])
}

#[cfg(test)]
mod tests {
    use super::*;
    fn descriptor() -> Vec<u8> {
        // Owner/group S-1-5-18, DACL grants FILE_ALL_ACCESS to that SID.
        let mut bytes = vec![1, 0, 4, 128];
        for value in [20u32, 20, 0, 32] {
            bytes.extend_from_slice(&value.to_le_bytes());
        }
        let sid = [1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0];
        bytes.extend_from_slice(&sid);
        bytes.extend_from_slice(&[2, 0, 28, 0, 1, 0, 0, 0, 0, 3, 20, 0, 255, 1, 31, 0]);
        bytes.extend_from_slice(&sid);
        bytes
    }
    #[test]
    fn bounded_security_records_roundtrip_and_reject_every_truncation() {
        let bytes = descriptor();
        validate(&bytes).unwrap();
        assert_eq!(decode(&encode(&bytes).unwrap()).unwrap(), bytes);
        for length in 0..bytes.len() {
            assert!(validate(&bytes[..length]).is_err(), "length {length}");
        }
        let mut deny = bytes.clone();
        deny[40] = 1;
        validate(&deny).unwrap();
        let mut null = bytes[..32].to_vec();
        null[16..20].fill(0);
        validate(&null).unwrap();
    }
    #[test]
    fn malformed_offsets_acls_and_unknown_aces_are_rejected() {
        let original = descriptor();
        for (offset, value) in [
            (0, 2),
            (3, 0),
            (4, 19),
            (4, 252),
            (12, 20),
            (16, 21),
            (32, 1),
            (34, 255),
            (36, 255),
            (40, 17),
            (41, 128),
            (42, 16),
            (49, 16),
        ] {
            let mut bytes = original.clone();
            bytes[offset] = value;
            assert!(validate(&bytes).is_err(), "offset {offset}, value {value}");
        }
        let mut overlap = original;
        overlap[8..12].copy_from_slice(&48u32.to_le_bytes());
        assert!(validate(&overlap).is_err());
        assert!(decode(b"HFSSEC02").is_err());
    }
}
