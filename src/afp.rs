//! Bounded AFP_AfpInfo transport for catalog FinderInfo and native backup time.
use crate::windows::{Error, Result, Status};
fn invalid(message: &str) -> Error {
    Error {
        status: Status::Unsupported,
        detail: message.into(),
    }
}
const EPOCH: i64 = 3_029_529_600; // 1904 to 2000, in seconds.
pub fn encode(finder: &[u8; 32], backup: u32) -> Result<[u8; 60]> {
    let mut result = [0; 60];
    result[..4].copy_from_slice(b"AFP\0");
    result[4..8].copy_from_slice(&0x100u32.to_be_bytes());
    let time = if backup == 0 {
        0x80000000
    } else {
        let time = i32::try_from(i64::from(backup) - EPOCH)
            .map_err(|_| invalid("AFP backup date cannot represent native time"))?;
        if time == i32::MIN {
            return Err(invalid("AFP backup date collides with unknown-time marker"));
        }
        time as u32
    };
    result[12..16].copy_from_slice(&time.to_be_bytes());
    result[16..48].copy_from_slice(finder);
    Ok(result)
}
pub fn decode(bytes: &[u8]) -> Result<([u8; 32], u32)> {
    if bytes.len() != 60
        || &bytes[..4] != b"AFP\0"
        || bytes[4..8] != 0x100u32.to_be_bytes()
        || bytes[8..12].iter().chain(&bytes[48..60]).any(|b| *b != 0)
    {
        return Err(invalid(
            "unsupported AFP_AfpInfo signature, length, version or reserved/ProDOS fields",
        ));
    }
    let time = u32::from_be_bytes(bytes[12..16].try_into().unwrap());
    let backup = if time == 0x80000000 {
        0
    } else {
        u32::try_from(i64::from(time as i32) + EPOCH)
            .map_err(|_| invalid("AFP backup date exceeds native range"))?
    };
    Ok((bytes[16..48].try_into().unwrap(), backup))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn canonical_afp_wire_dates_and_reserved_fields() {
        let mut finder = [0; 32];
        finder[..8].copy_from_slice(b"TEXTttxt");
        finder[8] = 0x40;
        for backup in [0, 3_029_529_599, 3_029_529_600, 3_900_000_000, u32::MAX] {
            let bytes = encode(&finder, backup).unwrap();
            assert_eq!(&bytes[..8], b"AFP\0\0\0\x01\0");
            assert_eq!(decode(&bytes).unwrap(), (finder, backup));
            for position in [0, 4, 8, 48, 54, 59] {
                let mut bad = bytes;
                bad[position] ^= 1;
                assert!(decode(&bad).is_err());
            }
        }
        assert!(encode(&finder, 1).is_err());
        assert!(decode(&[0; 59]).is_err());
    }
}
