//! Full nonnegative Windows timestamps with explicit HFS catalog projections.
//! Version 1 stays byte-identical for representable dates. Version 2 is used
//! only when a precise date falls outside the native 1904/u32-second range.
use super::*;

pub const EXTENDED_BYTES: usize = 128;

pub fn catalog_seconds(date: u64) -> Result<u32, RecordError> {
    if date > i64::MAX as u64 {
        return Err(RecordError::InvalidDate);
    }
    let first = crate::windows::hfs_to_filetime(0);
    Ok(date
        .saturating_sub(first)
        .div_euclid(u64::from(TICKS))
        .min(u64::from(u32::MAX)) as u32)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExtendedRecord([u8; EXTENDED_BYTES]);
impl ExtendedRecord {
    pub fn new(
        g: Generation,
        cnid: u32,
        kind: EntryKind,
        seconds: [u32; 4],
        dates: [Option<u64>; 4],
    ) -> Result<Self, RecordError> {
        if !valid_identity(cnid, kind) {
            return Err(RecordError::InvalidIdentity);
        }
        let mut b = [0; EXTENDED_BYTES];
        b[..8].copy_from_slice(b"HBTTIM02");
        b[8..16].copy_from_slice(&g.volume.id);
        put(&mut b, 16, g.volume.created);
        put(&mut b, 20, cnid);
        b[24..40].copy_from_slice(&g.epoch.0);
        b[40] = kind as u8;
        for i in 0..4 {
            put(&mut b, 48 + i * 4, seconds[i]);
            if let Some(date) = dates[i] {
                if catalog_seconds(date)? != seconds[i] {
                    return Err(RecordError::InvalidDate);
                }
                b[41] |= 1 << i;
                b[64 + i * 8..72 + i * 8].copy_from_slice(&date.to_be_bytes());
            }
        }
        seal(&mut b);
        Ok(Self(b))
    }
    pub fn encode(self) -> [u8; EXTENDED_BYTES] {
        self.0
    }
    pub fn decode(b: &[u8]) -> Option<Self> {
        if !valid_envelope(b, EXTENDED_BYTES, b"HBTTIM02")
            || b[41] & !15 != 0
            || b[42..48] != [0; 6]
            || Epoch::new(b[24..40].try_into().ok()?).is_none()
        {
            return None;
        }
        let kind = match b[40] {
            1 => EntryKind::Directory,
            2 => EntryKind::File,
            _ => return None,
        };
        if !valid_identity(get(b, 20), kind) {
            return None;
        }
        for i in 0..4 {
            let date = u64::from_be_bytes(b[64 + i * 8..72 + i * 8].try_into().ok()?);
            if b[41] & (1 << i) == 0 {
                if date != 0 {
                    return None;
                }
            } else if catalog_seconds(date).ok()? != get(b, 48 + i * 4) {
                return None;
            }
        }
        Some(Self(b.try_into().ok()?))
    }
    pub fn resolve(
        self,
        generation: Option<Generation>,
        current: VolumeState,
        cnid: u32,
        kind: EntryKind,
        seconds: [u32; 4],
    ) -> [u64; 4] {
        let mut dates = seconds.map(crate::windows::hfs_to_filetime);
        let Some(g) = generation.filter(|g| g.matches(current)) else {
            return dates;
        };
        let b = &self.0;
        if b[8..16] != current.id
            || get(b, 16) != current.created
            || b[24..40] != g.epoch.0
            || get(b, 20) != cnid
            || b[40] != kind as u8
            || get(b, 48) != seconds[0]
        {
            return dates;
        }
        for i in 0..4 {
            if b[41] & (1 << i) != 0 && get(b, 48 + i * 4) == seconds[i] {
                dates[i] = u64::from_be_bytes(b[64 + i * 8..72 + i * 8].try_into().unwrap());
            }
        }
        dates
    }
}
