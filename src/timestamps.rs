//! Bounded, versioned precision records used by Windows callbacks.
//!
//! Fractions are usable only while the root generation matches the current
//! volume identity AND write counter. Every writer transaction must publish the
//! next counter with its metadata. After a foreign write, a fresh epoch prevents
//! a new record from reactivating older records left on other catalog entries.
//! The digest detects corruption, not hostile edits or counter/volume cloning.
use sha2::{Digest, Sha256};
mod extended;
pub use extended::{EXTENDED_BYTES, ExtendedRecord, catalog_seconds};

pub const GENERATION_ATTRIBUTE: &str = "org.hfsbridge.windows.time-generation";
pub const TIMES_ATTRIBUTE: &str = "org.hfsbridge.windows.times";
pub const GENERATION_BYTES: usize = 80;
pub const RECORD_BYTES: usize = 112;
/// Attribute names are binary/case-sensitive even on HFS+ volumes.
pub(crate) fn is_private_attribute(name: &str) -> bool {
    matches!(
        name,
        GENERATION_ATTRIBUTE | TIMES_ATTRIBUTE | crate::links::KIND_ATTRIBUTE
    )
}
const TICKS: u32 = 10_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VolumeState {
    /// The eight persistent Finder volume-identifier bytes, without byte swaps.
    pub id: [u8; 8],
    pub created: u32,
    pub write_count: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Epoch([u8; 16]);
impl Epoch {
    /// The caller must supply a fresh cryptographically random nonzero value
    /// when establishing trust. This constructor does not generate randomness.
    pub fn new(bytes: [u8; 16]) -> Option<Self> {
        (bytes != [0; 16]).then_some(Self(bytes))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordError {
    ReusedEpoch,
    InvalidIdentity,
    InvalidDate,
}
impl std::fmt::Display for RecordError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid timestamp record: {self:?}")
    }
}
impl std::error::Error for RecordError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Generation {
    volume: VolumeState,
    epoch: Epoch,
}
impl Generation {
    /// Prepare the marker for exactly one upcoming metadata publication.
    /// It must be staged in the SAME transaction as the catalog and records.
    /// This does not mutate storage and must not be used for an unchanged flush.
    pub fn next(
        current: VolumeState,
        previous: Option<Self>,
        fresh_epoch: Epoch,
    ) -> Result<Self, RecordError> {
        let epoch = match previous {
            Some(old) if old.matches(current) => old.epoch,
            Some(old) if old.epoch == fresh_epoch => return Err(RecordError::ReusedEpoch),
            _ => fresh_epoch,
        };
        Ok(Self {
            volume: VolumeState {
                write_count: current.write_count.wrapping_add(1),
                ..current
            },
            epoch,
        })
    }
    pub fn matches(self, current: VolumeState) -> bool {
        self.volume == current
    }
    pub fn encode(self) -> [u8; GENERATION_BYTES] {
        let mut bytes = [0; GENERATION_BYTES];
        bytes[..8].copy_from_slice(b"HBTGEN01");
        bytes[8..16].copy_from_slice(&self.volume.id);
        put(&mut bytes, 16, self.volume.created);
        put(&mut bytes, 20, self.volume.write_count);
        bytes[24..40].copy_from_slice(&self.epoch.0);
        seal(&mut bytes);
        bytes
    }
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if !valid_envelope(bytes, GENERATION_BYTES, b"HBTGEN01") || bytes[40..48] != [0; 8] {
            return None;
        }
        Some(Self {
            volume: VolumeState {
                id: bytes[8..16].try_into().ok()?,
                created: get(bytes, 16),
                write_count: get(bytes, 20),
            },
            epoch: Epoch::new(bytes[24..40].try_into().ok()?)?,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    Directory = 1,
    File = 2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrecisionRecord {
    volume_id: [u8; 8],
    volume_created: u32,
    epoch: Epoch,
    cnid: u32,
    kind: EntryKind,
    mask: u8,
    /// Order throughout this module: creation, access, write, change.
    seconds: [u32; 4],
    fractions: [u32; 4],
}
impl PrecisionRecord {
    /// Dates must fit HFS+ and round down to the exact catalog seconds that will
    /// be published with this record. None means no precision for that field.
    pub fn new(
        generation: Generation,
        cnid: u32,
        kind: EntryKind,
        seconds: [u32; 4],
        dates: [Option<u64>; 4],
    ) -> Result<Self, RecordError> {
        if !valid_identity(cnid, kind) {
            return Err(RecordError::InvalidIdentity);
        }
        let mut mask = 0;
        let mut fractions = [0; 4];
        for (i, date) in dates.into_iter().enumerate() {
            if let Some(date) = date {
                if crate::windows::filetime_to_hfs(date).ok() != Some(seconds[i]) {
                    return Err(RecordError::InvalidDate);
                }
                mask |= 1 << i;
                fractions[i] = (date % u64::from(TICKS)) as u32;
            }
        }
        Ok(Self {
            volume_id: generation.volume.id,
            volume_created: generation.volume.created,
            epoch: generation.epoch,
            cnid,
            kind,
            mask,
            seconds,
            fractions,
        })
    }
    pub fn encode(self) -> [u8; RECORD_BYTES] {
        let mut bytes = [0; RECORD_BYTES];
        bytes[..8].copy_from_slice(b"HBTTIM01");
        bytes[8..16].copy_from_slice(&self.volume_id);
        put(&mut bytes, 16, self.volume_created);
        put(&mut bytes, 20, self.cnid);
        bytes[24..40].copy_from_slice(&self.epoch.0);
        bytes[40] = self.kind as u8;
        bytes[41] = self.mask;
        for i in 0..4 {
            put(&mut bytes, 48 + i * 4, self.seconds[i]);
            put(&mut bytes, 64 + i * 4, self.fractions[i]);
        }
        seal(&mut bytes);
        bytes
    }
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if !valid_envelope(bytes, RECORD_BYTES, b"HBTTIM01")
            || bytes[41] & !15 != 0
            || bytes[42..48] != [0; 6]
        {
            return None;
        }
        let kind = match bytes[40] {
            1 => EntryKind::Directory,
            2 => EntryKind::File,
            _ => return None,
        };
        let cnid = get(bytes, 20);
        if !valid_identity(cnid, kind) {
            return None;
        }
        let fractions = std::array::from_fn(|i| get(bytes, 64 + i * 4));
        if fractions
            .iter()
            .enumerate()
            .any(|(i, value)| *value >= TICKS || (bytes[41] & (1 << i) == 0 && *value != 0))
        {
            return None;
        }
        Some(Self {
            volume_id: bytes[8..16].try_into().ok()?,
            volume_created: get(bytes, 16),
            epoch: Epoch::new(bytes[24..40].try_into().ok()?)?,
            cnid,
            kind,
            mask: bytes[41],
            seconds: std::array::from_fn(|i| get(bytes, 48 + i * 4)),
            fractions,
        })
    }
    /// Fail closed to whole catalog seconds. Each unchanged field retains its
    /// own precision only after the global volume/epoch and entry checks pass.
    /// A changed birth date invalidates the entire entry (possible CNID reuse).
    pub fn resolve(
        self,
        generation: Option<Generation>,
        current: VolumeState,
        cnid: u32,
        kind: EntryKind,
        seconds: [u32; 4],
    ) -> [u64; 4] {
        let mut dates = seconds.map(crate::windows::hfs_to_filetime);
        let Some(generation) = generation.filter(|g| g.matches(current)) else {
            return dates;
        };
        if self.volume_id != current.id
            || self.volume_created != current.created
            || self.epoch != generation.epoch
            || self.cnid != cnid
            || self.kind != kind
            || self.seconds[0] != seconds[0]
        {
            return dates;
        }
        for i in 0..4 {
            if self.mask & (1 << i) != 0 && self.seconds[i] == seconds[i] {
                dates[i] += u64::from(self.fractions[i]);
            }
        }
        dates
    }
}

fn valid_identity(cnid: u32, kind: EntryKind) -> bool {
    cnid >= 16 || (cnid == 2 && kind == EntryKind::Directory)
}
fn get(bytes: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes(bytes[offset..offset + 4].try_into().unwrap())
}
fn put(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
}
fn seal(bytes: &mut [u8]) {
    let end = bytes.len() - 32;
    let digest = Sha256::digest(&bytes[..end]);
    bytes[end..].copy_from_slice(&digest);
}
fn valid_envelope(bytes: &[u8], length: usize, magic: &[u8; 8]) -> bool {
    bytes.len() == length
        && &bytes[..8] == magic
        && Sha256::digest(&bytes[..length - 32])[..] == bytes[length - 32..]
}
