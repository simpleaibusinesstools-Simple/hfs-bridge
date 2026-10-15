//! Fractional dates are trusted only with the current committed volume marker.
//! Build owned records before any attribute plan, then publish them alongside
//! the catalog/payload transaction. Merely reading or flushing never adds them.
use super::*;
use crate::timestamps::{self as wire, EntryKind, Epoch, Generation, PrecisionRecord, VolumeState};
use fstool::fs::hfs_plus::CatalogUpdate;

pub(super) struct PrecisionPublication(Vec<(u32, &'static str, Vec<u8>)>);
impl PrecisionPublication {
    pub(super) fn references(&self) -> Vec<(u32, &str, Option<&[u8]>)> {
        self.0
            .iter()
            .map(|(id, name, bytes)| (*id, *name, Some(bytes.as_slice())))
            .collect()
    }
}

pub(super) fn now_filetime() -> Result<u64> {
    let elapsed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| error(Status::InvalidParameter, e))?;
    let date = (elapsed.as_secs() + 11_644_473_600)
        .checked_mul(TICKS)
        .and_then(|value| value.checked_add(u64::from(elapsed.subsec_nanos() / 100)))
        .ok_or_else(|| error(Status::InvalidParameter, "timestamp overflow"))?;
    filetime_to_hfs(date)?;
    Ok(date)
}

fn fresh_epoch() -> Result<Epoch> {
    let mut bytes = [0; 16];
    #[cfg(windows)]
    {
        #[link(name = "bcrypt")]
        unsafe extern "system" {
            fn BCryptGenRandom(
                algorithm: *mut std::ffi::c_void,
                buffer: *mut u8,
                size: u32,
                flags: u32,
            ) -> i32;
        }
        // Documented user-mode system-preferred RNG: null provider, writable
        // 16-byte buffer, BCRYPT_USE_SYSTEM_PREFERRED_RNG. Failure is not a seed.
        let status = unsafe { BCryptGenRandom(std::ptr::null_mut(), bytes.as_mut_ptr(), 16, 2) };
        if status != 0 {
            return Err(error(
                Status::IoError,
                format!("system RNG failed: {status:#x}"),
            ));
        }
    }
    #[cfg(not(windows))]
    std::fs::File::open("/dev/urandom")
        .and_then(|mut file| file.read_exact(&mut bytes))
        .map_err(|e| error(Status::IoError, e))?;
    Epoch::new(bytes).ok_or_else(|| error(Status::IoError, "system RNG returned an invalid epoch"))
}

fn identity(body: &[u8]) -> Result<(EntryKind, [u32; 4])> {
    let kind = match volume::be16(body, 0) {
        1 => EntryKind::Directory,
        2 => EntryKind::File,
        _ => return Err(error(Status::Unsupported, "timestamp catalog identity")),
    };
    Ok((
        kind,
        [12, 24, 16, 20].map(|offset| volume::be32(body, offset)),
    ))
}

impl<D: BlockDevice> Adapter<D> {
    fn time_generation(&mut self) -> Result<(VolumeState, Option<Generation>)> {
        let mut header = [0; 112];
        self.device
            .read_at(1024, &mut header)
            .map_err(engine_error)?;
        let current = VolumeState {
            id: header[104..112].try_into().unwrap(),
            created: volume::be32(&header, 16),
            write_count: volume::be32(&header, 68),
        };
        let cache_allowed = self.read_only || self.fs.metadata_is_committed();
        if !cache_allowed {
            self.readonly_generation = None;
        }
        if cache_allowed
            && let Some((cached, generation)) = self.readonly_generation
            && cached == current
        {
            return Ok((current, generation));
        }
        let bytes =
            self.read_fixed_attribute(2, wire::GENERATION_ATTRIBUTE, wire::GENERATION_BYTES)?;
        let generation = bytes.as_deref().and_then(Generation::decode);
        if cache_allowed {
            self.readonly_generation = Some((current, generation));
        }
        Ok((current, generation))
    }

    fn resolve_precision(
        &mut self,
        cnid: u32,
        kind: EntryKind,
        seconds: [u32; 4],
        current: VolumeState,
        generation: Option<Generation>,
    ) -> Result<[u64; 4]> {
        if !generation.is_some_and(|value| value.matches(current)) {
            return Ok(seconds.map(hfs_to_filetime));
        }
        if self.committed_attribute_absent(cnid, wire::TIMES_ATTRIBUTE)? {
            return Ok(seconds.map(hfs_to_filetime));
        }
        let bytes = self.read_fixed_attribute(cnid, wire::TIMES_ATTRIBUTE, wire::RECORD_BYTES)?;
        if bytes.is_none() {
            let extended =
                self.read_fixed_attribute(cnid, wire::TIMES_ATTRIBUTE, wire::EXTENDED_BYTES)?;
            if let Some(record) = extended.as_deref().and_then(wire::ExtendedRecord::decode) {
                return Ok(record.resolve(generation, current, cnid, kind, seconds));
            }
        }
        Ok(bytes
            .as_deref()
            .and_then(PrecisionRecord::decode)
            .map_or_else(
                || seconds.map(hfs_to_filetime),
                |record| record.resolve(generation, current, cnid, kind, seconds),
            ))
    }

    pub(super) fn precise_dates(&mut self, cnid: u32, body: &[u8]) -> Result<[u64; 4]> {
        let (kind, seconds) = identity(body)?;
        let (current, generation) = self.time_generation()?;
        self.resolve_precision(cnid, kind, seconds, current, generation)
    }

    pub(super) fn prepare_precision(
        &mut self,
        catalog: &[CatalogUpdate],
        exact: &[(u32, [Option<u64>; 4])],
        future: Option<(u32, Kind)>,
    ) -> Result<PrecisionPublication> {
        let (current, previous) = self.time_generation()?;
        let next = Generation::next(current, previous, fresh_epoch()?)
            .map_err(|e| error(Status::InvalidParameter, e))?;
        let mut records = vec![(2, wire::GENERATION_ATTRIBUTE, next.encode().to_vec())];
        for update in catalog {
            let (kind, mut seconds, mut dates) =
                if let Some((_, kind)) = future.filter(|(id, _)| *id == update.cnid) {
                    (
                        if kind == Kind::File {
                            EntryKind::File
                        } else {
                            EntryKind::Directory
                        },
                        [0; 4],
                        [0; 4],
                    )
                } else {
                    let body = self.body(update.cnid)?;
                    let (kind, seconds) = identity(&body)?;
                    let dates =
                        self.resolve_precision(update.cnid, kind, seconds, current, previous)?;
                    (kind, seconds, dates)
                };
            let exact = exact
                .iter()
                .find(|(id, _)| *id == update.cnid)
                .map(|(_, times)| *times)
                .unwrap_or([None; 4]);
            for index in 0..4 {
                if let Some(second) = update.times[index] {
                    seconds[index] = second;
                    dates[index] = exact[index].unwrap_or_else(|| hfs_to_filetime(second));
                } else if exact[index].is_some() {
                    return Err(error(
                        Status::InvalidParameter,
                        "precise date without catalog update",
                    ));
                }
            }
            let encoded = if dates.iter().any(|&date| filetime_to_hfs(date).is_err()) {
                wire::ExtendedRecord::new(next, update.cnid, kind, seconds, dates.map(Some))
                    .map_err(|e| error(Status::InvalidParameter, e))?
                    .encode()
                    .to_vec()
            } else {
                PrecisionRecord::new(next, update.cnid, kind, seconds, dates.map(Some))
                    .map_err(|e| error(Status::InvalidParameter, e))?
                    .encode()
                    .to_vec()
            };
            records.push((update.cnid, wire::TIMES_ATTRIBUTE, encoded));
        }
        Ok(PrecisionPublication(records))
    }
}
