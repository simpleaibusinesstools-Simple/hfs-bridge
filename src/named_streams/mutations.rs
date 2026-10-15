//! Pure, bounded mutation plans. The caller must publish a returned store and
//! its catalog/precision changes atomically before exposing it to live handles.
//! Plans neither mutate their input nor perform device I/O.
use super::*;

fn aligned(bytes: u64, unit: u32) -> Result<u64> {
    if !(512..=65536).contains(&unit) || !unit.is_power_of_two() {
        return Err(invalid("invalid named-stream allocation unit"));
    }
    bytes
        .checked_add(u64::from(unit) - 1)
        .map(|size| size / u64::from(unit) * u64::from(unit))
        .filter(|&size| size <= MAX_BYTES as u64)
        .ok_or_else(|| invalid("named-stream allocation exceeds format limit"))
}

impl Store {
    pub fn find(&self, name: &str) -> Result<Option<&Stream>> {
        validate(self)?;
        validate_name(name)?;
        for stream in &self.streams {
            if same_name(&stream.name, name)? {
                return Ok(Some(stream));
            }
        }
        Ok(None)
    }

    fn index(&self, id: u64) -> Result<usize> {
        validate(self)?;
        self.streams.iter().position(|s| s.id == id).ok_or(Error {
            status: Status::NotFound,
            detail: "named-stream identity no longer exists".into(),
        })
    }

    // Check aggregate storage before cloning or growing a payload. The existing
    // store is validated, so subtraction cannot wrap. Metadata consumes space
    // within the format cap, not in addition to it.
    fn replacement_fits(&self, index: usize, allocation: u64) -> Result<()> {
        let current = validate(self)? as u64;
        if current - self.streams[index].allocation + allocation > MAX_BYTES as u64 {
            return Err(invalid("aggregate named-stream store exceeds format limit"));
        }
        Ok(())
    }

    /// Case-insensitive Windows identity, exact stored spelling, monotonically
    /// increasing IDs even when every earlier stream has been deleted.
    pub fn with_created(&self, name: &str, allocation: u64, unit: u32) -> Result<(Self, u64)> {
        if self.find(name)?.is_some() {
            return Err(Error {
                status: Status::Collision,
                detail: "named stream already exists".into(),
            });
        }
        let allocation = aligned(allocation, unit)?;
        let next_id = self
            .next_id
            .checked_add(1)
            .ok_or_else(|| invalid("named-stream IDs exhausted"))?;
        if self.streams.len() == MAX_STREAMS
            || validate(self)? + RECORD + name.encode_utf16().count() * 2 + allocation as usize
                > MAX_BYTES
        {
            return Err(invalid("named-stream count or storage limit"));
        }
        let mut result = self.clone();
        result.streams.push(Stream {
            id: self.next_id,
            name: name.into(),
            data: Vec::new(),
            allocation,
        });
        result.next_id = next_id;
        Ok((result, self.next_id))
    }

    /// Holes are zero-filled. Append uses the current logical EOF; constrained
    /// writes clip at EOF and never grow the stream. Empty writes are no-ops.
    #[allow(clippy::too_many_arguments)]
    pub fn with_write(
        &self,
        id: u64,
        offset: u64,
        bytes: &[u8],
        append: bool,
        constrained: bool,
        unit: u32,
    ) -> Result<(Self, usize)> {
        validate(self)?;
        self.clone()
            .into_write(id, offset, bytes, append, constrained, unit)
    }

    /// Consume an exclusively owned candidate. The caller retains the old
    /// committed disk state until publication; refusal need not preserve this
    /// disposable in-memory candidate.
    #[allow(clippy::too_many_arguments)]
    pub fn into_write(
        self,
        id: u64,
        offset: u64,
        bytes: &[u8],
        append: bool,
        constrained: bool,
        unit: u32,
    ) -> Result<(Self, usize)> {
        let index = self.index(id)?;
        let old = &self.streams[index];
        let offset = if append {
            old.data.len() as u64
        } else {
            offset
        };
        let count = if constrained {
            bytes.len().min(
                old.data
                    .len()
                    .saturating_sub(usize::try_from(offset).unwrap_or(usize::MAX)),
            )
        } else {
            bytes.len()
        };
        if count == 0 {
            return Ok((self, 0));
        }
        let end = offset
            .checked_add(count as u64)
            .ok_or_else(|| invalid("named-stream write offset overflow"))?;
        let allocation = old.allocation.max(aligned(end, unit)?);
        self.replacement_fits(index, allocation)?;
        let mut result = self;
        let stream = &mut result.streams[index];
        stream.allocation = allocation;
        stream.data.resize(stream.data.len().max(end as usize), 0);
        stream.data[offset as usize..end as usize].copy_from_slice(&bytes[..count]);
        Ok((result, count))
    }

    /// Shrinking EOF retains reserved allocation until cleanup or an explicit
    /// allocation request. Bytes removed by truncation cannot reappear on growth.
    pub fn with_size(&self, id: u64, size: u64, unit: u32) -> Result<Self> {
        let index = self.index(id)?;
        let allocation = self.streams[index].allocation.max(aligned(size, unit)?);
        self.replacement_fits(index, allocation)?;
        let mut result = self.clone();
        result.streams[index].allocation = allocation;
        result.streams[index].data.resize(size as usize, 0);
        Ok(result)
    }

    /// FileAllocationInformation truncates EOF at the rounded allocation, not
    /// at an unaligned requested byte count. Allocation growth never grows EOF.
    pub fn with_allocation(&self, id: u64, size: u64, unit: u32) -> Result<Self> {
        let index = self.index(id)?;
        let allocation = aligned(size, unit)?;
        self.replacement_fits(index, allocation)?;
        let mut result = self.clone();
        result.streams[index].allocation = allocation;
        result.streams[index].data.truncate(allocation as usize);
        Ok(result)
    }

    pub fn with_trimmed_allocation(&self, id: u64, unit: u32) -> Result<Self> {
        let index = self.index(id)?;
        self.with_allocation(id, self.streams[index].data.len() as u64, unit)
    }

    /// Keep the returned record for retained-handle lifetime handling. This does
    /// not grant permission to reuse its name or write through a deleted handle.
    pub fn without(&self, id: u64) -> Result<(Self, Stream)> {
        let index = self.index(id)?;
        let mut result = self.clone();
        let removed = result.streams.remove(index);
        Ok((result, removed))
    }
}
