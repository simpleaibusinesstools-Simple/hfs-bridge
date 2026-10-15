//! Bounded compressed reads and checked conversion to ordinary private data.
use super::decmpfs_reader::{BLOCK_BYTES, Header, ReadAt, Resource};
use super::{CatalogFile, ForkReader, HfsPlus, HfsPlusFileReader, HfsPlusFileReaderInner};
use crate::{Result, block::BlockDevice};
use std::io::{self, Read, Seek, SeekFrom};

struct ForkInput<'a> {
    dev: &'a mut dyn BlockDevice,
    fork: &'a ForkReader,
}
impl ReadAt for ForkInput<'_> {
    fn length(&self) -> u64 {
        self.fork.logical_size
    }
    fn read_exact_at(&mut self, offset: u64, output: &mut [u8]) -> io::Result<()> {
        if offset
            .checked_add(output.len() as u64)
            .is_none_or(|end| end > self.fork.logical_size)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "compressed resource read exceeds EOF",
            ));
        }
        self.fork
            .read(self.dev, offset, output)
            .map_err(io::Error::other)
    }
}

pub(super) fn metadata(
    fs: &HfsPlus,
    dev: &mut dyn BlockDevice,
    cnid: u32,
) -> Result<(Header, Vec<u8>)> {
    let bytes = fs
        .inline_attribute(dev, cnid, "com.apple.decmpfs")?
        .ok_or_else(|| {
            crate::Error::InvalidImage("compressed file lacks decmpfs attribute".into())
        })?;
    // Apple's compressed attributes are at most 3802 bytes, including the header.
    if bytes.len() > 3802 {
        return Err(crate::Error::Unsupported(
            "compressed attribute exceeds 3802-byte limit".into(),
        ));
    }
    let header = Header::metadata(&bytes)?;
    Ok((header, bytes))
}

pub(super) fn header(
    fs: &HfsPlus,
    dev: &mut dyn BlockDevice,
    cnid: u32,
) -> Result<(Header, Vec<u8>)> {
    let (_, bytes) = metadata(fs, dev, cnid)?;
    let header = Header::parse(&bytes).map_err(|error| match error.kind() {
        io::ErrorKind::Unsupported => crate::Error::Unsupported(error.to_string()),
        _ => crate::Error::Io(error),
    })?;
    Ok((header, bytes))
}

pub(super) fn open<'a>(
    fs: &HfsPlus,
    dev: &'a mut dyn BlockDevice,
    file: &CatalogFile,
) -> Result<HfsPlusFileReader<'a>> {
    if file.data_fork.logical_size != 0 || file.data_fork.total_blocks != 0 {
        return Err(crate::Error::Unsupported(
            "compressed file has a separate allocated data fork".into(),
        ));
    }
    let (header, bytes) = header(fs, dev, file.file_id)?;
    if !header.resource() {
        let expected = usize::try_from(header.size)
            .ok()
            .filter(|size| *size <= BLOCK_BYTES)
            .ok_or_else(|| {
                crate::Error::Unsupported("compressed inline output exceeds 64 KiB".into())
            })?;
        let decoded = super::decmpfs_reader::decode_block(header.kind, &bytes[16..], expected)?;
        return Ok(HfsPlusFileReader::buffered(decoded));
    }
    if bytes.len() != 16 {
        return Err(crate::Error::InvalidImage(
            "resource compression attribute has unexpected inline data".into(),
        ));
    }
    let fork = fs.open_fork(
        dev,
        &file.resource_fork,
        file.file_id,
        super::extents::FORK_RESOURCE,
        "compressed resource",
    )?;
    let resource = Resource::open(header, &mut ForkInput { dev, fork: &fork })?;
    Ok(HfsPlusFileReader {
        inner: HfsPlusFileReaderInner::Compressed(CompressedReader {
            dev,
            fork,
            resource,
            size: header.size,
            position: 0,
        }),
    })
}

pub(super) struct CompressedReader<'a> {
    dev: &'a mut dyn BlockDevice,
    fork: ForkReader,
    resource: Resource,
    pub(super) size: u64,
    position: u64,
}
impl Read for CompressedReader<'_> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let got = self.resource.read(
            &mut ForkInput {
                dev: self.dev,
                fork: &self.fork,
            },
            self.position,
            output,
        )?;
        self.position += got as u64;
        Ok(got)
    }
}
impl Seek for CompressedReader<'_> {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        let position = match position {
            SeekFrom::Start(value) => i128::from(value),
            SeekFrom::Current(delta) => i128::from(self.position) + i128::from(delta),
            SeekFrom::End(delta) => i128::from(self.size) + i128::from(delta),
        };
        self.position = u64::try_from(position).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "compressed seek outside u64 range",
            )
        })?;
        Ok(self.position)
    }
}

/// Immutable decoded source description, without borrowing the device. A
/// conversion reads these still-allocated source blocks between writes to its
/// private replacement blocks; source storage retires only at publication.
pub(super) enum DecodedSource {
    Inline(Vec<u8>),
    Resource {
        fork: ForkReader,
        resource: Resource,
    },
}
impl DecodedSource {
    pub(super) fn open(fs: &HfsPlus, dev: &mut dyn BlockDevice, cnid: u32) -> Result<Self> {
        let (header, bytes) = header(fs, dev, cnid)?;
        if !header.resource() {
            let expected = usize::try_from(header.size)
                .ok()
                .filter(|n| *n <= BLOCK_BYTES)
                .ok_or_else(|| {
                    crate::Error::Unsupported("compressed inline output exceeds 64 KiB".into())
                })?;
            return Ok(Self::Inline(super::decmpfs_reader::decode_block(
                header.kind,
                &bytes[16..],
                expected,
            )?));
        }
        if bytes.len() != 16 {
            return Err(crate::Error::InvalidImage(
                "resource compression attribute has unexpected inline data".into(),
            ));
        }
        let body = fs.catalog_record_cnid(cnid)?;
        let fork = fs.open_fork(
            dev,
            &super::volume_header::ForkData::decode(body[168..248].try_into().unwrap()),
            cnid,
            super::extents::FORK_RESOURCE,
            "conversion source",
        )?;
        let resource = Resource::open(header, &mut ForkInput { dev, fork: &fork })?;
        Ok(Self::Resource { fork, resource })
    }
    pub(super) fn read_at(
        &self,
        dev: &mut dyn BlockDevice,
        offset: u64,
        output: &mut [u8],
    ) -> Result<usize> {
        match self {
            Self::Inline(bytes) => {
                let start = offset.min(bytes.len() as u64) as usize;
                let count = output.len().min(bytes.len() - start);
                output[..count].copy_from_slice(&bytes[start..start + count]);
                Ok(count)
            }
            Self::Resource { fork, resource } => {
                Ok(resource.read(&mut ForkInput { dev, fork }, offset, output)?)
            }
        }
    }
}

pub(super) fn transform(
    fs: &mut HfsPlus,
    dev: &mut dyn BlockDevice,
    path: &std::path::Path,
    patch: Option<(u64, &[u8])>,
    resize: Option<u64>,
    force: bool,
) -> Result<()> {
    transform_with_publication(fs, dev, path, patch, resize, force, Default::default())
}

pub(super) fn transform_with_publication(
    fs: &mut HfsPlus,
    dev: &mut dyn BlockDevice,
    path: &std::path::Path,
    patch: Option<(u64, &[u8])>,
    resize: Option<u64>,
    force: bool,
    metadata: super::PublicationMetadata<'_>,
) -> Result<()> {
    transform_with_allocation(fs, dev, path, patch, resize, force, 0, metadata)
}

#[allow(clippy::too_many_arguments)]
pub(super) fn transform_with_allocation(
    fs: &mut HfsPlus,
    dev: &mut dyn BlockDevice,
    path: &std::path::Path,
    patch: Option<(u64, &[u8])>,
    resize: Option<u64>,
    force: bool,
    allocation: u64,
    metadata: super::PublicationMetadata<'_>,
) -> Result<()> {
    let name = path
        .to_str()
        .ok_or_else(|| crate::Error::InvalidArgument("non-UTF-8 conversion path".into()))?;
    let body = fs.catalog_record(name)?;
    let cnid = u32::from_be_bytes(body[8..12].try_into().unwrap());
    fs.metadata_edit_key_with_compression(cnid, true)?;
    let (header, _) = header(fs, dev, cnid)?;
    let size = if let Some(size) = resize {
        size
    } else if let Some((offset, bytes)) = patch {
        if bytes.is_empty() {
            return Ok(());
        }
        header
            .size
            .max(offset.checked_add(bytes.len() as u64).ok_or_else(|| {
                crate::Error::InvalidArgument("compressed patch offset overflow".into())
            })?)
    } else {
        return Err(crate::Error::InvalidArgument(
            "missing compressed edit".into(),
        ));
    };
    if !force && resize == Some(header.size) {
        return Ok(());
    }
    fs.validate_compressed_replacement(dev, cnid, size)?;
    let source = DecodedSource::open(fs, dev, cnid)?;
    let mut position = 0;
    let mut next = |dev: &mut dyn BlockDevice, output: &mut [u8]| -> Result<usize> {
        let count = size.saturating_sub(position).min(output.len() as u64) as usize;
        output[..count].fill(0);
        let original_count = header.size.saturating_sub(position).min(count as u64) as usize;
        if original_count != 0
            && source.read_at(dev, position, &mut output[..original_count])? != original_count
        {
            return Err(crate::Error::InvalidImage(
                "conversion source ended before decoded EOF".into(),
            ));
        }
        if let Some((offset, bytes)) = patch {
            let start = position.max(offset);
            let end = (position + count as u64).min(offset + bytes.len() as u64);
            if start < end {
                output[(start - position) as usize..(end - position) as usize]
                    .copy_from_slice(&bytes[(start - offset) as usize..(end - offset) as usize]);
            }
        }
        position += count as u64;
        Ok(count)
    };
    super::handle::replace_compressed_publication(
        fs, dev, path, &mut next, size, allocation, metadata,
    )
}

/// A separate preflight gate for conversion; ordinary read paths remain usable
/// even when a corrupt ownership graph makes mutation unsafe.
pub(super) fn validate_replacement(
    fs: &HfsPlus,
    dev: &mut dyn BlockDevice,
    cnid: u32,
    new_size: u64,
) -> Result<()> {
    validate_source(fs, dev, cnid, Some(new_size), false)
}

pub(super) fn validate_metadata(fs: &HfsPlus, dev: &mut dyn BlockDevice, cnid: u32) -> Result<()> {
    validate_source(fs, dev, cnid, None, false)
}

// Namespace replacement may already have validated and staged deletion of an
// unrelated entry. Preserve all source/ownership checks against the committed
// tree; the complete namespace plan will consume those pending deletions.
pub(super) fn validate_namespace_metadata(
    fs: &HfsPlus,
    dev: &mut dyn BlockDevice,
    cnid: u32,
) -> Result<()> {
    validate_source(fs, dev, cnid, None, true)
}

// Metadata-only validation does not reserve a decoded replacement or plan
// decmpfs removal. Source ownership and decoding checks remain identical.
fn validate_source(
    fs: &HfsPlus,
    dev: &mut dyn BlockDevice,
    cnid: u32,
    replacement: Option<u64>,
    allow_pending_deletions: bool,
) -> Result<()> {
    let invalid = |message: &str| crate::Error::InvalidImage(message.into());
    if fs.write_failed {
        return Err(crate::Error::InvalidArgument(
            "failed volume requires reopening".into(),
        ));
    }
    let key = if replacement.is_some() {
        fs.metadata_edit_key_with_compression(cnid, true)?
    } else {
        fs.basic_metadata_key(cnid)?
    };
    let w = fs.writer.as_ref().unwrap();
    let body = w.catalog.get(&key).unwrap();
    if body.len() != 248 || body[41] & 0x20 == 0 {
        return Err(crate::Error::InvalidArgument(
            "replacement target is not compressed".into(),
        ));
    }
    if body[88..96]
        .iter()
        .chain(&body[100..168])
        .any(|byte| *byte != 0)
    {
        return Err(invalid("compressed target has allocated data storage"));
    }
    if w.attribute_edit_plan.is_some()
        || (!allow_pending_deletions && !w.attribute_delete_ids.is_empty())
        || w.attribute_delete_ids.contains(&cnid)
    {
        return Err(crate::Error::Unsupported(
            "flush pending attribute mutation first".into(),
        ));
    }
    if replacement
        .is_some_and(|size| size.div_ceil(u64::from(w.block_size)) > u64::from(w.free_blocks))
    {
        return Err(crate::Error::InvalidArgument(
            "insufficient free space for complete decoded replacement".into(),
        ));
    }
    if super::journal::JournalLog::load(dev, &fs.volume_header)?.is_some_and(|log| log.is_dirty()) {
        return Err(invalid("compressed replacement requires a clean journal"));
    }
    fs.validate_attribute_storage(dev)?;
    let super::catalog::CatalogRecord::File(file) = super::catalog::CatalogRecord::decode(body)?
    else {
        return Err(invalid("compressed target is not a regular catalog file"));
    };
    header(fs, dev, cnid)?;
    // This private planner is dedicated to removing compression metadata. The
    // public EA editor must continue refusing com.apple.decmpfs.
    if replacement.is_some() {
        super::attribute_delete::plan_edits(
            dev,
            &w.attributes_file,
            w.block_size,
            cnid,
            &[("com.apple.decmpfs", None)],
        )?;
    }
    let records = super::attribute_delete::records(dev, &w.attributes_file, w.block_size)?;
    let attribute_runs = super::attribute_value::forks(&records, w.block_size, w.total_blocks)?;
    for (_, fork) in &attribute_runs {
        fs.validate_attribute_value_extents(dev, &fork.extents, true)?;
    }
    // The allocator trusts the bitmap. Validate all existing claims so even
    // an unrelated unallocated file cannot be overwritten by new data.
    let allocated = |run: &super::volume_header::ExtentDescriptor| -> Result<()> {
        if run.block_count == 0 {
            return Ok(());
        }
        let start = u64::from(run.start_block);
        let end = start + u64::from(run.block_count);
        if start == 0
            || end > u64::from(w.total_blocks)
            || (start..end).any(|block| w.bitmap[block as usize / 8] & (0x80 >> (block % 8)) == 0)
        {
            return Err(invalid("replacement bitmap does not own existing storage"));
        }
        Ok(())
    };
    for fork in [
        &w.allocation_file,
        &w.extents_file,
        &w.catalog_file,
        &w.attributes_file,
        &w.startup_file,
    ] {
        for run in &fork.extents {
            allocated(run)?;
        }
    }
    for extents in w.overflow_extents.values() {
        for run in extents {
            allocated(run)?;
        }
    }
    for record in w.catalog.values() {
        if record.len() == 248
            && i16::from_be_bytes(record[..2].try_into().unwrap()) == super::catalog::REC_FILE
        {
            for offset in [88, 168] {
                let fork = super::volume_header::ForkData::decode(
                    record[offset..offset + 80].try_into().unwrap(),
                );
                for run in &fork.extents {
                    allocated(run)?;
                }
            }
        }
    }
    let resource = fs.open_fork(
        dev,
        &file.resource_fork,
        cnid,
        super::extents::FORK_RESOURCE,
        "compression conversion resource",
    )?;
    let runs = &resource.extents;
    let covered = runs
        .iter()
        .map(|run| u64::from(run.block_count))
        .sum::<u64>();
    if covered != u64::from(file.resource_fork.total_blocks)
        || resource.logical_size > covered * u64::from(w.block_size)
    {
        return Err(invalid("conversion resource extent coverage"));
    }
    let overlaps = |a: &super::volume_header::ExtentDescriptor,
                    b: &super::volume_header::ExtentDescriptor| {
        b.block_count != 0
            && u64::from(a.start_block) < u64::from(b.start_block) + u64::from(b.block_count)
            && u64::from(b.start_block) < u64::from(a.start_block) + u64::from(a.block_count)
    };
    let journal = fs.attribute_journal_ranges(dev)?;
    for (index, run) in runs.iter().enumerate() {
        let start = u64::from(run.start_block);
        let end = start + u64::from(run.block_count);
        if start == 0
            || end > u64::from(w.total_blocks)
            || start * u64::from(w.block_size) < 2048
            || end * u64::from(w.block_size) > fs.total_bytes() - 1024
            || runs[..index].iter().any(|prior| overlaps(run, prior))
            || (start..end).any(|block| w.bitmap[block as usize / 8] & (0x80 >> (block % 8)) == 0)
            || journal.iter().any(|&(low, high)| {
                start * u64::from(w.block_size) < high && end * u64::from(w.block_size) > low
            })
            || [
                &w.allocation_file,
                &w.extents_file,
                &w.catalog_file,
                &w.attributes_file,
                &w.startup_file,
            ]
            .iter()
            .any(|fork| fork.extents.iter().any(|other| overlaps(run, other)))
            || w.overflow_extents.iter().any(|((tag, id, _), extents)| {
                (*tag != super::extents::FORK_RESOURCE || *id != cnid)
                    && extents.iter().any(|other| overlaps(run, other))
            })
            || w.catalog.values().any(|other| {
                other.len() == 248
                    && super::catalog::CatalogRecord::decode(other).is_ok()
                    && [88, 168].iter().any(|&offset| {
                        let id = u32::from_be_bytes(other[8..12].try_into().unwrap());
                        !(id == cnid && offset == 168)
                            && super::volume_header::ForkData::decode(
                                other[offset..offset + 80].try_into().unwrap(),
                            )
                            .extents
                            .iter()
                            .any(|other| overlaps(run, other))
                    })
            })
            || attribute_runs
                .iter()
                .any(|(_, fork)| fork.extents.iter().any(|other| overlaps(run, other)))
        {
            return Err(invalid(
                "conversion resource storage is unallocated, reserved or shared",
            ));
        }
    }
    // Consume every unit using a fixed buffer, so a corrupt late unit is found
    // before any conversion payload can be written. No declared-size buffer.
    let mut reader = open(fs, dev, &file)?;
    let mut scratch = vec![0; BLOCK_BYTES];
    while reader.read(&mut scratch)? != 0 {}
    Ok(())
}
