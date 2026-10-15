//! HFS+ read/write file handle using private replacement data/resource forks.
//!
//! Backs [`crate::fs::Filesystem::open_file_rw`] for HFS+ volumes.
//!
//! Only touched committed allocation blocks are copied using bounded scratch.
//! Untouched extents are shared with the committed fork; new blocks are private.
//! All detached blocks remain allocated, including during shrink/regrow, until
//! one metadata transaction publishes the new fork and retires unused blocks.
//! The journal persists private payload before publishing its pointer.
//!
//! Failed edits/commits require reopening and suppress implicit close retries.
//! Plain volumes still use direct metadata flush and have no crash-atomicity
//! guarantee. Temporary free space is needed for touched/new blocks; a full
//! overwrite still needs enough space for a complete replacement payload.
//!
//! ## Lifetime
//!
//! The handle holds `&'a mut HfsPlus` and `&'a mut dyn BlockDevice`
//! for its full lifetime, matching the trait signature.

use std::collections::BTreeMap;
use std::io::{self, Read, Seek, SeekFrom, Write};

use super::HfsPlus;
use super::catalog::{REC_FILE, UniStr, mode};
use super::extents::{FORK_DATA, FORK_RESOURCE};
use super::volume_header::{ExtentDescriptor, FORK_DATA_SIZE, FORK_EXTENT_COUNT, ForkData};
use super::writer::OwnedKey;
use crate::Result;
use crate::block::BlockDevice;
use crate::fs::FileHandle;

/// A read/write file handle on an HFS+ regular file. Reads / writes
/// translate fork-relative byte offsets into allocation-block I/O via
/// the file's extent list (inline + extents-overflow). Growth allocates
/// new runs from the volume bitmap.
pub struct HfsPlusFileHandle<'a> {
    fs: &'a mut HfsPlus,
    dev: &'a mut dyn BlockDevice,
    /// OwnedKey of the catalog entry that owns this file. Used to look
    /// the body up in the in-memory writer on every metadata refresh.
    cat_key: OwnedKey,
    /// CNID of the file we're editing. Needed to drive overflow-record
    /// updates.
    file_id: u32,
    /// The file's allocation runs, in fork order. Inline (first 8) plus
    /// any spilled into extents-overflow are merged into a single flat
    /// list for simple addressing during reads / writes.
    runs: Vec<ExtentDescriptor>,
    /// Logical length in bytes (after any pending writes).
    file_size: u64,
    /// Read / write cursor.
    pos: u64,
    /// True once mutations have made the on-disk catalog stale. Cleared
    /// on `sync` / `Drop`.
    dirty: bool,
    /// Snapshot of committed extents. Detached blocks cannot be reused until
    /// publication; unchanged blocks may remain in the new logical fork.
    committed_runs: Vec<ExtentDescriptor>,
    /// Only bytes below this committed EOF can be observed before publication.
    /// Keep it across pending shrink/regrow; update only after successful sync.
    committed_size: u64,
    /// Every private allocation since sync, including subsequently detached
    /// runs. Track ranges rather than one entry per allocation block.
    private_allocations: BTreeMap<u32, u32>,
    private: bool,
    failed: bool,
    clump_size: u32,
    fork: ForkKind,
}

#[derive(Clone, Copy)]
pub(super) enum ForkKind {
    Data,
    Resource,
}
impl ForkKind {
    fn offset(self) -> usize {
        match self {
            Self::Data => 88,
            Self::Resource => 168,
        }
    }
    fn tag(self) -> u8 {
        match self {
            Self::Data => FORK_DATA,
            Self::Resource => FORK_RESOURCE,
        }
    }
}

impl<'a> HfsPlusFileHandle<'a> {
    /// Construct a handle for the file at `cat_key`. Caller has already
    /// resolved the entry to a non-hardlink non-symlink regular file,
    /// assembled its merged run list and verified a clean journal.
    pub(super) fn new(
        fs: &'a mut HfsPlus,
        dev: &'a mut dyn BlockDevice,
        cat_key: OwnedKey,
        file_id: u32,
        runs: Vec<ExtentDescriptor>,
        file_size: u64,
        clump_size: u32,
    ) -> Self {
        Self {
            fs,
            dev,
            cat_key,
            file_id,
            committed_runs: runs.clone(),
            committed_size: file_size,
            runs,
            file_size,
            pos: 0,
            dirty: false,
            private_allocations: BTreeMap::new(),
            private: false,
            failed: false,
            clump_size,
            fork: ForkKind::Data,
        }
    }

    /// Allocation block size in bytes.
    fn block_size(&self) -> u64 {
        u64::from(self.fs.volume_header.block_size)
    }

    /// Translate a fork-relative byte offset to (device byte offset,
    /// bytes available in this run). Returns `None` past EOF (i.e. past
    /// the last allocated block).
    fn locate(&self, fork_off: u64) -> Option<(u64, u64)> {
        locate_in(&self.runs, self.block_size(), fork_off)
    }
    fn ensure_usable(&self) -> Result<()> {
        if self.failed || self.fs.write_failed {
            return Err(crate::Error::InvalidArgument(
                "hfs+ handle: failed edit requires reopening".into(),
            ));
        }
        Ok(())
    }
    fn poison(&mut self) {
        self.failed = true;
        self.fs.write_failed = true;
    }
    fn is_private_block(&self, block: u32) -> bool {
        self.private_allocations
            .range(..=block)
            .next_back()
            .is_some_and(|(&start, &count)| block - start < count)
    }

    /// Copy blocks containing committed file bytes, including a partial EOF
    /// block. Full preallocated blocks above committed EOF can be filled in
    /// place: their data remains invisible until the new EOF is published.
    /// Pending shrink must not reduce this committed boundary.
    fn privatize_range(&mut self, start: u64, end: u64, overwrite: bool) -> Result<()> {
        if end <= start {
            return Ok(());
        }
        let bs = self.block_size();
        let first = start / bs;
        let last = end.div_ceil(bs);
        let visible_last = self.committed_size.div_ceil(bs);
        let mut needed = 0u64;
        for index in first..last {
            if index >= visible_last {
                continue;
            }
            let (off, _) = self.locate(index * bs).ok_or_else(|| {
                crate::Error::InvalidImage("hfs+ handle: missing block during edit".into())
            })?;
            if !self.is_private_block(u32::try_from(off / bs).unwrap()) {
                needed += 1;
            }
        }
        if needed > u64::from(self.fs.writer.as_ref().unwrap().free_blocks) {
            return Err(crate::Error::InvalidArgument(
                "hfs+ handle: insufficient space for touched replacement blocks".into(),
            ));
        }
        if needed == 0 {
            return Ok(());
        }
        // Larger engine requests reduce write-through device calls. The raw
        // sector backend still splits each request at its verified adapter cap.
        const COPY_BYTES: usize = 1024 * 1024;
        let mut scratch = Vec::new();
        let max_blocks = u32::try_from(COPY_BYTES as u64 / bs).unwrap().max(1);
        let fully_overwritten =
            |block: u64| overwrite && block * bs >= start && (block + 1) * bs <= end;
        let mut index = first;
        while index < last {
            if index >= visible_last {
                break;
            }
            let (source, _) = self.locate(index * bs).unwrap();
            if self.is_private_block(u32::try_from(source / bs).unwrap()) {
                index += 1;
                continue;
            }
            // Adjacent committed blocks can be copied together. Keep the same
            // private-before-publication rule and bounded I/O buffers; never
            // span a private block or a discontinuity in the source fork.
            let mut contiguous = 1;
            let replace_all = fully_overwritten(index);
            while contiguous < max_blocks && index + u64::from(contiguous) < last.min(visible_last)
            {
                let next = self.locate((index + u64::from(contiguous)) * bs).unwrap().0;
                if next != source + u64::from(contiguous) * bs
                    || self.is_private_block(u32::try_from(next / bs).unwrap())
                    || fully_overwritten(index + u64::from(contiguous)) != replace_all
                {
                    break;
                }
                contiguous += 1;
            }
            let replacement = self
                .fs
                .writer
                .as_mut()
                .unwrap()
                .allocate_largest_run(contiguous)?;
            self.private_allocations
                .insert(replacement.start_block, replacement.block_count);
            let dest = u64::from(replacement.start_block) * bs;
            let length = u64::from(replacement.block_count) * bs;
            // Complete input blocks will be filled by write_into_runs before
            // any publication. Their old bytes are unnecessary, but the new
            // blocks remain private and old storage stays owned until commit.
            // Partial edges still copy every byte outside the supplied range.
            if !replace_all {
                if scratch.is_empty() {
                    scratch.resize((needed * bs).min(COPY_BYTES as u64) as usize, 0);
                }
                let mut copied = 0;
                while copied < length {
                    let take = (length - copied).min(scratch.len() as u64) as usize;
                    self.dev.read_at(source + copied, &mut scratch[..take])?;
                    self.dev.write_at(dest + copied, &scratch[..take])?;
                    copied += take as u64;
                }
            }
            for relative in 0..replacement.block_count {
                replace_block(
                    &mut self.runs,
                    index + u64::from(relative),
                    replacement.start_block + relative,
                )?;
            }
            index += u64::from(replacement.block_count);
        }
        Ok(())
    }

    /// Total bytes covered by the current run list.
    fn allocated_bytes(&self) -> u64 {
        let bs = self.block_size();
        self.runs
            .iter()
            .map(|r| u64::from(r.block_count) * bs)
            .sum()
    }

    /// Total allocation blocks across the run list.
    fn total_blocks(&self) -> u32 {
        self.runs.iter().map(|r| r.block_count).sum()
    }

    /// Read up to `buf.len()` bytes from the current cursor; never past EOF.
    fn read_inner(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.ensure_usable()
            .map_err(|e| io::Error::other(e.to_string()))?;
        if self.pos >= self.file_size || buf.is_empty() {
            return Ok(0);
        }
        let want = (self.file_size - self.pos).min(buf.len() as u64) as usize;
        let mut done = 0;
        while done < want {
            let (off, left) = self
                .locate(self.pos + done as u64)
                .ok_or_else(|| io::Error::other("hfs+ handle: invalid fork extent coverage"))?;
            let take = (want - done).min(left as usize);
            self.dev
                .read_at(off, &mut buf[done..done + take])
                .map_err(|e| io::Error::other(e.to_string()))?;
            done += take;
        }
        self.pos += done as u64;
        Ok(done)
    }

    fn dev_write_at(&mut self, off: u64, data: &[u8]) -> Result<()> {
        debug_assert!(self.private);
        self.dev.write_at(off, data)
    }

    /// Grow the private run list. Newly-allocated blocks are zeroed on disk
    /// so reads of unwritten holes return zeros.
    fn ensure_capacity(&mut self, needed_bytes: u64) -> Result<()> {
        let bs = self.block_size();
        let have_bytes = self.allocated_bytes();
        if needed_bytes <= have_bytes {
            return Ok(());
        }
        let extra_bytes = needed_bytes - have_bytes;
        let mut extra_blocks = u32::try_from(extra_bytes.div_ceil(bs)).map_err(|_| {
            crate::Error::InvalidArgument(
                "hfs+ handle: capacity grow overflows u32 block count".into(),
            )
        })?;
        if extra_blocks > self.fs.writer.as_ref().unwrap().free_blocks {
            return Err(crate::Error::InvalidArgument(
                "hfs+ handle: insufficient free space".into(),
            ));
        }
        // Two-phase to avoid the alternating borrow between
        // `self.fs.writer` (allocation bookkeeping) and `self.dev_write_at`
        // (which needs `self` as a whole): first stage every run, then
        // drop the writer borrow, then apply the private zero-fills.
        let mut staged: Vec<ExtentDescriptor> = Vec::new();
        {
            let writer = self.fs.writer.as_mut().ok_or_else(|| {
                crate::Error::InvalidArgument("hfs+: volume opened read-only".into())
            })?;
            while extra_blocks > 0 {
                let run = writer.allocate_largest_run(extra_blocks)?;
                extra_blocks -= run.block_count;
                staged.push(run);
            }
        }
        for run in staged {
            // Zero the freshly-allocated run so reads of holes return
            // zero. (A block freed by `remove` and re-handed-out may
            // still carry stale bytes.) The zero-fill goes straight to
            // disk, never through the journal: nothing references these
            // blocks until the metadata flush commits, so there is no
            // consistency to protect and journaling it would only bloat
            // every transaction by the size of the allocation.
            let len = u64::from(run.block_count) * bs;
            let off = u64::from(run.start_block) * bs;
            let zeros = vec![0u8; len.min(1024 * 1024) as usize];
            let mut written = 0;
            while written < len {
                let take = (len - written).min(zeros.len() as u64) as usize;
                self.dev.write_at(off + written, &zeros[..take])?;
                written += take as u64;
            }
            self.private_allocations
                .insert(run.start_block, run.block_count);
            self.runs.push(run);
        }
        coalesce_runs(&mut self.runs);
        Ok(())
    }

    /// Shrink the run list so it covers no more than `cap_bytes` bytes,
    /// detaching trailing blocks. None can be reused until metadata commit.
    /// Round up so a partial-block tail stays allocated.
    fn shrink_to(&mut self, cap_bytes: u64) -> Result<()> {
        let bs = self.block_size();
        let needed_blocks_u64 = cap_bytes.div_ceil(bs);
        let needed_blocks = u32::try_from(needed_blocks_u64).map_err(|_| {
            crate::Error::InvalidArgument("hfs+ handle: shrink-target overflows u32 blocks".into())
        })?;
        let mut have: u32 = self.total_blocks();
        while have > needed_blocks {
            let last = self
                .runs
                .last_mut()
                .ok_or_else(|| crate::Error::InvalidImage("hfs+ handle: run list empty".into()))?;
            let surplus = have - needed_blocks;
            if last.block_count <= surplus {
                have -= last.block_count;
                self.runs.pop();
            } else {
                // Trim the tail of this run.
                let new_count = last.block_count - surplus;
                last.block_count = new_count;
                have = needed_blocks;
            }
        }
        Ok(())
    }

    /// Write `data` at fork-relative offset `off`. The runs must already
    /// cover `off + data.len()` bytes.
    fn write_into_runs(&mut self, off: u64, data: &[u8]) -> io::Result<()> {
        let mut done = 0usize;
        while done < data.len() {
            let (dev_off, in_run) = self.locate(off + done as u64).ok_or_else(|| {
                io::Error::other("hfs+: write past allocated capacity (internal)")
            })?;
            let chunk = (data.len() - done).min(in_run as usize);
            self.dev_write_at(dev_off, &data[done..done + chunk])
                .map_err(|e| io::Error::other(e.to_string()))?;
            done += chunk;
        }
        Ok(())
    }

    /// Zero the bytes in `[start, end)`. The runs must already cover
    /// that range.
    fn zero_range(&mut self, start: u64, end: u64) -> io::Result<()> {
        if end <= start {
            return Ok(());
        }
        self.privatize_range(start, end, false)
            .map_err(|e| io::Error::other(e.to_string()))?;
        let zeros = vec![0u8; (end - start).min(1024 * 1024) as usize];
        let mut pos = start;
        while pos < end {
            let want = (end - pos).min(zeros.len() as u64) as usize;
            self.write_into_runs(pos, &zeros[..want])?;
            pos += want as u64;
        }
        Ok(())
    }

    /// Internal write path. Extends the runs as needed, zeros any gap
    /// between old EOF and the cursor, writes the bytes, updates the
    /// in-memory size and marks dirty.
    fn write_inner(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let new_end = self.pos.checked_add(buf.len() as u64).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "hfs+: write offset overflow")
        })?;
        let gap_start = self.file_size;
        let gap_end = self.pos.min(new_end);
        self.private = true;
        self.ensure_capacity(new_end.max(self.file_size))
            .map_err(|e| io::Error::other(e.to_string()))?;
        if gap_end > gap_start {
            self.zero_range(gap_start, gap_end)?;
        }
        self.privatize_range(self.pos, new_end, true)
            .map_err(|e| io::Error::other(e.to_string()))?;
        self.write_into_runs(self.pos, buf)?;
        self.pos += buf.len() as u64;
        if self.pos > self.file_size {
            self.file_size = self.pos;
        }
        self.dirty = true;
        Ok(buf.len())
    }

    /// Grow or shrink the file to exactly `new_len` bytes. Marks dirty.
    fn set_len_inner(&mut self, new_len: u64) -> Result<()> {
        if new_len == self.file_size {
            return Ok(());
        }
        self.private = true;
        if new_len > self.file_size {
            let old_len = self.file_size;
            self.ensure_capacity(new_len)?;
            self.zero_range(old_len, new_len)
                .map_err(crate::Error::Io)?;
            self.file_size = new_len;
        } else if new_len < self.file_size {
            self.shrink_to(new_len)?;
            self.file_size = new_len;
            if self.pos > self.file_size {
                self.pos = self.file_size;
            }
        }
        self.dirty = true;
        Ok(())
    }

    /// Reserve real zeroed allocation without extending EOF. A smaller
    /// allocation truncates EOF, as required by Windows allocation requests.
    pub(super) fn set_allocation(&mut self, bytes: u64) -> Result<()> {
        self.ensure_usable()?;
        if !bytes.is_multiple_of(self.block_size()) {
            return Err(crate::Error::InvalidArgument(
                "hfs+ handle: unaligned allocation size".into(),
            ));
        }
        let result = (|| {
            if bytes == self.allocated_bytes() {
                return Ok(());
            }
            self.private = true;
            if bytes > self.allocated_bytes() {
                self.ensure_capacity(bytes)?;
            } else {
                self.shrink_to(bytes)?;
                self.file_size = self.file_size.min(bytes);
                self.pos = self.pos.min(self.file_size);
            }
            self.dirty = true;
            Ok(())
        })();
        if result.is_err() {
            self.poison();
        }
        result
    }

    /// Re-encode the catalog file body to reflect the current run list
    /// and `file_size`. Inline extents go straight into the file
    /// record's selected fork; spilled extents use its own overflow tag.
    fn refresh_catalog_body(&mut self) -> Result<()> {
        // Build the new inline-fork descriptor up front so we don't
        // hold both an immutable view of `self.runs` and a mutable
        // borrow of `self.fs.writer` simultaneously.
        let mut inline = [ExtentDescriptor::default(); FORK_EXTENT_COUNT];
        let inline_count = self.runs.len().min(FORK_EXTENT_COUNT);
        for (slot, ext) in inline.iter_mut().zip(self.runs.iter().take(inline_count)) {
            *slot = *ext;
        }
        let total_blocks = self.total_blocks();
        let logical_size = self.file_size;
        let file_id = self.file_id;
        let fork_tag = self.fork.tag();
        let fork_offset = self.fork.offset();
        let extra_runs: Vec<ExtentDescriptor> = if self.runs.len() > FORK_EXTENT_COUNT {
            self.runs[FORK_EXTENT_COUNT..].to_vec()
        } else {
            Vec::new()
        };
        let writer =
            self.fs.writer.as_mut().ok_or_else(|| {
                crate::Error::InvalidArgument("hfs+: volume opened read-only".into())
            })?;
        let new_fork = ForkData {
            logical_size,
            clump_size: self.clump_size,
            total_blocks,
            extents: inline,
        };

        // 1. Patch only the selected 80-byte fork descriptor.
        let body = writer.catalog.get_mut(&self.cat_key).ok_or_else(|| {
            crate::Error::InvalidImage("hfs+ handle: catalog entry vanished".into())
        })?;
        if body.len() < fork_offset + FORK_DATA_SIZE {
            return Err(crate::Error::InvalidImage(
                "hfs+ handle: short catalog file body".into(),
            ));
        }
        if body.len() < 2 || i16::from_be_bytes([body[0], body[1]]) != REC_FILE {
            return Err(crate::Error::InvalidImage(
                "hfs+ handle: catalog body is not a file record".into(),
            ));
        }
        let enc = encode_fork_array(&new_fork);
        body[fork_offset..fork_offset + FORK_DATA_SIZE].copy_from_slice(&enc);

        // 2. Drop any existing overflow records for this file's selected
        //    fork; we'll re-emit them from the current run list.
        let keys: Vec<(u8, u32, u32)> = writer
            .overflow_extents
            .range((fork_tag, file_id, 0)..=(fork_tag, file_id, u32::MAX))
            .map(|(k, _)| *k)
            .collect();
        for k in keys {
            writer.overflow_extents.remove(&k);
        }

        // 3. If we have more than 8 runs, lay the remainder into
        //    extents-overflow records (8 per record), keyed by the
        //    fork-block where each record starts.
        if !extra_runs.is_empty() {
            let mut start_block: u32 = inline
                .iter()
                .map(|e| e.block_count)
                .fold(0u32, |a, b| a.saturating_add(b));
            for chunk in extra_runs.chunks(FORK_EXTENT_COUNT) {
                let mut group = [ExtentDescriptor::default(); FORK_EXTENT_COUNT];
                for (slot, ext) in group.iter_mut().zip(chunk.iter()) {
                    *slot = *ext;
                }
                writer
                    .overflow_extents
                    .insert((fork_tag, file_id, start_block), group);
                for ext in chunk {
                    start_block = start_block.saturating_add(ext.block_count);
                }
            }
        }
        Ok(())
    }

    /// Persist this handle's changes.
    ///
    /// Publish the private fork and retire old blocks in one metadata batch.
    /// Journal payload sync also persists all preceding private data writes.
    fn sync_inner(&mut self) -> Result<()> {
        self.ensure_usable()?;
        if !self.dirty {
            return Ok(());
        }
        // The replacement payload is private. Publish its pointer and retire
        // old blocks in the SAME metadata journal transaction.
        self.refresh_catalog_body()?;
        let writer = self.fs.writer.as_mut().unwrap();
        // Subtract live physical ranges from every owned allocation. Detached
        // private blocks and replaced/truncated committed blocks are retired
        // together. Untouched committed ranges remain allocated.
        for run in unused_runs(&self.committed_runs, &self.private_allocations, &self.runs)? {
            writer.free(run.start_block, run.block_count);
        }
        writer.flushed = false;
        self.fs.flush(self.dev)?;
        self.committed_runs.clone_from(&self.runs);
        self.committed_size = self.file_size;
        self.private_allocations.clear();
        self.private = false;
        self.dirty = false;
        Ok(())
    }
}

/// A fresh handle makes the aggregate reservation exact: all its current runs
/// are committed, and no replacement block may reuse storage retired here.
pub(super) fn edit_with_related_attributes(
    fs: &mut HfsPlus,
    dev: &mut dyn BlockDevice,
    path: &std::path::Path,
    resource: bool,
    edit: super::ForkEdit<'_>,
    metadata: super::PublicationMetadata<'_>,
) -> Result<bool> {
    use super::ForkEdit;
    let mut file = open_fork_rw(
        fs,
        dev,
        path,
        Default::default(),
        None,
        if resource {
            ForkKind::Resource
        } else {
            ForkKind::Data
        },
        false,
    )?;
    let bs = file.block_size();
    let allocated = file.allocated_bytes();
    let size = file.file_size;
    // Union of zero-filled gap and written range. Fresh growth is already
    // private; only the intersecting old allocation needs replacement copies.
    let range_blocks = |start: u64, end: u64| {
        let growth = end.div_ceil(bs).saturating_sub(allocated / bs);
        let visible_end = end.min(allocated).div_ceil(bs).min(size.div_ceil(bs));
        let copies = visible_end.saturating_sub(start / bs);
        growth + copies
    };
    let needed = match edit {
        ForkEdit::Write { offset, bytes } => {
            if bytes.is_empty() {
                return Ok(false);
            }
            let end = offset.checked_add(bytes.len() as u64).ok_or_else(|| {
                crate::Error::InvalidArgument("hfs+: write offset overflow".into())
            })?;
            range_blocks(offset.min(size), end)
        }
        ForkEdit::Resize(new_size) => {
            if new_size == size {
                return Ok(false);
            }
            if new_size > size {
                range_blocks(size, new_size)
            } else {
                0
            }
        }
        ForkEdit::Allocate { bytes, truncate } => {
            if !bytes.is_multiple_of(bs) {
                return Err(crate::Error::InvalidArgument(
                    "hfs+: unaligned allocation size".into(),
                ));
            }
            if bytes == allocated && !(truncate && size != 0) {
                return Ok(false);
            }
            if truncate && size != 0 {
                bytes / bs
            } else {
                (bytes / bs).saturating_sub(allocated / bs)
            }
        }
    };
    let plan = file.fs.plan_related_attributes(
        file.dev,
        file.file_id,
        super::RelatedTarget::Ordinary,
        metadata.attributes,
        metadata.related,
    )?;
    file.fs.validate_catalog_updates(
        file.file_id,
        super::RelatedTarget::Ordinary,
        false,
        metadata.catalog,
    )?;
    let free = plan
        .transaction
        .as_ref()
        .and_then(|(plan, _)| plan.allocation.as_ref())
        .map_or(file.fs.writer.as_ref().unwrap().free_blocks, |a| {
            a.free_blocks
        });
    if needed > u64::from(free) {
        return Err(crate::Error::InvalidArgument(
            "insufficient free space for combined fork edit and attributes".into(),
        ));
    }
    let result = (|| {
        // Stage the private metadata bitmap BEFORE the handle reserves payload
        // blocks, so neither allocator can replace the other's reservations.
        file.fs.stage_related_attribute_plan(plan.transaction)?;
        if let Some(finder) = plan.finder {
            file.fs.set_finder_info(file.file_id, &finder, None)?;
        }
        match edit {
            ForkEdit::Write { offset, bytes } => {
                file.pos = offset;
                file.write_inner(bytes)?;
            }
            ForkEdit::Resize(size) => file.set_len_inner(size)?,
            ForkEdit::Allocate { bytes, truncate } => {
                if truncate {
                    file.set_len_inner(0)?;
                }
                file.set_allocation(bytes)?;
            }
        }
        file.fs.stage_catalog_updates(metadata.catalog)?;
        file.sync_inner()?;
        Ok(true)
    })();
    if result.is_err() {
        file.poison();
    }
    result
}

/// A new symlink's payload must not become visible as ordinary user data before
/// its type and related metadata. Reuse private fork allocation and the existing
/// journal publication; do not change an already populated file or resource fork.
pub(super) fn convert_empty_file_to_symlink(
    fs: &mut HfsPlus,
    dev: &mut dyn BlockDevice,
    path: &std::path::Path,
    target: &str,
    metadata: super::PublicationMetadata<'_>,
) -> Result<()> {
    if target.is_empty() || target.len() > 1024 || target.contains('\0') || target.starts_with('/')
    {
        return Err(crate::Error::InvalidArgument(
            "hfs+: relative UTF-8 symlink target must contain 1..1024 non-NUL bytes".into(),
        ));
    }
    let mut file = open_file_rw(fs, dev, path, Default::default(), None)?;
    let body = file
        .fs
        .writer
        .as_ref()
        .unwrap()
        .catalog
        .get(&file.cat_key)
        .unwrap();
    let resource = ForkData::decode(body[168..248].try_into().unwrap());
    if file.file_size != 0
        || file.allocated_bytes() != 0
        || resource.logical_size != 0
        || resource.total_blocks != 0
        || resource
            .extents
            .iter()
            .any(|e| e.start_block != 0 || e.block_count != 0)
    {
        return Err(crate::Error::InvalidArgument(
            "hfs+: symlink conversion requires empty unallocated data and resource forks".into(),
        ));
    }
    let file_mode = u16::from_be_bytes(body[42..44].try_into().unwrap());
    let plan = file.fs.plan_related_attributes(
        file.dev,
        file.file_id,
        super::RelatedTarget::Ordinary,
        metadata.attributes,
        metadata.related,
    )?;
    file.fs.validate_catalog_updates(
        file.file_id,
        super::RelatedTarget::Ordinary,
        false,
        metadata.catalog,
    )?;
    let free = plan
        .transaction
        .as_ref()
        .and_then(|(plan, _)| plan.allocation.as_ref())
        .map_or(file.fs.writer.as_ref().unwrap().free_blocks, |a| {
            a.free_blocks
        });
    if (target.len() as u64).div_ceil(file.block_size()) > u64::from(free) {
        return Err(crate::Error::InvalidArgument(
            "insufficient space for symlink and metadata".into(),
        ));
    }
    let result = (|| {
        file.fs.stage_related_attribute_plan(plan.transaction)?;
        if let Some(finder) = plan.finder {
            file.fs.set_finder_info(file.file_id, &finder, None)?;
        }
        file.write_inner(target.as_bytes())?;
        file.fs.stage_catalog_updates(metadata.catalog)?;
        let body = file
            .fs
            .writer
            .as_mut()
            .unwrap()
            .catalog
            .get_mut(&file.cat_key)
            .unwrap();
        body[42..44].copy_from_slice(&((file_mode & !mode::S_IFMT) | mode::S_IFLNK).to_be_bytes());
        body[48..56].copy_from_slice(b"slnkrhap");
        body[168..248].fill(0); // Reserved empty symlink resource fork.
        file.sync_inner()
    })();
    if result.is_err() {
        file.poison();
    }
    result
}

/// A directory link is still a catalog *file* on HFS+. Keep both records in
/// the same publication instead of deleting/recreating the placeholder (which
/// would lose its identity, attributes and crash-atomic namespace).
pub(super) fn convert_empty_directory_to_symlink(
    fs: &mut HfsPlus,
    dev: &mut dyn BlockDevice,
    path: &std::path::Path,
    target: &str,
    metadata: super::PublicationMetadata<'_>,
) -> Result<()> {
    if target.is_empty() || target.len() > 1024 || target.contains('\0') || target.starts_with('/')
    {
        return Err(crate::Error::InvalidArgument(
            "hfs+: invalid relative symlink target".into(),
        ));
    }
    let path_str = path
        .to_str()
        .ok_or_else(|| crate::Error::InvalidArgument("hfs+: non-UTF-8 path".into()))?;
    let body = fs.catalog_record(path_str)?;
    if body.len() != 88
        || i16::from_be_bytes(body[..2].try_into().unwrap()) != super::catalog::REC_FOLDER
    {
        return Err(crate::Error::InvalidArgument(
            "hfs+: directory placeholder required".into(),
        ));
    }
    let cnid = u32::from_be_bytes(body[8..12].try_into().unwrap());
    let key = fs.metadata_edit_key(cnid)?; // Includes root/private/lock/thread guards.
    let journal = super::journal::JournalLog::load(dev, &fs.volume_header)?;
    if journal.as_ref().is_some_and(|log| log.is_dirty()) {
        return Err(crate::Error::InvalidImage(
            "hfs+: dirty journal requires reopening".into(),
        ));
    }
    let w = fs.writer.as_ref().unwrap();
    if body[4..8] != [0; 4]
        || w.catalog
            .iter()
            .any(|(key, _)| key.parent_id == cnid && !key.name.code_units.is_empty())
    {
        return Err(crate::Error::InvalidArgument(
            "hfs+: directory placeholder is not empty".into(),
        ));
    }
    // Only ordinary attribute/security/folder-count flags have defined meaning
    // here. Folder bounds and extended Finder fields are not file metadata.
    let flags = u16::from_be_bytes(body[2..4].try_into().unwrap());
    if flags & !0x1c != 0
        || body[44..56].iter().any(|b| *b != 0)
        || body[64..80].iter().any(|b| *b != 0)
        || body[84..88] != [0; 4]
        || w.overflow_extents.keys().any(|(_, id, _)| *id == cnid)
    {
        return Err(crate::Error::Unsupported(
            "hfs+: directory has metadata requiring separate conversion semantics".into(),
        ));
    }
    if metadata
        .attributes
        .iter()
        .any(|(name, _)| *name == "com.apple.FinderInfo")
        || metadata
            .catalog
            .iter()
            .any(|update| update.cnid == cnid && update.attributes.is_some())
    {
        return Err(crate::Error::Unsupported(
            "hfs+: directory conversion accepts dates and ordinary attributes only".into(),
        ));
    }
    // Preflight against the unchanged directory before staging either record.
    let plan = fs.plan_related_attributes(
        dev,
        cnid,
        super::RelatedTarget::Ordinary,
        metadata.attributes,
        metadata.related,
    )?;
    fs.validate_catalog_updates(
        cnid,
        super::RelatedTarget::Ordinary,
        false,
        metadata.catalog,
    )?;
    let free = plan
        .transaction
        .as_ref()
        .and_then(|(plan, _)| plan.allocation.as_ref())
        .map_or(w.free_blocks, |a| a.free_blocks);
    if (target.len() as u64).div_ceil(u64::from(w.block_size)) > u64::from(free) {
        return Err(crate::Error::InvalidArgument(
            "insufficient space for directory link and metadata".into(),
        ));
    }
    drop(plan);
    let mut file_body = vec![0; 248];
    file_body[..2].copy_from_slice(&REC_FILE.to_be_bytes());
    file_body[2..4].copy_from_slice(&(flags & !0x10).to_be_bytes());
    file_body[8..48].copy_from_slice(&body[8..48]); // CNID, dates and BSD ownership.
    let permissions = u16::from_be_bytes(body[42..44].try_into().unwrap()) & !mode::S_IFMT;
    file_body[42..44].copy_from_slice(&(permissions | mode::S_IFREG).to_be_bytes());
    file_body[56..64].copy_from_slice(&body[56..64]); // Shared Finder flags/location.
    file_body[80..84].copy_from_slice(&body[80..84]); // Text encoding.
    let thread_key = OwnedKey {
        parent_id: cnid,
        name: UniStr::default(),
    };
    let thread = super::writer::encode_thread_body(
        super::catalog::REC_FILE_THREAD,
        key.parent_id,
        &key.name,
    );
    let w = fs.writer.as_mut().unwrap();
    w.catalog.insert(key, file_body);
    w.catalog.insert(thread_key, thread);
    w.flushed = false;
    // The ordinary converter stages target/type/attributes and performs the
    // single durable publication. A failure after staging must poison the
    // writer, including any late read failure before a device write occurs.
    let result = convert_empty_file_to_symlink(fs, dev, path, target, metadata);
    if result.is_err() {
        fs.write_failed = true;
    }
    result
}

/// Only a newly-created, empty ordinary data fork may use this staging helper.
/// The constructor has already checked aggregate space and identity. Its caller
/// owns publication, so the local handle must not sync on success or drop.
pub(super) fn reserve_new_entry(
    fs: &mut HfsPlus,
    dev: &mut dyn BlockDevice,
    path: &std::path::Path,
    allocation: u64,
) -> Result<()> {
    let mut file = open_file_rw(fs, dev, path, Default::default(), None)?;
    if file.file_size != 0 || file.allocated_bytes() != 0 {
        return Err(crate::Error::InvalidArgument(
            "hfs+: creation reservation needs an empty new fork".into(),
        ));
    }
    let result = (|| {
        file.set_allocation(allocation)?;
        file.refresh_catalog_body()?;
        file.dirty = false;
        Ok(())
    })();
    if result.is_err() {
        file.poison();
    }
    result
}

impl<'a> Read for HfsPlusFileHandle<'a> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.read_inner(buf)
    }
}

impl<'a> Write for HfsPlusFileHandle<'a> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.ensure_usable()
            .map_err(|e| io::Error::other(e.to_string()))?;
        let result = self.write_inner(buf);
        if result.is_err() {
            self.poison();
        }
        result
    }

    fn flush(&mut self) -> io::Result<()> {
        self.sync().map_err(|e| io::Error::other(e.to_string()))
    }
}

impl<'a> Seek for HfsPlusFileHandle<'a> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.ensure_usable()
            .map_err(|e| io::Error::other(e.to_string()))?;
        let new_pos: i128 = match pos {
            SeekFrom::Start(n) => n as i128,
            SeekFrom::End(d) => self.file_size as i128 + d as i128,
            SeekFrom::Current(d) => self.pos as i128 + d as i128,
        };
        if new_pos < 0 || new_pos > u64::MAX as i128 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "hfs+: seek to negative offset",
            ));
        }
        self.pos = new_pos as u64;
        Ok(self.pos)
    }
}

impl<'a> FileHandle for HfsPlusFileHandle<'a> {
    fn len(&self) -> u64 {
        self.file_size
    }

    fn set_len(&mut self, new_len: u64) -> Result<()> {
        self.ensure_usable()?;
        let result = self.set_len_inner(new_len);
        if result.is_err() {
            self.poison();
        }
        result
    }

    fn sync(&mut self) -> Result<()> {
        let result = self.sync_inner();
        if result.is_err() {
            self.poison();
        }
        result
    }
}

impl<'a> Drop for HfsPlusFileHandle<'a> {
    fn drop(&mut self) {
        // Best-effort: persist on drop so the file is durable even when
        // the caller forgets to `sync`. Drop can't return errors, so the
        // failure is reported on stderr instead of vanishing — callers
        // that need to act on it must `sync()` explicitly.
        if self.dirty && !self.failed && !self.fs.write_failed {
            if let Err(e) = self.sync_inner() {
                self.poison();
                eprintln!(
                    "hfs+: failed to persist file {:?} on close: {e}",
                    self.cat_key.name.to_display_name()
                );
            }
            self.dirty = false;
        }
    }
}

/// Encode an `HFSPlusForkData` (80 bytes) into a byte array. Mirrors
/// the writer's `fork_to_array` helper (kept private there) — duplicated
/// here so the handle stays decoupled from writer internals.
fn encode_fork_array(fork: &ForkData) -> [u8; FORK_DATA_SIZE] {
    let mut out = [0u8; FORK_DATA_SIZE];
    out[0..8].copy_from_slice(&fork.logical_size.to_be_bytes());
    out[8..12].copy_from_slice(&fork.clump_size.to_be_bytes());
    out[12..16].copy_from_slice(&fork.total_blocks.to_be_bytes());
    for (i, ext) in fork.extents.iter().enumerate() {
        let off = 16 + i * 8;
        out[off..off + 4].copy_from_slice(&ext.start_block.to_be_bytes());
        out[off + 4..off + 8].copy_from_slice(&ext.block_count.to_be_bytes());
    }
    out
}

/// Dedicated replacement of an existing symlink. No public file handle gains
/// access to link payloads; all ownership/metadata checks finish before writes.
pub(super) fn replace_symlink_target(
    fs: &mut HfsPlus,
    dev: &mut dyn BlockDevice,
    path: &std::path::Path,
    target: &str,
    metadata: super::PublicationMetadata<'_>,
) -> Result<()> {
    if target.is_empty() || target.len() > 1024 || target.contains('\0') || target.starts_with('/')
    {
        return Err(crate::Error::InvalidArgument(
            "hfs+: invalid relative symlink target".into(),
        ));
    }
    let path_str = path
        .to_str()
        .ok_or_else(|| crate::Error::InvalidArgument("hfs+: non-UTF-8 path".into()))?;
    let body = fs.catalog_record(path_str)?;
    let cnid = u32::from_be_bytes(body[8..12].try_into().unwrap());
    fs.metadata_key_inner(cnid, false, false, false, true)?;
    fs.validate_remove_attributes(dev, cnid)?;
    // Read and validate the existing payload before any private allocation.
    let old = fs.read_symlink_target(dev, cnid)?;
    if old.is_empty() || old.len() > 1024 || old.contains('\0') {
        return Err(crate::Error::Unsupported(
            "hfs+: unsupported existing symlink target".into(),
        ));
    }
    if metadata
        .catalog
        .iter()
        .any(|u| u.cnid == cnid && u.attributes.is_some())
    {
        return Err(crate::Error::Unsupported(
            "hfs+: target replacement cannot change link flags".into(),
        ));
    }
    let mut file = open_fork_rw(
        fs,
        dev,
        path,
        Default::default(),
        None,
        ForkKind::Data,
        true,
    )?;
    let plan = file.fs.plan_related_attributes(
        file.dev,
        cnid,
        super::RelatedTarget::Symbolic,
        metadata.attributes,
        metadata.related,
    )?;
    if plan.finder.is_some() {
        return Err(crate::Error::Unsupported(
            "hfs+: target replacement preserves Finder identity".into(),
        ));
    }
    file.fs.validate_catalog_updates(
        cnid,
        super::RelatedTarget::Symbolic,
        false,
        metadata.catalog,
    )?;
    let free = plan
        .transaction
        .as_ref()
        .and_then(|(plan, _)| plan.allocation.as_ref())
        .map_or(file.fs.writer.as_ref().unwrap().free_blocks, |a| {
            a.free_blocks
        });
    if (target.len() as u64).div_ceil(file.block_size()) > u64::from(free) {
        return Err(crate::Error::InvalidArgument(
            "insufficient space for symlink replacement and metadata".into(),
        ));
    }
    let result = (|| {
        file.fs.stage_related_attribute_plan(plan.transaction)?;
        // Shrink only this private handle's run list. Committed blocks remain
        // allocated until sync publishes the new pointer and retires them.
        file.set_len_inner(0)?;
        file.write_inner(target.as_bytes())?;
        file.fs.stage_catalog_updates(metadata.catalog)?;
        file.sync_inner()
    })();
    if result.is_err() {
        file.poison();
    }
    result
}

/// Retire a conventional link's data fork and restore an empty ordinary entry
/// in one publication. The caller supplies the Windows directory hint. No
/// target is followed, and directory-only metadata conversions are bounded.
pub(super) fn remove_symlink(
    fs: &mut HfsPlus,
    dev: &mut dyn BlockDevice,
    path: &std::path::Path,
    directory: bool,
    metadata: super::PublicationMetadata<'_>,
) -> Result<()> {
    let path_str = path
        .to_str()
        .ok_or_else(|| crate::Error::InvalidArgument("hfs+: non-UTF-8 path".into()))?;
    let body = fs.catalog_record(path_str)?;
    let cnid = u32::from_be_bytes(body[8..12].try_into().unwrap());
    fs.metadata_key_inner(cnid, false, false, false, true)?;
    // metadata_key_inner also accepts ordinary nodes; require the link identity.
    if body.len() != 248
        || &body[48..56] != b"slnkrhap"
        || u16::from_be_bytes(body[42..44].try_into().unwrap()) & mode::S_IFMT != mode::S_IFLNK
    {
        return Err(crate::Error::InvalidArgument(
            "hfs+: conventional symbolic link required".into(),
        ));
    }
    fs.validate_remove_attributes(dev, cnid)?;
    let old = fs.read_symlink_target(dev, cnid)?;
    if old.is_empty() || old.len() > 1024 || old.contains('\0') {
        return Err(crate::Error::Unsupported(
            "hfs+: unsupported existing symlink target".into(),
        ));
    }
    let flags = u16::from_be_bytes(body[2..4].try_into().unwrap());
    if directory
        && (flags & !0x0c != 0
            || body[44..48].iter().any(|b| *b != 0)
            || body[64..80].iter().any(|b| *b != 0)
            || body[84..88] != [0; 4])
    {
        return Err(crate::Error::Unsupported(
            "hfs+: link metadata has no directory representation".into(),
        ));
    }
    if metadata
        .catalog
        .iter()
        .any(|u| u.cnid == cnid && u.attributes.is_some())
    {
        return Err(crate::Error::Unsupported(
            "hfs+: link removal cannot change flags".into(),
        ));
    }
    let mut file = open_fork_rw(
        fs,
        dev,
        path,
        Default::default(),
        None,
        ForkKind::Data,
        true,
    )?;
    let plan = file.fs.plan_related_attributes(
        file.dev,
        cnid,
        super::RelatedTarget::Symbolic,
        metadata.attributes,
        metadata.related,
    )?;
    if plan.finder.is_some() {
        return Err(crate::Error::Unsupported(
            "hfs+: link removal cannot replace Finder metadata".into(),
        ));
    }
    file.fs.validate_catalog_updates(
        cnid,
        super::RelatedTarget::Symbolic,
        false,
        metadata.catalog,
    )?;
    let result = (|| {
        file.fs.stage_related_attribute_plan(plan.transaction)?;
        file.set_len_inner(0)?;
        file.refresh_catalog_body()?;
        file.fs.stage_catalog_updates(metadata.catalog)?;
        let w = file.fs.writer.as_mut().unwrap();
        for run in unused_runs(&file.committed_runs, &file.private_allocations, &file.runs)? {
            w.free(run.start_block, run.block_count);
        }
        // Read the staged body so attribute-presence flags and dates survive.
        let staged = w.catalog.get_mut(&file.cat_key).unwrap();
        let permissions = u16::from_be_bytes(staged[42..44].try_into().unwrap()) & !mode::S_IFMT;
        staged[42..44].copy_from_slice(
            &(permissions
                | if directory {
                    mode::S_IFDIR
                } else {
                    mode::S_IFREG
                })
            .to_be_bytes(),
        );
        staged[48..56].fill(0);
        if directory {
            let mut folder = staged[..88].to_vec();
            folder[..2].copy_from_slice(&super::catalog::REC_FOLDER.to_be_bytes());
            folder[4..8].fill(0);
            w.catalog.insert(file.cat_key.clone(), folder);
            let thread_key = OwnedKey {
                parent_id: cnid,
                name: UniStr::default(),
            };
            let thread = super::writer::encode_thread_body(
                super::catalog::REC_FOLDER_THREAD,
                file.cat_key.parent_id,
                &file.cat_key.name,
            );
            w.catalog.insert(thread_key, thread);
        }
        w.flushed = false;
        file.fs.flush(file.dev)?;
        // The entry may now be a folder: do not run the file-fork synchronizer
        // on drop. All ownership was retired by the publication above.
        file.dirty = false;
        Ok(())
    })();
    if result.is_err() {
        file.poison();
    }
    result
}

/// Open `path` for read+write, honoring the requested flags. A pending
/// journal is refused here because recovery would invalidate the cached
/// catalog. Recovery must happen before constructing this filesystem.
pub(super) fn open_file_rw<'a>(
    fs: &'a mut HfsPlus,
    dev: &'a mut dyn BlockDevice,
    path: &std::path::Path,
    flags: crate::fs::OpenFlags,
    meta: Option<crate::fs::FileMeta>,
) -> Result<HfsPlusFileHandle<'a>> {
    open_fork_rw(fs, dev, path, flags, meta, ForkKind::Data, false)
}

pub(super) fn open_resource_rw<'a>(
    fs: &'a mut HfsPlus,
    dev: &'a mut dyn BlockDevice,
    path: &std::path::Path,
) -> Result<HfsPlusFileHandle<'a>> {
    open_fork_rw(
        fs,
        dev,
        path,
        Default::default(),
        None,
        ForkKind::Resource,
        false,
    )
}

fn open_fork_rw<'a>(
    fs: &'a mut HfsPlus,
    dev: &'a mut dyn BlockDevice,
    path: &std::path::Path,
    flags: crate::fs::OpenFlags,
    meta: Option<crate::fs::FileMeta>,
    kind: ForkKind,
    symbolic: bool,
) -> Result<HfsPlusFileHandle<'a>> {
    if fs.write_failed {
        return Err(crate::Error::InvalidArgument(
            "hfs+: failed edit requires reopening the volume".into(),
        ));
    }
    let path_str = path
        .to_str()
        .ok_or_else(|| crate::Error::InvalidArgument(format!("hfs+: non-UTF-8 path {path:?}")))?;

    // A pending journal would invalidate this handle's cached catalog. The
    // volume must be reopened and recovered before attaching an editor.
    let journal = super::journal::JournalLog::load(dev, &fs.volume_header)?;
    if journal.as_ref().is_some_and(|log| log.is_dirty()) {
        return Err(crate::Error::InvalidImage(
            "hfs+: dirty journal requires reopening".into(),
        ));
    }

    // Resolve to an existing file, optionally creating it. We can't
    // borrow `fs` through the lookup machinery while we also need a
    // mutable borrow for create, so do them in distinct phases.
    let resolved = lookup_file_for_rw(fs, path_str);
    let (parent_id, name) = split_parent_and_name(fs, path_str)?;
    let owned_key = OwnedKey {
        parent_id,
        name: name.clone(),
    };

    let resolved = match resolved {
        Ok(()) => Some(()),
        Err(_) if flags.create => None,
        Err(e) => return Err(e),
    };

    if resolved.is_none() {
        // create=true path. Insert an empty regular file via the
        // existing writer machinery.
        let meta = meta.ok_or_else(|| {
            crate::Error::InvalidArgument(
                "hfs+: open_file_rw with create=true requires meta".into(),
            )
        })?;
        let mut empty = std::io::Cursor::new(Vec::<u8>::new());
        fs.create_file(
            dev, path_str, &mut empty, 0, meta.mode, meta.uid, meta.gid, meta.mtime,
        )?;
    }

    // Read the catalog body and assemble the merged run list.
    let (file_id, file_size, runs, clump_size) = {
        let writer = fs
            .writer
            .as_ref()
            .ok_or_else(|| crate::Error::InvalidArgument("hfs+: volume opened read-only".into()))?;
        let body = writer.catalog.get(&owned_key).ok_or_else(|| {
            crate::Error::InvalidArgument(format!(
                "hfs+: no entry {:?} under CNID {parent_id}",
                name.to_string_lossy()
            ))
        })?;
        if body.len() < 248 || i16::from_be_bytes([body[0], body[1]]) != REC_FILE {
            return Err(crate::Error::InvalidArgument(format!(
                "hfs+: {path_str} is not a regular file"
            )));
        }
        // Verify the file is a plain regular (not hlnk, not slnk).
        let file_type = &body[48..52];
        let creator = &body[52..56];
        if file_type == b"hlnk" && creator == b"hfs+" {
            return Err(crate::Error::Unsupported(format!(
                "hfs+: {path_str} is a hard link; open_file_rw on the iNode is not implemented"
            )));
        }
        if !symbolic && file_type == b"slnk" && creator == b"rhap" {
            return Err(crate::Error::InvalidArgument(format!(
                "hfs+: {path_str} is a symlink, not a regular file"
            )));
        }
        // mode_bits: file_mode lives inside BSDInfo at body[32..48], with
        // file_mode at byte 42..44.
        let file_mode = u16::from_be_bytes([body[42], body[43]]);
        let mode_bits = file_mode & mode::S_IFMT;
        if if symbolic {
            !matches!(kind, ForkKind::Data)
                || mode_bits != mode::S_IFLNK
                || file_type != b"slnk"
                || creator != b"rhap"
                || body[168..248].iter().any(|b| *b != 0)
        } else {
            mode_bits != 0 && mode_bits != mode::S_IFREG
        } {
            return Err(crate::Error::Unsupported(format!(
                "hfs+: {path_str} is not a regular file (mode {file_mode:#06o})"
            )));
        }
        let file_id = u32::from_be_bytes(body[8..12].try_into().unwrap());
        if file_id < 16
            || u16::from_be_bytes(body[2..4].try_into().unwrap()) & 1 != 0
            || (body[40] | body[41]) & 0x06 != 0
            || body[41] & 0x20 != 0
            || u16::from_be_bytes(body[56..58].try_into().unwrap()) & 0x1000 != 0
        {
            return Err(crate::Error::Unsupported(
                "hfs+ handle: reserved, locked or compressed file".into(),
            ));
        }

        let mut fork_buf = [0u8; FORK_DATA_SIZE];
        let fork_offset = kind.offset();
        let fork_tag = kind.tag();
        fork_buf.copy_from_slice(&body[fork_offset..fork_offset + FORK_DATA_SIZE]);
        let fork = ForkData::decode(&fork_buf);

        // Merged run list: inline extents first, then overflow groups
        // in fork-block order.
        let mut runs: Vec<ExtentDescriptor> = Vec::new();
        for ext in &fork.extents {
            if ext.block_count == 0 {
                continue;
            }
            runs.push(*ext);
        }
        let mut logical_blocks: u64 = runs.iter().map(|r| u64::from(r.block_count)).sum();
        for ((fork_type, fid, start), group) in writer
            .overflow_extents
            .range((fork_tag, file_id, 0)..=(fork_tag, file_id, u32::MAX))
        {
            debug_assert_eq!((*fork_type, *fid), (fork_tag, file_id));
            if u64::from(*start) != logical_blocks {
                return Err(crate::Error::InvalidImage(
                    "hfs+ handle: discontinuous fork overflow".into(),
                ));
            }
            for ext in group {
                if ext.block_count == 0 {
                    continue;
                }
                runs.push(*ext);
                logical_blocks += u64::from(ext.block_count);
            }
        }

        let covered: u64 = runs.iter().map(|r| u64::from(r.block_count)).sum();
        if covered != u64::from(fork.total_blocks)
            || fork.logical_size > covered * u64::from(writer.block_size)
            || runs.iter().any(|r| {
                r.start_block == 0
                    || r.start_block
                        .checked_add(r.block_count)
                        .is_none_or(|end| end > writer.total_blocks)
            })
        {
            return Err(crate::Error::InvalidImage(
                "hfs+ handle: invalid fork extent coverage".into(),
            ));
        }
        let mut physical = runs.clone();
        physical.sort_by_key(|run| run.start_block);
        if physical
            .windows(2)
            .any(|pair| pair[0].start_block + pair[0].block_count > pair[1].start_block)
        {
            return Err(crate::Error::InvalidImage(
                "hfs+ handle: overlapping fork extents".into(),
            ));
        }
        // Neither fork may retire blocks owned by its sibling. Check both
        // inline and overflow ranges before allowing any payload writes.
        let other_tag = if fork_tag == FORK_DATA {
            FORK_RESOURCE
        } else {
            FORK_DATA
        };
        let other_offset = if fork_offset == 88 { 168 } else { 88 };
        fork_buf.copy_from_slice(&body[other_offset..other_offset + FORK_DATA_SIZE]);
        let other = ForkData::decode(&fork_buf);
        let siblings = other.extents.iter().chain(
            writer
                .overflow_extents
                .range((other_tag, file_id, 0)..=(other_tag, file_id, u32::MAX))
                .flat_map(|(_, group)| group.iter()),
        );
        for sibling in siblings.filter(|r| r.block_count != 0) {
            let sibling_end = sibling
                .start_block
                .checked_add(sibling.block_count)
                .ok_or_else(|| {
                    crate::Error::InvalidImage("hfs+ handle: sibling extent overflow".into())
                })?;
            if runs.iter().any(|r| {
                r.start_block < sibling_end && sibling.start_block < r.start_block + r.block_count
            }) {
                return Err(crate::Error::InvalidImage(
                    "hfs+ handle: data/resource forks share blocks".into(),
                ));
            }
        }
        for run in &runs {
            for block in run.start_block..run.start_block + run.block_count {
                if writer
                    .bitmap
                    .get(block as usize / 8)
                    .is_none_or(|b| b & (0x80 >> (block % 8)) == 0)
                {
                    return Err(crate::Error::InvalidImage(
                        "hfs+ handle: fork references unallocated blocks".into(),
                    ));
                }
            }
        }
        (file_id, fork.logical_size, runs, fork.clump_size)
    };

    let mut handle =
        HfsPlusFileHandle::new(fs, dev, owned_key, file_id, runs, file_size, clump_size);
    handle.fork = kind;
    if flags.truncate && handle.file_size > 0 {
        handle.set_len(0)?;
    }
    if flags.append {
        handle.pos = handle.file_size;
    }
    Ok(handle)
}

fn locate_in(runs: &[ExtentDescriptor], block_size: u64, fork_off: u64) -> Option<(u64, u64)> {
    let mut cursor = 0;
    for run in runs {
        let bytes = u64::from(run.block_count) * block_size;
        if fork_off < cursor + bytes {
            let into = fork_off - cursor;
            return Some((u64::from(run.start_block) * block_size + into, bytes - into));
        }
        cursor += bytes;
    }
    None
}

/// Dedicated conversion path. The ordinary handle constructor continues to
/// reject compressed entries. All source claims and decoding are validated
/// before this handle can write a private replacement block.
#[cfg(feature = "hfs-compression")]
pub(super) fn replace_compressed(
    fs: &mut HfsPlus,
    dev: &mut dyn BlockDevice,
    path: &std::path::Path,
    input: &mut dyn Read,
    size: u64,
) -> Result<()> {
    replace_compressed_next(fs, dev, path, &mut |_, bytes| Ok(input.read(bytes)?), size)
}

#[cfg(feature = "hfs-compression")]
pub(super) fn replace_compressed_next(
    fs: &mut HfsPlus,
    dev: &mut dyn BlockDevice,
    path: &std::path::Path,
    next: &mut dyn FnMut(&mut dyn BlockDevice, &mut [u8]) -> Result<usize>,
    size: u64,
) -> Result<()> {
    replace_compressed_planned(fs, dev, path, next, size, 0, &[], &[])
}

#[cfg(feature = "hfs-compression")]
#[allow(clippy::too_many_arguments)]
pub(super) fn replace_compressed_planned(
    fs: &mut HfsPlus,
    dev: &mut dyn BlockDevice,
    path: &std::path::Path,
    next: &mut dyn FnMut(&mut dyn BlockDevice, &mut [u8]) -> Result<usize>,
    size: u64,
    allocation: u64,
    changes: &[(&str, Option<&[u8]>)],
    related: &[(u32, &str, Option<&[u8]>)],
) -> Result<()> {
    replace_compressed_publication(
        fs,
        dev,
        path,
        next,
        size,
        allocation,
        super::PublicationMetadata {
            attributes: changes,
            related,
            catalog: &[],
        },
    )
}

#[cfg(feature = "hfs-compression")]
pub(super) fn replace_compressed_publication(
    fs: &mut HfsPlus,
    dev: &mut dyn BlockDevice,
    path: &std::path::Path,
    next: &mut dyn FnMut(&mut dyn BlockDevice, &mut [u8]) -> Result<usize>,
    size: u64,
    allocation: u64,
    metadata: super::PublicationMetadata<'_>,
) -> Result<()> {
    let path = path
        .to_str()
        .ok_or_else(|| crate::Error::InvalidArgument("non-UTF-8 conversion path".into()))?;
    let original = fs.catalog_record(path)?;
    if original.len() != 248 {
        return Err(crate::Error::Unsupported(
            "conversion requires a regular file".into(),
        ));
    }
    let cnid = u32::from_be_bytes(original[8..12].try_into().unwrap());
    fs.validate_compressed_replacement_with_related_attributes(
        dev,
        cnid,
        size,
        allocation,
        metadata.attributes,
        metadata.related,
    )?;
    fs.validate_catalog_updates(
        cnid,
        super::RelatedTarget::Compressed,
        false,
        metadata.catalog,
    )?;
    let key = fs.metadata_edit_key_with_compression(cnid, true)?;
    let (header, _) = super::compression::header(fs, dev, cnid)?;
    let resource = ForkData::decode(original[168..248].try_into().unwrap());
    let retired = if header.resource() {
        fs.open_fork(dev, &resource, cnid, FORK_RESOURCE, "conversion resource")?
            .extents
    } else {
        Vec::new()
    };
    let plan =
        fs.compressed_related_attribute_plan(dev, cnid, metadata.attributes, metadata.related)?;
    let finder = plan.finder;
    let clump = u32::from_be_bytes(original[96..100].try_into().unwrap());
    let mut handle = HfsPlusFileHandle::new(fs, dev, key.clone(), cnid, Vec::new(), 0, clump);
    let result = (|| -> Result<()> {
        // Reserve fresh attribute payloads before allocating data. Retired
        // attribute blocks remain allocated until their journal publication.
        handle.fs.stage_related_attribute_plan(plan.transaction)?;
        if allocation != 0 {
            handle.set_allocation(allocation)?;
        }
        let mut scratch = vec![0; 64 * 1024];
        let mut remaining = size;
        while remaining != 0 {
            let count = remaining.min(scratch.len() as u64) as usize;
            let mut filled = 0;
            while filled < count {
                let got = next(handle.dev, &mut scratch[filled..count])?;
                if got == 0 || got > count - filled {
                    return Err(crate::Error::InvalidArgument(
                        "conversion input ended before its declared size".into(),
                    ));
                }
                filled += got;
            }
            handle.write_all(&scratch[..count])?;
            remaining -= count as u64;
        }
        if next(handle.dev, &mut scratch[..1])? != 0 {
            return Err(crate::Error::InvalidArgument(
                "conversion input exceeds its declared size".into(),
            ));
        }
        handle.refresh_catalog_body()?;
        let w = handle.fs.writer.as_mut().unwrap();
        let body = w.catalog.get_mut(&key).unwrap();
        body[41] &= !super::decmpfs::UF_COMPRESSED;
        if let Some(finder) = finder {
            super::attributes::store_finder_info(body, &finder);
        }
        if header.resource() {
            body[168..248].fill(0);
            w.overflow_extents
                .retain(|(tag, id, _), _| *tag != FORK_RESOURCE || *id != cnid);
            // No further payload allocations follow these frees. Metadata
            // homes and bitmap changes belong to the same journal batch.
            for run in retired {
                w.free(run.start_block, run.block_count);
            }
        }
        handle.dirty = true; // Includes an empty replacement's metadata changes.
        handle.fs.stage_catalog_updates(metadata.catalog)?;
        handle.sync_inner()
    })();
    if result.is_err() {
        handle.poison();
    }
    result
}

fn coalesce_runs(runs: &mut Vec<ExtentDescriptor>) {
    let mut merged: Vec<ExtentDescriptor> = Vec::with_capacity(runs.len());
    for run in std::mem::take(runs) {
        if let Some(last) = merged.last_mut()
            && last.start_block.checked_add(last.block_count) == Some(run.start_block)
            && let Some(count) = last.block_count.checked_add(run.block_count)
        {
            last.block_count = count;
        } else {
            merged.push(run);
        }
    }
    *runs = merged;
}

fn replace_block(runs: &mut Vec<ExtentDescriptor>, index: u64, physical: u32) -> Result<()> {
    let mut base = 0u64;
    for slot in 0..runs.len() {
        let run = runs[slot];
        if index < base + u64::from(run.block_count) {
            let before = u32::try_from(index - base).unwrap();
            let after = run.block_count - before - 1;
            let mut replacement = Vec::with_capacity(3);
            if before > 0 {
                replacement.push(ExtentDescriptor {
                    block_count: before,
                    ..run
                });
            }
            replacement.push(ExtentDescriptor {
                start_block: physical,
                block_count: 1,
            });
            if after > 0 {
                replacement.push(ExtentDescriptor {
                    start_block: run.start_block + before + 1,
                    block_count: after,
                });
            }
            runs.splice(slot..=slot, replacement);
            coalesce_runs(runs);
            return Ok(());
        }
        base += u64::from(run.block_count);
    }
    Err(crate::Error::InvalidImage(
        "hfs+ handle: replacement block is past fork".into(),
    ))
}

/// Range subtraction avoids a bitmap/set entry for every block in a huge file.
fn unused_runs(
    committed: &[ExtentDescriptor],
    private: &BTreeMap<u32, u32>,
    current: &[ExtentDescriptor],
) -> Result<Vec<ExtentDescriptor>> {
    let mut live = BTreeMap::new();
    for run in current {
        let end = run
            .start_block
            .checked_add(run.block_count)
            .ok_or_else(|| {
                crate::Error::InvalidImage("hfs+ handle: live extent overflow".into())
            })?;
        if live.insert(run.start_block, end).is_some() {
            return Err(crate::Error::InvalidImage(
                "hfs+ handle: duplicate live extent".into(),
            ));
        }
    }
    let mut unused = Vec::new();
    for (start, count) in committed
        .iter()
        .map(|run| (run.start_block, run.block_count))
        .chain(private.iter().map(|(&start, &count)| (start, count)))
    {
        let end = start.checked_add(count).ok_or_else(|| {
            crate::Error::InvalidImage("hfs+ handle: owned extent overflow".into())
        })?;
        let mut pos = start;
        while pos < end {
            if let Some((_, &live_end)) = live.range(..=pos).next_back()
                && live_end > pos
            {
                pos = live_end.min(end);
            } else {
                let until = live
                    .range(pos..)
                    .next()
                    .map_or(end, |(&next, _)| next.min(end));
                unused.push(ExtentDescriptor {
                    start_block: pos,
                    block_count: until - pos,
                });
                pos = until;
            }
        }
    }
    Ok(unused)
}

/// Probe the writer's in-memory catalog for a regular file at
/// `path_str`. Returns Ok only when the entry exists.
fn lookup_file_for_rw(fs: &HfsPlus, path_str: &str) -> Result<()> {
    let (parent_id, name) = split_parent_and_name(fs, path_str)?;
    let writer = fs
        .writer
        .as_ref()
        .ok_or_else(|| crate::Error::InvalidArgument("hfs+: volume opened read-only".into()))?;
    let key = OwnedKey {
        parent_id,
        name: name.clone(),
    };
    if writer.catalog.contains_key(&key) {
        Ok(())
    } else {
        Err(crate::Error::InvalidArgument(format!(
            "hfs+: no entry {:?} under CNID {parent_id}",
            name.to_string_lossy()
        )))
    }
}

/// Walk `path_str` and return the parent CNID + final-name component,
/// resolving every intermediate against the writer's in-memory catalog.
fn split_parent_and_name(fs: &HfsPlus, path_str: &str) -> Result<(u32, UniStr)> {
    let parts: Vec<&str> = path_str
        .split('/')
        .filter(|p| !p.is_empty() && *p != ".")
        .collect();
    if parts.is_empty() {
        return Err(crate::Error::InvalidArgument(
            "hfs+: cannot open the root path".into(),
        ));
    }
    let (last, prefix) = parts.split_last().unwrap();
    let writer = fs
        .writer
        .as_ref()
        .ok_or_else(|| crate::Error::InvalidArgument("hfs+: volume opened read-only".into()))?;
    let mut cnid = super::catalog::ROOT_FOLDER_ID;
    for part in prefix {
        let name = UniStr::from_path_component_checked(part)?;
        let (_, child_cnid, rec_type) = writer.lookup(cnid, &name).ok_or_else(|| {
            crate::Error::InvalidArgument(format!("hfs+: parent component {part:?} does not exist"))
        })?;
        if rec_type != super::catalog::REC_FOLDER {
            return Err(crate::Error::InvalidArgument(format!(
                "hfs+: component {part:?} is not a directory"
            )));
        }
        cnid = child_cnid;
    }
    Ok((cnid, UniStr::from_path_component_checked(last)?))
}
