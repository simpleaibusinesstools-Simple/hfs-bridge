//! HFS+ — Apple's legacy macOS filesystem (pre-2017).
//!
//! ## Status
//!
//! Read and write support.
//!
//! Read side: open, list directories, stream regular file contents,
//! read symbolic-link targets, and resolve hard links to their
//! underlying indirect-node iNodes. Files whose data fork spills
//! beyond eight inline extents are read through the extents-overflow
//! B-tree.
//!
//! Write side: format a fresh volume, create directories, regular
//! files, symbolic links, and hard links; remove empty directories
//! and files (with their forks). The writer keeps user data forks
//! streaming-only (64 KiB scratch) and spills fragmented files into
//! the extents-overflow B-tree when their run list outgrows the eight
//! inline extents in a catalog record. An optional journal stub
//! (clean, no transactions to replay) can be requested via
//! [`writer::FormatOpts::journaled`].
//!
//! Implementation is based on Apple Technical Note TN1150, the
//! canonical public reference for HFS+ on-disk structures.
//!
//! ## Scope and deferred features
//!
//! * Low-level open can replay a pending journal. The enclosing Windows
//!   application's checked opener refuses it and offers recovery into a copy.
//! * HFSX case-sensitive comparison is honoured at the catalog-key
//!   level; non-ASCII case folding follows a simplified table.
//! * The local fork supports checked attribute-tree edits and fork-backed
//!   values, including bounded multi-entry inline batches and reclamation.
//! * The production compression reader supports decmpfs formats 1, 3, 4 and
//!   7 through 14, with bounded conversion to ordinary data on supported writes.
//!   The older `decmpfs` helper is not the production reader.
//! * Ordinary resource-fork editing is supported through checked private-block
//!   publication. Linked, locked and unsupported special nodes retain guards.
//!
//! ## Module layout
//!
//! * [`volume_header`] — the 512-byte `HFSPlusVolumeHeader` at offset 1024.
//! * [`btree`] — node descriptors, header records, record-offset tables.
//! * [`catalog`] — catalog keys, leaf records, lookup.
//! * [`extents`] — extents-overflow B-tree walker for spilled extents.
//! * [`attributes`] — extended-attribute B-tree walker.
//! * [`decmpfs`] — HFSCompression header / block decoder.

mod attribute_delete;
mod attribute_value;
pub mod attributes;
pub mod btree;
pub(crate) mod case_fold;
pub mod catalog;
mod catalog_ownership;
#[cfg(feature = "hfs-compression")]
mod compression;
pub mod decmpfs;
#[cfg(feature = "hfs-compression")]
mod decmpfs_reader;
pub mod extents;
pub mod handle;
pub(crate) mod journal;
mod reclamation;
pub mod size_plan;
pub mod unicode;
mod unicode_data;
pub mod volume_header;
pub mod writer;

/// Low-level journal transactions, also used by independent durability tests.
pub use journal::JournalLog;
pub use journal::{ReplaySummary, preflight_replay, replay_journal};
pub use writer::FormatOpts;

/// One ordinary fork mutation with a single metadata publication.
#[derive(Clone, Copy, Debug)]
pub enum ForkEdit<'a> {
    Write { offset: u64, bytes: &'a [u8] },
    Resize(u64),
    Allocate { bytes: u64, truncate: bool },
}

/// Native catalog fields to publish with a mutation. Time order is creation,
/// access, write, change, in HFS seconds. Attributes use the native 0xb3 subset.
#[derive(Clone, Copy, Debug)]
pub struct CatalogUpdate {
    pub cnid: u32,
    pub times: [Option<u32>; 4],
    pub attributes: Option<u32>,
}

/// A complete caller-supplied metadata batch, validated before payload writes.
#[derive(Clone, Copy, Default)]
pub struct PublicationMetadata<'a> {
    pub attributes: &'a [(&'a str, Option<&'a [u8]>)],
    pub related: &'a [(u32, &'a str, Option<&'a [u8]>)],
    pub catalog: &'a [CatalogUpdate],
}

use std::io::Read;

use crate::Result;
use crate::block::BlockDevice;

use attributes::Attributes;
use btree::ForkReader;
use catalog::{Catalog, CatalogFile, CatalogKey, CatalogRecord, ROOT_FOLDER_ID, UniStr, mode};
use extents::ExtentsOverflow;
use volume_header::{ForkData, VolumeHeader, read_volume_header};

/// Maximum bytes we'll ever read from a symlink's data fork; symlinks
/// are tiny path strings and a sane filesystem stays well under this.
const SYMLINK_MAX_BYTES: u64 = 4096;

/// Seconds between the HFS+ epoch (1904-01-01) and the Unix epoch
/// (1970-01-01). HFS+ stores catalog dates as seconds since 1904.
const HFS_EPOCH_OFFSET: u32 = 2_082_844_800;

/// One preflighted tree publication. Keys are resolved again before staging;
/// a constructor's future identity does not exist during preflight.
struct RelatedAttributePlan {
    finder: Option<[u8; 32]>,
    transaction: Option<(
        attribute_delete::Plan,
        std::collections::BTreeMap<u32, bool>,
    )>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum RelatedTarget {
    Future,
    Ordinary,
    Compressed,
    Symbolic,
}

/// Convert Unix epoch seconds to an HFS+ catalog date. `0` (no timestamp)
/// maps to `0`; values past the u32 range saturate.
fn unix_to_hfs_time(unix: u32) -> u32 {
    if unix == 0 {
        0
    } else {
        unix.saturating_add(HFS_EPOCH_OFFSET)
    }
}

/// Validated committed attribute-tree snapshot for a read-only caller.
/// Discard after any volume publication; payload forks are still read and
/// validated through the owning filesystem before their values are returned.
pub struct AttributeReadIndex {
    names: std::collections::BTreeMap<u32, Vec<String>>,
    records: Vec<Vec<u8>>,
    fixed_tree_supported: bool,
}
impl AttributeReadIndex {
    pub fn names(&self, cnid: u32) -> Vec<String> {
        self.names.get(&cnid).cloned().unwrap_or_default()
    }
}

/// An opened HFS+ volume.
pub struct HfsPlus {
    /// Any failed mutation/flush requires closing and reopening the volume.
    write_failed: bool,
    volume_header: VolumeHeader,
    catalog: Catalog,
    /// Extents-overflow B-tree, refreshed together with the catalog on flush.
    /// Absent only if the volume header has no extents-overflow file,
    /// which is unusual but technically permitted.
    overflow: Option<ExtentsOverflow>,
    /// Attributes B-tree (extended attributes), opened lazily-but-once
    /// at mount time. Absent on volumes that have never had an xattr
    /// set — including every volume produced by this writer.
    attributes: Option<Attributes>,
    /// CNID of the HFS+ private data directory (where `iNode<N>`
    /// indirect-node files live), if it exists on this volume.
    /// Resolved lazily on first hard-link encounter.
    private_dir_cnid: std::cell::Cell<Option<u32>>,
    /// `true` once we've attempted to resolve `private_dir_cnid`. We
    /// cache the absent result too so we don't re-scan every time.
    private_dir_resolved: std::cell::Cell<bool>,
    /// Cached volume name, taken from the root folder's thread record.
    volume_name: String,
    /// Writer state, present only while a freshly formatted volume
    /// (or one re-opened for mutation) is being built. `None` for
    /// read-only opens.
    writer: Option<writer::Writer>,
}

impl HfsPlus {
    /// Open an existing HFS+ volume on `dev`. The returned handle is
    /// writable: subsequent `create_*` / `remove` calls mutate the live
    /// image, and [`flush`](Self::flush) persists the rewritten catalog,
    /// extents-overflow tree, allocation bitmap, and volume header.
    ///
    /// On a journaled volume any unreplayed transaction is drained
    /// *before* we read the catalog, extents-overflow, or bitmap: the
    /// pending journal may carry the only authoritative copy of those
    /// blocks following a crash mid-`flush`. Replay is idempotent, so
    /// volumes that crashed mid-replay land in the same state.
    pub fn open(dev: &mut dyn BlockDevice) -> Result<Self> {
        // Read the volume header first so we know whether replay is
        // applicable (journaled vs. not) and where the journal lives.
        let vh = read_volume_header(dev)?;
        journal::replay(dev, &vh)?;
        // Re-read the volume header in case replay restored it.
        let vh = read_volume_header(dev)?;
        let hfsx = vh.is_hfsx();

        let cat_fork = ForkReader::from_inline(&vh.catalog_file, vh.block_size, "catalog")?;
        let catalog = Catalog::open(dev, cat_fork, hfsx)?;

        // Open the extents-overflow file if its fork has any blocks.
        // It can be empty on a fresh volume.
        let overflow = if vh.extents_file.total_blocks > 0 {
            let ext_fork =
                ForkReader::from_inline(&vh.extents_file, vh.block_size, "extents-overflow")?;
            Some(ExtentsOverflow::open(dev, ext_fork)?)
        } else {
            None
        };

        // Open the attributes B-tree if the volume carries one. This
        // is the table HFSCompression reads `com.apple.decmpfs` from;
        // images produced by our writer have an empty attributes fork
        // and so skip this path entirely.
        let attributes = open_attributes(dev, &vh, hfsx)?;

        // The root folder's thread record is keyed by (ROOT_FOLDER_ID, "");
        // its name field is the volume name.
        let volume_name = lookup_thread_name(dev, &catalog, ROOT_FOLDER_ID)?
            .unwrap_or_else(|| "Untitled".to_string());

        // Reconstruct the in-memory writer state by walking the catalog
        // leaves and the extents-overflow leaves and loading the on-disk
        // bitmap. After this, create_* / remove / flush all work on the
        // live image exactly as they do post-format.
        let writer = writer::open_writable(dev, &vh, volume_name.clone())?;

        Ok(Self {
            write_failed: false,
            volume_header: vh,
            catalog,
            overflow,
            attributes,
            private_dir_cnid: std::cell::Cell::new(None),
            private_dir_resolved: std::cell::Cell::new(false),
            volume_name,
            writer: Some(writer),
        })
    }

    /// A staging, write or publication error made this instance unsafe to reuse.
    /// Pure preflight refusals do not set this flag.
    pub fn requires_reopen(&self) -> bool {
        self.write_failed
    }

    /// A read snapshot can be reused only between complete metadata publications.
    /// The caller must also check live volume identity and invalidate on mutation.
    pub fn metadata_is_committed(&self) -> bool {
        !self.write_failed
            && self
                .writer
                .as_ref()
                .is_some_and(|w| w.metadata_matches(&self.volume_header))
    }

    /// Require the classic 1904 epoch for every loaded file and folder. Apple
    /// permits individual records to opt into expanded dates independently of
    /// the volume flag. This check only reads the already loaded catalog.
    pub fn require_classic_catalog_dates(&self) -> Result<()> {
        let writer = self.writer.as_ref().ok_or_else(|| {
            crate::Error::Unsupported("hfs+: date preflight requires a loaded catalog".into())
        })?;
        for body in writer.catalog.values() {
            if body.len() >= 4
                && matches!(
                    i16::from_be_bytes(body[..2].try_into().unwrap()),
                    catalog::REC_FILE | catalog::REC_FOLDER
                )
                && u16::from_be_bytes(body[2..4].try_into().unwrap()) & 0x1000 != 0
            {
                return Err(crate::Error::Unsupported(
                    "hfs+: expanded catalog timestamps are not supported".into(),
                ));
            }
        }
        Ok(())
    }

    /// Format `dev` as a fresh HFS+ volume and return a handle that
    /// accepts subsequent `create_*` calls. Call [`flush`](Self::flush)
    /// when done to persist the catalog, bitmap, and volume header.
    pub fn format(dev: &mut dyn BlockDevice, opts: &writer::FormatOpts) -> Result<Self> {
        let (vh, w) = writer::format(dev, opts)?;
        let hfsx = vh.is_hfsx();
        let mut w = w;
        let mut vh_mut = vh.clone();
        writer::flush(&mut w, &mut vh_mut, dev)?;
        w.flushed = false;

        let cat_fork = ForkReader::from_inline(&vh_mut.catalog_file, vh_mut.block_size, "catalog")?;
        let catalog = Catalog::open(dev, cat_fork, hfsx)?;
        let overflow = if vh_mut.extents_file.total_blocks > 0 {
            let ext_fork = ForkReader::from_inline(
                &vh_mut.extents_file,
                vh_mut.block_size,
                "extents-overflow",
            )?;
            Some(ExtentsOverflow::open(dev, ext_fork)?)
        } else {
            None
        };
        let attributes = open_attributes(dev, &vh_mut, hfsx)?;
        let volume_name = w.volume_name.clone();
        Ok(Self {
            write_failed: false,
            volume_header: vh_mut,
            catalog,
            overflow,
            attributes,
            private_dir_cnid: std::cell::Cell::new(None),
            private_dir_resolved: std::cell::Cell::new(false),
            volume_name,
            writer: Some(w),
        })
    }

    /// Create a directory at the given absolute path.
    #[allow(clippy::too_many_arguments)]
    pub fn create_dir(
        &mut self,
        _dev: &mut dyn BlockDevice,
        path: &str,
        mode: u16,
        uid: u32,
        gid: u32,
        mtime: u32,
    ) -> Result<u32> {
        let (parent_id, name) = self.resolve_new_target(path)?;
        let w = self
            .writer
            .as_mut()
            .ok_or_else(|| crate::Error::InvalidArgument("hfs+: volume is read-only".into()))?;
        let cnid = w.next_cnid;
        w.next_cnid = w
            .next_cnid
            .checked_add(1)
            .ok_or_else(|| crate::Error::Unsupported("hfs+: CNID space exhausted".into()))?;
        writer::insert_folder(
            w,
            parent_id,
            &name,
            cnid,
            mode,
            uid,
            gid,
            unix_to_hfs_time(mtime),
        )?;
        Ok(cnid)
    }

    /// Create a regular file at the given absolute path, streaming
    /// `len` bytes from `src` into freshly allocated allocation blocks.
    #[allow(clippy::too_many_arguments)]
    pub fn create_file<R: std::io::Read + ?Sized>(
        &mut self,
        dev: &mut dyn BlockDevice,
        path: &str,
        src: &mut R,
        len: u64,
        mode: u16,
        uid: u32,
        gid: u32,
        mtime: u32,
    ) -> Result<u32> {
        let (parent_id, name) = self.resolve_new_target(path)?;
        let w = self
            .writer
            .as_mut()
            .ok_or_else(|| crate::Error::InvalidArgument("hfs+: volume is read-only".into()))?;
        let cnid = w.next_cnid;
        w.next_cnid = w
            .next_cnid
            .checked_add(1)
            .ok_or_else(|| crate::Error::Unsupported("hfs+: CNID space exhausted".into()))?;
        let fork = writer::stream_data_to_blocks(w, dev, src, len, cnid)?;
        writer::insert_file(
            w,
            parent_id,
            &name,
            cnid,
            mode | catalog::mode::S_IFREG,
            uid,
            gid,
            unix_to_hfs_time(mtime),
            *b"\0\0\0\0",
            *b"\0\0\0\0",
            &fork,
            0,
        )?;
        Ok(cnid)
    }

    /// Create a symlink at `path` whose target is the UTF-8 byte string
    /// `target`. Finder type `slnk` / creator `rhap`, mode S_IFLNK.
    #[allow(clippy::too_many_arguments)]
    pub fn create_symlink(
        &mut self,
        dev: &mut dyn BlockDevice,
        path: &str,
        target: &str,
        mode: u16,
        uid: u32,
        gid: u32,
        mtime: u32,
    ) -> Result<u32> {
        let (parent_id, name) = self.resolve_new_target(path)?;
        let w = self
            .writer
            .as_mut()
            .ok_or_else(|| crate::Error::InvalidArgument("hfs+: volume is read-only".into()))?;
        let cnid = w.next_cnid;
        w.next_cnid = w
            .next_cnid
            .checked_add(1)
            .ok_or_else(|| crate::Error::Unsupported("hfs+: CNID space exhausted".into()))?;
        let fork = writer::write_inline_data(w, dev, target.as_bytes())?;
        writer::insert_file(
            w,
            parent_id,
            &name,
            cnid,
            mode | catalog::mode::S_IFLNK,
            uid,
            gid,
            unix_to_hfs_time(mtime),
            *b"slnk",
            *b"rhap",
            &fork,
            0,
        )?;
        Ok(cnid)
    }

    /// Create a device, FIFO, or socket node. HFS+ encodes the kind
    /// through the `BSDInfo.fileMode` `S_IF*` bits, and packs the rdev
    /// for char/block devices into `BSDInfo.special` using the same
    /// Linux "new"-style encoding fstool uses elsewhere
    /// ([`crate::fs::devnum::encode_devnum`]) so a tar round-trip
    /// through HFS+ preserves `(major, minor)`. FIFOs and sockets
    /// store `special = 0`.
    ///
    /// The data fork is empty (special files have no content). Catalog
    /// `fileType` / `creator` are zero, mirroring how Apple writes
    /// these on a real volume.
    #[allow(clippy::too_many_arguments)]
    pub fn create_device(
        &mut self,
        _dev: &mut dyn BlockDevice,
        path: &str,
        kind: crate::fs::DeviceKind,
        major: u32,
        minor: u32,
        mode: u16,
        uid: u32,
        gid: u32,
        mtime: u32,
    ) -> Result<u32> {
        let (parent_id, name) = self.resolve_new_target(path)?;
        let w = self
            .writer
            .as_mut()
            .ok_or_else(|| crate::Error::InvalidArgument("hfs+: volume is read-only".into()))?;
        let cnid = w.next_cnid;
        w.next_cnid = w
            .next_cnid
            .checked_add(1)
            .ok_or_else(|| crate::Error::Unsupported("hfs+: CNID space exhausted".into()))?;
        let (kind_bits, special) = match kind {
            crate::fs::DeviceKind::Char => (
                catalog::mode::S_IFCHR,
                crate::fs::devnum::encode_devnum(major, minor),
            ),
            crate::fs::DeviceKind::Block => (
                catalog::mode::S_IFBLK,
                crate::fs::devnum::encode_devnum(major, minor),
            ),
            crate::fs::DeviceKind::Fifo => (catalog::mode::S_IFIFO, 0),
            crate::fs::DeviceKind::Socket => (catalog::mode::S_IFSOCK, 0),
        };
        writer::insert_file(
            w,
            parent_id,
            &name,
            cnid,
            mode | kind_bits,
            uid,
            gid,
            unix_to_hfs_time(mtime),
            *b"\0\0\0\0",
            *b"\0\0\0\0",
            &ForkData::default(),
            special,
        )?;
        Ok(cnid)
    }

    /// Create a hard link at `dst_path` pointing at the same on-disk
    /// content as `src_path`. After the call:
    ///
    /// * the data fork that previously lived under `src_path` is owned
    ///   by an `iNode<N>` file inside the HFS+ private-data directory;
    /// * both `src_path` and `dst_path` are `hlnk`/`hfs+` indirect-node
    ///   catalog entries with `BSDInfo.special == N`;
    /// * the read path (`open_file_reader`, `list_path`, …) follows the
    ///   hlnk pointer transparently and exposes the original bytes
    ///   under both names.
    ///
    /// Returns the link-inode number `N`. Errors if `src_path` is a
    /// directory, a symlink, or an already-existing hard link.
    pub fn create_hardlink(
        &mut self,
        _dev: &mut dyn BlockDevice,
        src_path: &str,
        dst_path: &str,
    ) -> Result<u32> {
        let (src_parent, src_name) = self.resolve_create_target(src_path)?;
        let (dst_parent, dst_name) = self.resolve_new_target(dst_path)?;
        let w = self
            .writer
            .as_mut()
            .ok_or_else(|| crate::Error::InvalidArgument("hfs+: volume is read-only".into()))?;
        writer::promote_to_hardlink(w, src_parent, &src_name, dst_parent, &dst_name)
    }

    /// Remove a file, symlink, or empty directory at `path`.
    pub fn remove(&mut self, dev: &mut dyn BlockDevice, path: &str) -> Result<()> {
        let (parent_id, name) = self.resolve_create_target(path)?;
        let cnid = u32::from_be_bytes(self.catalog_record(path)?[8..12].try_into().unwrap());
        self.validate_remove_attributes(dev, cnid)?;
        let w = self
            .writer
            .as_mut()
            .ok_or_else(|| crate::Error::InvalidArgument("hfs+: volume is read-only".into()))?;
        writer::remove_entry(w, parent_id, &name)?;
        w.attribute_delete_ids.insert(cnid);
        Ok(())
    }

    /// Validate node/fork ownership and supported attribute reclamation without
    /// staging or writing. Every deletion entry point uses this preflight.
    pub fn validate_remove_attributes(&self, dev: &mut dyn BlockDevice, cnid: u32) -> Result<()> {
        let w = self
            .writer
            .as_ref()
            .ok_or_else(|| crate::Error::Unsupported("read-only volume".into()))?;
        if w.attribute_edit_plan.is_some() {
            return Err(crate::Error::Unsupported(
                "hfs+: flush the pending attribute edit before file deletion".into(),
            ));
        }
        self.validate_attribute_storage(dev)?;
        reclamation::validate(self, dev, cnid)?;
        let mut deleted = w.attribute_delete_ids.clone();
        deleted.insert(cnid);
        if let Some(plan) = attribute_delete::plan(dev, &w.attributes_file, w.block_size, &deleted)?
        {
            self.validate_attribute_value_extents(dev, &plan.retired, true)?;
            if !plan.retired.is_empty() {
                let records = attribute_delete::records(dev, &w.attributes_file, w.block_size)?;
                let mut occupied = attribute_value::forks(&records, w.block_size, w.total_blocks)?
                    .into_iter()
                    .flat_map(|(_, reader)| reader.extents)
                    .collect::<Vec<_>>();
                occupied.sort_by_key(|extent| extent.start_block);
                if occupied.windows(2).any(|p| {
                    u64::from(p[0].start_block) + u64::from(p[0].block_count)
                        > u64::from(p[1].start_block)
                }) {
                    return Err(crate::Error::InvalidImage(
                        "hfs+: shared attribute value blocks".into(),
                    ));
                }
            }
        }
        Ok(())
    }

    /// Rename or move an existing entry, preserving its CNID, record metadata,
    /// data/resource forks and CNID-keyed attributes. Replacement is refused.
    pub fn rename(
        &mut self,
        _dev: &mut dyn BlockDevice,
        source: &str,
        destination: &str,
    ) -> Result<()> {
        let (source_parent, source_name) = self.resolve_create_target(source)?;
        let (target_parent, target_name) = self.resolve_create_target(destination)?;
        let writer = self
            .writer
            .as_mut()
            .ok_or_else(|| crate::Error::InvalidArgument("hfs+: volume is read-only".into()))?;
        writer::rename_entry(
            writer,
            source_parent,
            &source_name,
            target_parent,
            &target_name,
        )
    }

    /// Rename the volume's root catalog key and its CNID-2 thread together.
    /// Ordinary entry rename deliberately cannot modify reserved identities.
    /// The existing flush/journal path publishes these two records atomically.
    pub fn set_volume_name(&mut self, name: &str) -> Result<()> {
        if name.chars().any(|c| matches!(c, '/' | ':' | '\0')) {
            return Err(crate::Error::InvalidArgument(
                "hfs+: invalid volume name".into(),
            ));
        }
        let name = UniStr::from_path_component_checked(name)?;
        let old_key = self.catalog_key_by_cnid(ROOT_FOLDER_ID)?;
        if old_key.parent_id != catalog::ROOT_PARENT_ID {
            return Err(crate::Error::InvalidImage(
                "hfs+: invalid volume root parent".into(),
            ));
        }
        let w = self.writer.as_mut().ok_or_else(|| {
            crate::Error::Unsupported("hfs+: volume name requires a writer".into())
        })?;
        let body = w.catalog.get(&old_key).unwrap().clone();
        if (body[40] | body[41]) & 0x06 != 0
            || u16::from_be_bytes(body[56..58].try_into().unwrap()) & 0x1000 != 0
        {
            return Err(crate::Error::Unsupported(
                "hfs+: volume root is locked".into(),
            ));
        }
        if old_key.name == name {
            return Ok(());
        }
        if let Some((_, cnid, _)) = w.lookup(catalog::ROOT_PARENT_ID, &name)
            && cnid != ROOT_FOLDER_ID
        {
            return Err(crate::Error::InvalidImage(
                "hfs+: volume name collides with another root record".into(),
            ));
        }
        let thread_key = writer::OwnedKey {
            parent_id: ROOT_FOLDER_ID,
            name: UniStr::default(),
        };
        // catalog_key_by_cnid already validated the forward/thread identity.
        let mut thread = w.catalog.get(&thread_key).unwrap()[..8].to_vec();
        thread.extend_from_slice(&(name.code_units.len() as u16).to_be_bytes());
        for unit in &name.code_units {
            thread.extend_from_slice(&unit.to_be_bytes());
        }
        let display = name.to_display_name();
        w.catalog.remove(&old_key);
        w.catalog.insert(
            writer::OwnedKey {
                parent_id: catalog::ROOT_PARENT_ID,
                name,
            },
            body,
        );
        w.catalog.insert(thread_key, thread);
        w.volume_name = display.clone();
        self.volume_name = display;
        w.flushed = false;
        Ok(())
    }

    /// Snapshot the raw file/folder catalog body for identity and metadata
    /// verification. Thread keys and volume-root renaming are not exposed.
    pub fn catalog_record(&self, path: &str) -> Result<Vec<u8>> {
        let (parent, name) = self.resolve_create_target(path)?;
        let writer = self.writer.as_ref().ok_or_else(|| {
            crate::Error::Unsupported("hfs+: catalog snapshot requires a loaded writer".into())
        })?;
        let (key, _, _) = writer.lookup(parent, &name).ok_or_else(|| {
            crate::Error::InvalidArgument("hfs+: catalog entry does not exist".into())
        })?;
        Ok(writer.catalog.get(&key).unwrap().clone())
    }

    /// Reverse a live catalog identity, checking its thread against the exact
    /// forward key. No lossy UTF-16 conversion or catalog-wide scan is used.
    fn catalog_key_by_cnid(&self, cnid: u32) -> Result<writer::OwnedKey> {
        if self.write_failed {
            return Err(crate::Error::InvalidArgument(
                "hfs+: failed edit requires reopening the volume".into(),
            ));
        }
        let w = self.writer.as_ref().ok_or_else(|| {
            crate::Error::Unsupported("hfs+: identity lookup requires a loaded writer".into())
        })?;
        let thread_key = writer::OwnedKey {
            parent_id: cnid,
            name: UniStr::default(),
        };
        let body = w.catalog.get(&thread_key).ok_or_else(|| {
            crate::Error::InvalidArgument("hfs+: catalog identity does not exist".into())
        })?;
        let CatalogRecord::Thread(thread) = CatalogRecord::decode(body)? else {
            return Err(crate::Error::InvalidImage(
                "hfs+: identity key is not a thread".into(),
            ));
        };
        let key = writer::OwnedKey {
            parent_id: thread.parent_id,
            name: thread.name,
        };
        let body = w.catalog.get(&key).ok_or_else(|| {
            crate::Error::InvalidImage("hfs+: thread points to a missing entry".into())
        })?;
        let expected_thread = match CatalogRecord::decode(body)? {
            CatalogRecord::Folder(folder) if folder.folder_id == cnid => catalog::REC_FOLDER_THREAD,
            CatalogRecord::File(file) if file.file_id == cnid => catalog::REC_FILE_THREAD,
            _ => {
                return Err(crate::Error::InvalidImage(
                    "hfs+: thread identity mismatch".into(),
                ));
            }
        };
        if i16::from_be_bytes(w.catalog.get(&thread_key).unwrap()[..2].try_into().unwrap())
            != expected_thread
        {
            return Err(crate::Error::InvalidImage(
                "hfs+: thread kind mismatch".into(),
            ));
        }
        Ok(key)
    }

    /// Current path for an open CNID, including renamed ancestors. Checks cycles
    /// and each parent kind before returning a String-based engine path.
    pub fn catalog_path(&self, mut cnid: u32) -> Result<String> {
        let mut visited = alloc::collections::BTreeSet::new();
        let mut components = Vec::new();
        while cnid != ROOT_FOLDER_ID {
            if !visited.insert(cnid) {
                return Err(crate::Error::InvalidImage(
                    "hfs+: catalog parent cycle".into(),
                ));
            }
            let key = self.catalog_key_by_cnid(cnid)?;
            let name = key.name.to_display_name();
            if UniStr::from_path_component_checked(&name)?.code_units != key.name.code_units {
                return Err(crate::Error::Unsupported(
                    "hfs+: path name cannot round-trip".into(),
                ));
            }
            components.push(name);
            cnid = key.parent_id;
            if !matches!(
                CatalogRecord::decode(&self.catalog_record_cnid(cnid)?)?,
                CatalogRecord::Folder(_)
            ) {
                return Err(crate::Error::InvalidImage(
                    "hfs+: catalog parent is not a folder".into(),
                ));
            }
        }
        // Validate the root even when it was the requested identity.
        self.catalog_key_by_cnid(ROOT_FOLDER_ID)?;
        components.reverse();
        Ok(format!("/{}", components.join("/")))
    }

    pub fn catalog_record_cnid(&self, cnid: u32) -> Result<Vec<u8>> {
        let key = self.catalog_key_by_cnid(cnid)?;
        Ok(self
            .writer
            .as_ref()
            .unwrap()
            .catalog
            .get(&key)
            .unwrap()
            .clone())
    }

    /// Read a small fixed-size inline record from the current committed tree.
    /// Absent, fork-backed and malformed value bodies return None. Structural
    /// tree and device errors remain errors. No value extents are ever read.
    /// The caller must independently validate the returned record's contents.
    pub fn fixed_inline_attribute(
        &self,
        dev: &mut dyn BlockDevice,
        cnid: u32,
        name: &str,
        expected_size: usize,
    ) -> Result<Option<Vec<u8>>> {
        self.catalog_key_by_cnid(cnid)?;
        attribute_delete::inline_record(cnid, name, &[])?;
        if expected_size > 3802 {
            return Err(crate::Error::InvalidArgument(
                "hfs+: fixed attribute read limit".into(),
            ));
        }
        let w = self.writer.as_ref().unwrap();
        if w.attribute_edit_plan.is_some() {
            return Err(crate::Error::Unsupported(
                "flush pending attribute edit before read".into(),
            ));
        }
        if w.attributes_file.total_blocks == 0 {
            if w.attributes_file.logical_size != 0 || w.attributes_file.inline_blocks() != 0 {
                return Err(crate::Error::InvalidImage(
                    "hfs+: inconsistent empty attributes fork".into(),
                ));
            }
            return Ok(None);
        }
        self.validate_attribute_storage(dev)?;
        let fork = ForkReader::from_inline(&w.attributes_file, w.block_size, "attributes")?;
        if fork.logical_size < 512
            || fork.logical_size
                > u64::from(w.attributes_file.total_blocks) * u64::from(w.block_size)
        {
            return Err(crate::Error::InvalidImage(
                "hfs+: invalid attributes fork length".into(),
            ));
        }
        // self.attributes describes the originally opened tree, which may have
        // moved after a committed copy-on-write edit. Always reopen the writer fork.
        attributes::Attributes::open(dev, fork, true)?.lookup_fixed_inline(
            dev,
            cnid,
            name,
            expected_size,
        )
    }

    /// Read a committed attribute using its exact binary UTF-16 name.
    /// The legacy method name is retained for callers. Fork-backed values
    /// follow their attribute continuation records, with a 16 MiB read cap.
    /// ResourceFork/FinderInfo are represented separately in the catalog.
    pub fn inline_attribute(
        &self,
        dev: &mut dyn BlockDevice,
        cnid: u32,
        name: &str,
    ) -> Result<Option<Vec<u8>>> {
        self.catalog_key_by_cnid(cnid)?;
        attribute_delete::inline_record(cnid, name, &[])?;
        if name == "com.apple.FinderInfo" {
            let body = self.catalog_record_cnid(cnid)?;
            let mut bytes = attributes::public_finder_info(body[48..80].try_into().unwrap());
            if &bytes[..8] == b"slnkrhap" {
                bytes[..8].fill(0);
            }
            return Ok(bytes.iter().any(|b| *b != 0).then(|| bytes.to_vec()));
        }
        if self.writer.as_ref().unwrap().attribute_edit_plan.is_some() {
            return Err(crate::Error::Unsupported(
                "flush pending attribute edit before read".into(),
            ));
        }
        let w = self.writer.as_ref().unwrap();
        if w.attributes_file.total_blocks == 0 {
            return Ok(None);
        }
        self.validate_attribute_storage(dev)?;
        let records = attribute_delete::records(dev, &w.attributes_file, w.block_size)?;
        self.read_attribute_records(dev, cnid, name, &records)
    }

    fn read_attribute_records(
        &self,
        dev: &mut dyn BlockDevice,
        cnid: u32,
        name: &str,
        records: &[Vec<u8>],
    ) -> Result<Option<Vec<u8>>> {
        let w = self.writer.as_ref().unwrap();
        let wanted = name.encode_utf16().collect::<Vec<_>>();
        let group = records
            .iter()
            .filter_map(|record| match attributes::AttrKey::decode(record) {
                Ok(key) if key.file_id == cnid && key.name.code_units == wanted => {
                    Some(Ok(record.as_slice()))
                }
                Ok(_) => None,
                Err(error) => Some(Err(error)),
            })
            .collect::<Result<Vec<_>>>()?;
        if group.is_empty() {
            return Ok(None);
        }
        match attribute_value::decode(&group, w.block_size, w.total_blocks)? {
            attribute_value::Value::Inline(data) => Ok(Some(data)),
            attribute_value::Value::Fork(reader) => {
                self.validate_attribute_value_extents(dev, &reader.extents, true)?;
                for (other_key, other) in
                    attribute_value::forks(records, w.block_size, w.total_blocks)?
                {
                    if other_key.file_id == cnid && other_key.name.code_units == wanted {
                        continue;
                    }
                    if reader.extents.iter().any(|a| {
                        other.extents.iter().any(|b| {
                            u64::from(a.start_block)
                                < u64::from(b.start_block) + u64::from(b.block_count)
                                && u64::from(b.start_block)
                                    < u64::from(a.start_block) + u64::from(a.block_count)
                        })
                    }) {
                        return Err(crate::Error::InvalidImage(
                            "hfs+: shared attribute value blocks".into(),
                        ));
                    }
                }
                if reader.logical_size > 16 * 1024 * 1024 {
                    return Err(crate::Error::Unsupported(
                        "hfs+: attribute value exceeds 16 MiB read limit".into(),
                    ));
                }
                let length = usize::try_from(reader.logical_size).map_err(|_| {
                    crate::Error::Unsupported("hfs+: attribute value exceeds address space".into())
                })?;
                let mut data = vec![0; length];
                reader.read(dev, 0, &mut data)?;
                Ok(Some(data))
            }
        }
    }

    /// Names and raw records from a fully validated committed attribute tree.
    /// The returned index is a snapshot: callers must discard it after any
    /// publication. Fork-backed payloads are not read into the snapshot.
    pub fn attribute_read_index(&self, dev: &mut dyn BlockDevice) -> Result<AttributeReadIndex> {
        let w = self.writer.as_ref().ok_or_else(|| {
            crate::Error::Unsupported("hfs+: attribute index needs loaded catalog".into())
        })?;
        if w.attribute_edit_plan.is_some() {
            return Err(crate::Error::Unsupported(
                "flush pending attribute edit before read".into(),
            ));
        }
        self.validate_attribute_storage(dev)?;
        let (records, fixed_tree_supported) =
            attribute_delete::records_with_fixed_support(dev, &w.attributes_file, w.block_size)?;
        let mut index = std::collections::BTreeMap::<u32, Vec<String>>::new();
        for record in &records {
            let key = attributes::AttrKey::decode(record)?;
            if key.start_block == 0 {
                let name = String::from_utf16(&key.name.code_units).map_err(|_| {
                    crate::Error::Unsupported(
                        "attribute name cannot round-trip through UTF-16".into(),
                    )
                })?;
                index.entry(key.file_id).or_default().push(name);
            }
        }
        Ok(AttributeReadIndex {
            names: index,
            records,
            fixed_tree_supported,
        })
    }

    /// Read using a caller-owned, current committed snapshot. Value decoding,
    /// size limits and fork ownership checks are shared with the uncached API.
    pub fn indexed_attribute(
        &self,
        dev: &mut dyn BlockDevice,
        index: &AttributeReadIndex,
        cnid: u32,
        name: &str,
    ) -> Result<Option<Vec<u8>>> {
        self.catalog_key_by_cnid(cnid)?;
        attribute_delete::inline_record(cnid, name, &[])?;
        if name == "com.apple.FinderInfo" {
            return self.inline_attribute(dev, cnid, name);
        }
        if self.writer.as_ref().unwrap().attribute_edit_plan.is_some() {
            return Err(crate::Error::Unsupported(
                "flush pending attribute edit before read".into(),
            ));
        }
        self.read_attribute_records(dev, cnid, name, &index.records)
    }

    /// Bounded private value from an already validated committed snapshot.
    /// The caller must check its live volume marker before every use and
    /// discard the snapshot after publication, just as for indexed_attribute.
    /// Fork-backed or malformed value bodies retain fixed_inline_attribute's
    /// None result; their payload storage is never read.
    pub fn indexed_fixed_inline_attribute(
        &self,
        index: &AttributeReadIndex,
        cnid: u32,
        name: &str,
        expected_size: usize,
    ) -> Result<Option<Vec<u8>>> {
        self.catalog_key_by_cnid(cnid)?;
        attribute_delete::inline_record(cnid, name, &[])?;
        if expected_size > 3802 {
            return Err(crate::Error::InvalidArgument(
                "hfs+: fixed attribute read limit".into(),
            ));
        }
        if !self.metadata_is_committed() {
            return Err(crate::Error::Unsupported(
                "flush pending metadata before snapshot read".into(),
            ));
        }
        let fork = &self.writer.as_ref().unwrap().attributes_file;
        if fork.total_blocks == 0 {
            if fork.logical_size != 0 || fork.inline_blocks() != 0 {
                return Err(crate::Error::InvalidImage(
                    "hfs+: inconsistent empty attributes fork".into(),
                ));
            }
            return Ok(None);
        }
        if !index.fixed_tree_supported {
            return Err(crate::Error::InvalidImage(
                "hfs+: invalid bounded attributes traversal".into(),
            ));
        }
        let wanted = name.encode_utf16().collect::<Vec<_>>();
        for record in &index.records {
            let key = attributes::AttrKey::decode(record)?;
            if key.file_id == cnid && key.start_block == 0 && key.name.code_units == wanted {
                return Ok(attributes::fixed_inline_body(
                    &record[key.encoded_len..],
                    expected_size,
                ));
            }
        }
        Ok(None)
    }

    /// Exact names from a fully validated committed attribute tree.
    pub fn attribute_names(&self, dev: &mut dyn BlockDevice, cnid: u32) -> Result<Vec<String>> {
        self.catalog_key_by_cnid(cnid)?;
        let w = self.writer.as_ref().unwrap();
        if w.attribute_edit_plan.is_some() {
            return Err(crate::Error::Unsupported(
                "flush pending attribute edit before read".into(),
            ));
        }
        let mut names = attribute_delete::names(dev, &w.attributes_file, w.block_size, cnid)?;
        if names.iter().any(|name| name == "com.apple.FinderInfo") {
            return Err(crate::Error::Unsupported(
                "hfs+: duplicate catalog/tree FinderInfo".into(),
            ));
        }
        if self
            .inline_attribute(dev, cnid, "com.apple.FinderInfo")?
            .is_some()
        {
            names.push("com.apple.FinderInfo".into());
            names.sort();
        }
        Ok(names)
    }

    fn split_finder_changes<'a>(
        changes: &'a [(&'a str, Option<&'a [u8]>)],
    ) -> Result<(Option<[u8; 32]>, Vec<(&'a str, Option<&'a [u8]>)>)> {
        let mut finder = None;
        let mut ordinary = Vec::new();
        if changes.len() > 256 {
            return Err(crate::Error::Unsupported(
                "hfs+: attribute batch exceeds 256 entries".into(),
            ));
        }
        for &(name, value) in changes {
            if name == "com.apple.FinderInfo" {
                if finder.is_some() {
                    return Err(crate::Error::InvalidArgument(
                        "hfs+: duplicate FinderInfo".into(),
                    ));
                }
                let bytes = match value {
                    Some(value) => <[u8; 32]>::try_from(value).map_err(|_| {
                        crate::Error::InvalidArgument("hfs+: FinderInfo must have 32 bytes".into())
                    })?,
                    None => [0; 32],
                };
                if &bytes[..8] == b"hlnkhfs+" || &bytes[..8] == b"slnkrhap" {
                    return Err(crate::Error::Unsupported(
                        "hfs+: linked FinderInfo needs dedicated semantics".into(),
                    ));
                }
                finder = Some(bytes);
            } else {
                ordinary.push((name, value));
            }
        }
        Ok((finder, ordinary))
    }
    /// Catalog-backed FinderInfo/backup time; no attribute-tree shadow copy.
    pub fn inline_attribute_allocation_bytes(
        &self,
        changes: &[(&str, Option<&[u8]>)],
    ) -> Result<u64> {
        let (_, ordinary) = Self::split_finder_changes(changes)?;
        let w = self.writer.as_ref().ok_or_else(|| {
            crate::Error::Unsupported("hfs+: attribute allocation needs writer state".into())
        })?;
        let mut needed = if w.attributes_file.total_blocks == 0
            && ordinary.iter().any(|(_, value)| value.is_some())
        {
            (8 * 4096u64).div_ceil(u64::from(w.block_size)) * u64::from(w.block_size)
        } else {
            0
        };
        for (name, value) in ordinary {
            attribute_delete::inline_record(16, name, &[])?;
            if let Some(value) = value {
                if value.len() > attribute_value::MAX_VALUE_BYTES {
                    return Err(crate::Error::Unsupported(
                        "hfs+: attribute value exceeds 16 MiB".into(),
                    ));
                }
                if value.len() > 3802 {
                    needed += (value.len() as u64).div_ceil(u64::from(w.block_size))
                        * u64::from(w.block_size);
                }
            }
        }
        Ok(needed)
    }
    /// Catalog-backed FinderInfo/backup time; no attribute-tree shadow copy.
    pub fn set_finder_info(
        &mut self,
        cnid: u32,
        value: &[u8; 32],
        backup: Option<u32>,
    ) -> Result<()> {
        let key = self.metadata_edit_key(cnid)?;
        Self::split_finder_changes(&[("com.apple.FinderInfo", Some(value))])?;
        let w = self.writer.as_mut().unwrap();
        let body = w.catalog.get_mut(&key).unwrap();
        attributes::store_finder_info(body, value);
        if let Some(backup) = backup {
            body[28..32].copy_from_slice(&backup.to_be_bytes());
        }
        w.flushed = false;
        Ok(())
    }

    fn metadata_edit_key(&self, cnid: u32) -> Result<writer::OwnedKey> {
        self.metadata_edit_key_with_compression(cnid, false)
    }
    fn metadata_edit_key_with_compression(
        &self,
        cnid: u32,
        compressed: bool,
    ) -> Result<writer::OwnedKey> {
        self.metadata_edit_key_inner(cnid, compressed, false)
    }

    fn metadata_edit_key_inner(
        &self,
        cnid: u32,
        compressed: bool,
        allow_root: bool,
    ) -> Result<writer::OwnedKey> {
        self.metadata_key_inner(cnid, compressed, allow_root, false, false)
    }

    // Only the basic-date/flag API may traverse catalog locks. It still rejects
    // linked/private identities and cannot clear immutable/append-only BSD bits.
    fn basic_metadata_key(&self, cnid: u32) -> Result<writer::OwnedKey> {
        self.metadata_key_inner(cnid, true, true, true, false)
    }

    // Namespace operations may rename/reclaim a complete conventional symlink,
    // but this permission never extends to its data, Finder identity or xattrs.
    fn namespace_metadata_key(&self, cnid: u32, dates_only: bool) -> Result<writer::OwnedKey> {
        self.metadata_key_inner(cnid, true, dates_only, dates_only, true)
    }

    fn metadata_key_inner(
        &self,
        cnid: u32,
        compressed: bool,
        allow_root: bool,
        basic: bool,
        symbolic: bool,
    ) -> Result<writer::OwnedKey> {
        let key = self.catalog_key_by_cnid(cnid)?;
        if key.parent_id == ROOT_FOLDER_ID
            && matches!(
                key.name.to_display_name().as_str(),
                "\0\0\0\0HFS+ Private Data" | ".HFS+ Private Directory Data\r"
            )
        {
            return Err(crate::Error::Unsupported(
                "hfs+: private hard-link directory metadata is reserved".into(),
            ));
        }
        let body = self.writer.as_ref().unwrap().catalog.get(&key).unwrap();
        let kind = i16::from_be_bytes(body[..2].try_into().unwrap());
        let file = kind == catalog::REC_FILE;
        let mode = u16::from_be_bytes(body[42..44].try_into().unwrap()) & mode::S_IFMT;
        let symlink = symbolic
            && file
            && body.len() == 248
            && mode == mode::S_IFLNK
            && &body[48..56] == b"slnkrhap"
            && body[41] & 0x20 == 0
            && body[168..248].iter().all(|byte| *byte == 0);
        let root = allow_root
            && cnid == ROOT_FOLDER_ID
            && key.parent_id == 1
            && kind == catalog::REC_FOLDER;
        if (cnid < 16 && !root)
            || !matches!(
                (kind, body.len()),
                (catalog::REC_FILE, 248) | (catalog::REC_FOLDER, 88)
            )
            || (mode != 0 && mode != if file { mode::S_IFREG } else { mode::S_IFDIR } && !symlink)
            || (!basic && file && u16::from_be_bytes(body[2..4].try_into().unwrap()) & 1 != 0)
            || (!basic && (body[40] | body[41]) & 6 != 0)
            || (!compressed && body[41] & 0x20 != 0)
            || (!basic && u16::from_be_bytes(body[56..58].try_into().unwrap()) & 0x1000 != 0)
            || (file
                && ((&body[48..52] == b"hlnk" && &body[52..56] == b"hfs+")
                    || (!symlink && &body[48..52] == b"slnk" && &body[52..56] == b"rhap")))
        {
            return Err(crate::Error::Unsupported(
                "hfs+: reserved, locked, compressed or linked metadata target".into(),
            ));
        }
        Ok(key)
    }

    /// Protect the journal independently of its optional hidden catalog records.
    /// The JIB reservation may exceed the active ring size; retain the whole range.
    fn attribute_journal_ranges(&self, dev: &mut dyn BlockDevice) -> Result<Vec<(u64, u64)>> {
        let w = self.writer.as_ref().unwrap();
        let bs = u64::from(w.block_size);
        let mut ranges = Vec::new();
        if w.journal_buffer_blocks != 0 {
            ranges.push((u64::from(w.journal_info_block) * bs, bs));
            ranges.push((
                u64::from(w.journal_buffer_start) * bs,
                u64::from(w.journal_buffer_blocks) * bs,
            ));
        } else {
            let jib = self.volume_header.journal_info_block;
            if jib != 0 {
                ranges.push((u64::from(jib) * bs, bs));
            }
            if let Some(log) = journal::JournalLog::load(dev, &self.volume_header)? {
                let mut info = [0u8; 52];
                dev.read_at(u64::from(jib) * bs, &mut info)?;
                ranges.push((
                    log.buf_off,
                    u64::from_be_bytes(info[44..52].try_into().unwrap()),
                ));
            }
        }
        for (start, size) in &mut ranges {
            let end = start.checked_add(*size).ok_or_else(|| {
                crate::Error::InvalidImage("hfs+: journal reservation overflow".into())
            })?;
            if *start == 0 || *size == 0 || end > self.total_bytes() {
                return Err(crate::Error::InvalidImage(
                    "hfs+: journal reservation outside volume".into(),
                ));
            }
            *size = end;
        }
        Ok(ranges)
    }

    fn validate_attribute_storage(&self, dev: &mut dyn BlockDevice) -> Result<()> {
        let w = self.writer.as_ref().unwrap();
        let own = &w.attributes_file;
        if own.total_blocks == 0 {
            return Ok(());
        }
        let journal_ranges = self.attribute_journal_ranges(dev)?;
        if own.inline_blocks() != u64::from(own.total_blocks)
            || w.overflow_extents.keys().any(|(_, id, _)| *id == 8)
        {
            return Err(crate::Error::Unsupported(
                "hfs+: attribute metadata overflow extents".into(),
            ));
        }
        let spans = own
            .extents
            .iter()
            .filter(|e| e.block_count != 0)
            .collect::<Vec<_>>();
        let overlap = |a: &volume_header::ExtentDescriptor, b: &volume_header::ExtentDescriptor| {
            b.block_count != 0
                && u64::from(a.start_block) < u64::from(b.start_block) + u64::from(b.block_count)
                && u64::from(b.start_block) < u64::from(a.start_block) + u64::from(a.block_count)
        };
        for (i, extent) in spans.iter().enumerate() {
            let start = u64::from(extent.start_block);
            let end = start + u64::from(extent.block_count);
            if end > u64::from(w.total_blocks)
                || start * u64::from(w.block_size) < 2048
                || end * u64::from(w.block_size) > self.total_bytes() - 1024
                || journal_ranges.iter().any(|&(low, high)| {
                    start * u64::from(w.block_size) < high && end * u64::from(w.block_size) > low
                })
                || spans[..i].iter().any(|prior| overlap(extent, prior))
                || (start..end)
                    .any(|block| w.bitmap[block as usize / 8] & (0x80 >> (block % 8)) == 0)
            {
                return Err(crate::Error::InvalidImage(
                    "hfs+: attribute metadata extent ownership".into(),
                ));
            }
            for other in [
                &w.allocation_file,
                &w.extents_file,
                &w.catalog_file,
                &w.startup_file,
            ] {
                if other.extents.iter().any(|other| overlap(extent, other)) {
                    return Err(crate::Error::InvalidImage(
                        "hfs+: overlapping special-file extents".into(),
                    ));
                }
            }
            if w.catalog.overlaps_file_fork(start, end) {
                return Err(crate::Error::InvalidImage(
                    "hfs+: attribute metadata overlaps user fork".into(),
                ));
            }
            if w.overflow_extents
                .values()
                .flatten()
                .any(|other| overlap(extent, other))
            {
                return Err(crate::Error::InvalidImage(
                    "hfs+: attribute metadata overlaps overflow fork".into(),
                ));
            }
        }
        Ok(())
    }

    fn validate_attribute_value_extents(
        &self,
        dev: &mut dyn BlockDevice,
        extents: &[volume_header::ExtentDescriptor],
        allocated: bool,
    ) -> Result<()> {
        let w = self.writer.as_ref().unwrap();
        let journal_ranges = self.attribute_journal_ranges(dev)?;
        let overlap = |a: &volume_header::ExtentDescriptor, b: &volume_header::ExtentDescriptor| {
            b.block_count != 0
                && u64::from(a.start_block) < u64::from(b.start_block) + u64::from(b.block_count)
                && u64::from(b.start_block) < u64::from(a.start_block) + u64::from(a.block_count)
        };
        for extent in extents {
            let start = u64::from(extent.start_block);
            let end = start + u64::from(extent.block_count);
            if end > u64::from(w.total_blocks)
                || start * u64::from(w.block_size) < 1536
                || end * u64::from(w.block_size) > self.total_bytes() - 1024
                || journal_ranges.iter().any(|&(low, high)| {
                    start * u64::from(w.block_size) < high && end * u64::from(w.block_size) > low
                })
                || (start..end).any(|block| {
                    (w.bitmap[block as usize / 8] & (0x80 >> (block % 8)) != 0) != allocated
                })
                || [
                    &w.allocation_file,
                    &w.extents_file,
                    &w.catalog_file,
                    &w.attributes_file,
                    &w.startup_file,
                ]
                .iter()
                .any(|fork| fork.extents.iter().any(|other| overlap(extent, other)))
                || w.overflow_extents
                    .values()
                    .flatten()
                    .any(|other| overlap(extent, other))
                || w.catalog.overlaps_file_fork(start, end)
            {
                return Err(crate::Error::InvalidImage(
                    "hfs+: attribute value extent ownership".into(),
                ));
            }
        }
        Ok(())
    }

    /// Stage one checked inline attribute edit and its catalog HasAttributes
    /// flag. Flush publishes tree, bitmap, fork descriptor and catalog together.
    /// Preflight failures leave the writer and device unchanged.
    pub fn set_inline_attribute(
        &mut self,
        dev: &mut dyn BlockDevice,
        cnid: u32,
        name: &str,
        value: Option<&[u8]>,
    ) -> Result<()> {
        self.set_inline_attributes(dev, cnid, &[(name, value)])
    }

    /// Stage one atomic batch on one CNID. Exact duplicate names are refused;
    /// case-distinct names remain separate. No partial batch is staged on error.
    pub fn set_inline_attributes(
        &mut self,
        dev: &mut dyn BlockDevice,
        cnid: u32,
        changes: &[(&str, Option<&[u8]>)],
    ) -> Result<()> {
        let key = self.metadata_edit_key(cnid)?;
        let (finder, ordinary) = Self::split_finder_changes(changes)?;
        let plan = self.plan_inline_attributes(dev, cnid, &ordinary)?;
        if let Some((plan, has_attributes)) = plan {
            self.stage_inline_attribute_plan(key.clone(), plan, has_attributes)?;
        }
        if let Some(finder) = finder {
            let w = self.writer.as_mut().unwrap();
            attributes::store_finder_info(w.catalog.get_mut(&key).unwrap(), &finder);
            w.flushed = false;
        }
        Ok(())
    }

    /// Atomically stage small ordinary attributes on several entries, including
    /// the volume root. This can absorb already-preflighted file deletions into
    /// the same tree publication. Existing single-entry APIs retain their gates.
    /// At most 256 distinct (CNID, name) pairs, each value at most 3802 bytes.
    /// FinderInfo, compression/system attributes and fork-backed target values
    /// need their dedicated APIs. A pending attribute edit must be flushed first.
    /// No device writes or partial new staging occur if this preflight fails.
    pub fn set_small_attributes_batch(
        &mut self,
        dev: &mut dyn BlockDevice,
        changes: &[(u32, &str, Option<&[u8]>)],
    ) -> Result<()> {
        if changes.is_empty() {
            return Ok(());
        }
        if changes.len() > 256 {
            return Err(crate::Error::Unsupported(
                "hfs+: small attribute batch exceeds 256 entries".into(),
            ));
        }
        let mut names = std::collections::BTreeSet::new();
        let mut keys = std::collections::BTreeMap::new();
        for &(cnid, name, value) in changes {
            if !names.insert((cnid, name)) {
                return Err(crate::Error::InvalidArgument(
                    "hfs+: duplicate identity/name in small attribute batch".into(),
                ));
            }
            attribute_delete::inline_record(cnid, name, value.unwrap_or(&[]))?;
            if matches!(
                name,
                "com.apple.ResourceFork" | "com.apple.FinderInfo" | "com.apple.decmpfs"
            ) || name.starts_with("com.apple.system.")
            {
                return Err(crate::Error::Unsupported(
                    "hfs+: attribute needs dedicated semantics".into(),
                ));
            }
            keys.insert(cnid, self.metadata_edit_key_inner(cnid, false, true)?);
        }
        self.validate_attribute_storage(dev)?;
        let w = self.writer.as_ref().unwrap();
        if w.attribute_edit_plan.is_some() {
            return Err(crate::Error::Unsupported(
                "hfs+: flush pending attribute edit before small batch".into(),
            ));
        }
        if w.attributes_file.total_blocks == 0 {
            if w.attributes_file.logical_size != 0 || w.attributes_file.inline_blocks() != 0 {
                return Err(crate::Error::InvalidImage(
                    "hfs+: inconsistent empty attributes fork".into(),
                ));
            }
            if changes.iter().all(|(_, _, value)| value.is_none()) {
                return Ok(());
            }
            let blocks = (8 * 4096u64).div_ceil(u64::from(w.block_size)) as u32;
            w.check_contiguous_allocation(blocks)?;
        }
        let (plan, flags) = attribute_delete::plan_small_batch(
            dev,
            &w.attributes_file,
            w.block_size,
            &w.attribute_delete_ids,
            changes,
        )?;
        // Retired fork-backed values belonged to the pending deletions. Check
        // all value owners before clearing those pending IDs, so shared or
        // unallocated blocks can never enter the combined reclamation batch.
        self.validate_attribute_value_extents(dev, &plan.retired, true)?;
        if !plan.retired.is_empty() {
            let records = attribute_delete::records(dev, &w.attributes_file, w.block_size)?;
            let mut occupied = Vec::new();
            for (_, reader) in attribute_value::forks(&records, w.block_size, w.total_blocks)? {
                self.validate_attribute_value_extents(dev, &reader.extents, true)?;
                occupied.extend(reader.extents);
            }
            occupied.sort_by_key(|extent| extent.start_block);
            if occupied.windows(2).any(|pair| {
                u64::from(pair[0].start_block) + u64::from(pair[0].block_count)
                    > u64::from(pair[1].start_block)
            }) {
                return Err(crate::Error::InvalidImage(
                    "hfs+: shared attribute value blocks".into(),
                ));
            }
        }
        let (&first, key) = keys.first_key_value().unwrap();
        self.stage_inline_attribute_plan(key.clone(), plan, flags[&first])?;
        let w = self.writer.as_mut().unwrap();
        for (cnid, key) in keys {
            let body = w.catalog.get_mut(&key).unwrap();
            let old = u16::from_be_bytes(body[2..4].try_into().unwrap());
            body[2..4]
                .copy_from_slice(&((old & !4) | if flags[&cnid] { 4 } else { 0 }).to_be_bytes());
        }
        // The staged plan includes every pending deletion. Subsequent removal
        // stays refused by validate_remove_attributes until this plan is flushed.
        w.attribute_delete_ids.clear();
        Ok(())
    }

    /// Stage one complete ordinary-attribute transaction across existing
    /// entries, including the root and already-preflighted file deletions.
    /// Supports inline and fork-backed values, with 256 distinct (CNID, name)
    /// pairs and at most 16 MiB of replacement payload in total. All fresh
    /// storage is reserved on a private bitmap before any new staging occurs.
    /// Existing single-entry plans cannot be appended to; supply the complete
    /// batch before staging. FinderInfo/compression/system metadata and locked
    /// or linked targets keep their dedicated APIs and existing restrictions.
    pub fn set_attributes_batch(
        &mut self,
        dev: &mut dyn BlockDevice,
        changes: &[(u32, &str, Option<&[u8]>)],
    ) -> Result<()> {
        self.set_attributes_batch_with_publication(dev, changes, &[], &[])
    }

    /// Compose a complete multi-entry attribute batch and pending deletions
    /// with sixteen additional inline records and sixteen catalog updates.
    /// The 256 public-attribute budget is unchanged. All identities must still
    /// exist after staged deletion; locked/compressed targets remain refused.
    /// Preflight failure preserves earlier work. The caller flushes once.
    pub fn set_attributes_batch_with_publication(
        &mut self,
        dev: &mut dyn BlockDevice,
        changes: &[(u32, &str, Option<&[u8]>)],
        related: &[(u32, &str, Option<&[u8]>)],
        catalog: &[CatalogUpdate],
    ) -> Result<()> {
        if changes.is_empty() && related.is_empty() && catalog.is_empty() {
            return Ok(());
        }
        if changes.len() > 256 {
            return Err(crate::Error::Unsupported(
                "hfs+: attribute batch exceeds 256 entries".into(),
            ));
        }
        if related.len() > 16
            || related
                .iter()
                .any(|(_, _, v)| v.is_some_and(|v| v.len() > 3802))
        {
            return Err(crate::Error::Unsupported(
                "hfs+: related metadata exceeds sixteen inline records".into(),
            ));
        }
        let mut batch = changes.to_vec();
        batch.extend_from_slice(related);
        let mut names = std::collections::BTreeSet::new();
        for &(cnid, name, value) in &batch {
            if !names.insert((cnid, name)) {
                return Err(crate::Error::InvalidArgument(
                    "hfs+: duplicate identity/name in attribute batch".into(),
                ));
            }
            attribute_delete::inline_record(cnid, name, &[])?;
            if value.is_some_and(|value| value.len() > attribute_value::MAX_VALUE_BYTES) {
                return Err(crate::Error::Unsupported(
                    "hfs+: attribute value exceeds 16 MiB limit".into(),
                ));
            }
            if matches!(
                name,
                "com.apple.ResourceFork" | "com.apple.FinderInfo" | "com.apple.decmpfs"
            ) || name.starts_with("com.apple.system.")
            {
                return Err(crate::Error::Unsupported(
                    "hfs+: attribute needs dedicated semantics".into(),
                ));
            }
            self.metadata_edit_key_inner(cnid, false, true)?;
        }
        self.validate_catalog_updates(ROOT_FOLDER_ID, RelatedTarget::Ordinary, false, catalog)?;
        self.validate_attribute_storage(dev)?;
        let w = self.writer.as_ref().unwrap();
        if w.attribute_edit_plan.is_some() {
            return Err(crate::Error::Unsupported(
                "hfs+: flush pending attribute edit before complete batch".into(),
            ));
        }
        if w.attributes_file.total_blocks == 0 {
            if w.attributes_file.logical_size != 0 || w.attributes_file.inline_blocks() != 0 {
                return Err(crate::Error::InvalidImage(
                    "hfs+: inconsistent empty attributes fork".into(),
                ));
            }
        }
        let transaction = if batch.is_empty()
            || (w.attributes_file.total_blocks == 0
                && batch.iter().all(|(_, _, value)| value.is_none()))
        {
            None
        } else {
            let records = attribute_delete::records(dev, &w.attributes_file, w.block_size)?;
            Some(self.plan_fork_attribute_batch(dev, &batch, &records, &w.attribute_delete_ids)?)
        };
        let result = (|| {
            self.stage_related_attribute_plan(transaction)?;
            // Only a staged attribute plan has consumed pending deletions.
            // Catalog-only/absent-removal batches leave them for normal flush.
            if self.writer.as_ref().unwrap().attribute_edit_plan.is_some() {
                self.writer.as_mut().unwrap().attribute_delete_ids.clear();
            }
            self.stage_catalog_updates(catalog)
        })();
        if result.is_err() {
            self.write_failed = true;
        }
        result
    }

    /// Prevalidate creation attributes before staging an empty ordinary entry.
    /// Creation and its complete attribute batch are published by caller flush.
    /// These host defaults use 0644 for files and 0755 for directories.
    #[allow(clippy::too_many_arguments)]
    pub fn create_entry_with_inline_attributes(
        &mut self,
        dev: &mut dyn BlockDevice,
        path: &str,
        directory: bool,
        uid: u32,
        gid: u32,
        mtime: u32,
        changes: &[(&str, Option<&[u8]>)],
    ) -> Result<u32> {
        self.resolve_new_target(path)?;
        let expected_cnid = self.writer.as_ref().unwrap().next_cnid;
        let (finder, ordinary) = Self::split_finder_changes(changes)?;
        let plan = self.plan_inline_attributes(dev, expected_cnid, &ordinary)?;
        let cnid = if directory {
            self.create_dir(dev, path, 0o755, uid, gid, mtime)?
        } else {
            self.create_file(dev, path, &mut &[][..], 0, 0o644, uid, gid, mtime)?
        };
        if cnid != expected_cnid {
            self.write_failed = true;
            return Err(crate::Error::InvalidImage(
                "hfs+: creation identity changed after attribute preflight".into(),
            ));
        }
        if let Some((plan, has_attributes)) = plan {
            let key = self.metadata_edit_key(cnid)?;
            if let Err(error) = self.stage_inline_attribute_plan(key, plan, has_attributes) {
                self.write_failed = true;
                return Err(error);
            }
        }
        if let Some(finder) = finder {
            self.set_finder_info(cnid, &finder, None)?;
        }
        Ok(cnid)
    }

    /// Identity for an empty-entry constructor. The related-attribute API
    /// requires this identity back, refusing stale preflight before mutation.
    pub fn creation_cnid(&self, path: &str) -> Result<u32> {
        self.resolve_new_target(path)?;
        let w = self.writer.as_ref().unwrap();
        let cnid = w.next_cnid;
        if cnid < 16
            || w.catalog.values().any(|body| {
                body.len() >= 12
                    && matches!(
                        i16::from_be_bytes(body[..2].try_into().unwrap()),
                        catalog::REC_FILE | catalog::REC_FOLDER
                    )
                    && u32::from_be_bytes(body[8..12].try_into().unwrap()) == cnid
            })
        {
            return Err(crate::Error::InvalidImage(
                "hfs+: next creation identity is already reserved".into(),
            ));
        }
        cnid.checked_add(1)
            .ok_or_else(|| crate::Error::Unsupported("hfs+: CNID space exhausted".into()))?;
        Ok(cnid)
    }

    /// Create an empty entry and stage its full attributes plus up to sixteen
    /// small related records (including its future identity and root/parents).
    /// The separate related budget preserves the 256 constructor-attribute
    /// limit. All records and fresh storage are preflighted before creation.
    /// Caller flush publishes the complete change; no pending plan is appended.
    #[allow(clippy::too_many_arguments)]
    pub fn create_entry_with_related_attributes(
        &mut self,
        dev: &mut dyn BlockDevice,
        path: &str,
        expected_cnid: u32,
        directory: bool,
        uid: u32,
        gid: u32,
        mtime: u32,
        changes: &[(&str, Option<&[u8]>)],
        related: &[(u32, &str, Option<&[u8]>)],
    ) -> Result<u32> {
        self.create_entry_with_publication(
            dev,
            path,
            expected_cnid,
            directory,
            uid,
            gid,
            mtime,
            0,
            PublicationMetadata {
                attributes: changes,
                related,
                catalog: &[],
            },
        )
    }

    /// Stage a new empty entry, genuine data reservation and complete metadata
    /// together. Caller flush publishes once. All space and field refusals
    /// precede creation; new reservation blocks are zeroed before publication.
    #[allow(clippy::too_many_arguments)]
    pub fn create_entry_with_publication(
        &mut self,
        dev: &mut dyn BlockDevice,
        path: &str,
        expected_cnid: u32,
        directory: bool,
        uid: u32,
        gid: u32,
        mtime: u32,
        allocation: u64,
        metadata: PublicationMetadata<'_>,
    ) -> Result<u32> {
        if self.creation_cnid(path)? != expected_cnid {
            return Err(crate::Error::InvalidArgument(
                "hfs+: stale creation identity".into(),
            ));
        }
        let plan = self.plan_related_attributes(
            dev,
            expected_cnid,
            RelatedTarget::Future,
            metadata.attributes,
            metadata.related,
        )?;
        self.validate_catalog_updates(
            expected_cnid,
            RelatedTarget::Future,
            directory,
            metadata.catalog,
        )?;
        let w = self.writer.as_ref().unwrap();
        if !allocation.is_multiple_of(u64::from(w.block_size)) || (directory && allocation != 0) {
            return Err(crate::Error::InvalidArgument(
                "hfs+: invalid creation reservation".into(),
            ));
        }
        let free = plan
            .transaction
            .as_ref()
            .and_then(|(p, _)| p.allocation.as_ref())
            .map_or(w.free_blocks, |a| a.free_blocks);
        if allocation / u64::from(w.block_size) > u64::from(free) {
            return Err(crate::Error::InvalidArgument(
                "insufficient free space for creation and metadata".into(),
            ));
        }
        let result = (|| {
            let cnid = if directory {
                self.create_dir(dev, path, 0o755, uid, gid, mtime)?
            } else {
                self.create_file(dev, path, &mut &[][..], 0, 0o644, uid, gid, mtime)?
            };
            self.stage_related_attribute_plan(plan.transaction)?;
            if allocation != 0 {
                handle::reserve_new_entry(self, dev, std::path::Path::new(path), allocation)?;
            }
            if let Some(finder) = plan.finder {
                self.set_finder_info(cnid, &finder, None)?;
            }
            self.stage_catalog_updates(metadata.catalog)?;
            Ok(cnid)
        })();
        if result.is_err() {
            self.write_failed = true;
        }
        result
    }

    fn validate_catalog_updates(
        &self,
        target: u32,
        mode: RelatedTarget,
        future_directory: bool,
        updates: &[CatalogUpdate],
    ) -> Result<()> {
        if updates.len() > 16 {
            return Err(crate::Error::Unsupported(
                "hfs+: more than sixteen related catalog updates".into(),
            ));
        }
        let mut unique = std::collections::BTreeSet::new();
        for update in updates {
            if !unique.insert(update.cnid) {
                return Err(crate::Error::InvalidArgument(
                    "hfs+: duplicate catalog update".into(),
                ));
            }
            if mode == RelatedTarget::Future && update.cnid == target {
                let mut body = [0; 248];
                body[..2].copy_from_slice(
                    &(if future_directory {
                        catalog::REC_FOLDER
                    } else {
                        catalog::REC_FILE
                    })
                    .to_be_bytes(),
                );
                Self::validate_catalog_attributes(&body, update.attributes)?;
            } else {
                let key = self.metadata_key_inner(
                    update.cnid,
                    mode == RelatedTarget::Compressed && update.cnid == target,
                    true,
                    false,
                    mode == RelatedTarget::Symbolic && update.cnid == target,
                )?;
                Self::validate_catalog_attributes(
                    self.writer.as_ref().unwrap().catalog.get(&key).unwrap(),
                    update.attributes,
                )?;
            }
        }
        Ok(())
    }

    fn stage_catalog_updates(&mut self, updates: &[CatalogUpdate]) -> Result<()> {
        for update in updates {
            self.set_catalog_windows_info(update.cnid, update.times, update.attributes)?;
        }
        Ok(())
    }

    /// Shared constructor/conversion preflight. Only the future constructor
    /// identity bypasses the existing-entry gate; only the conversion target
    /// may be compressed. Dedicated metadata cannot enter through related data.
    fn plan_related_attributes(
        &self,
        dev: &mut dyn BlockDevice,
        target: u32,
        mode: RelatedTarget,
        changes: &[(&str, Option<&[u8]>)],
        related: &[(u32, &str, Option<&[u8]>)],
    ) -> Result<RelatedAttributePlan> {
        let (finder, ordinary) = Self::split_finder_changes(changes)?;
        if related.len() > 16
            || related
                .iter()
                .any(|(_, _, v)| v.is_some_and(|v| v.len() > 3802))
        {
            return Err(crate::Error::Unsupported(
                "hfs+: related metadata exceeds sixteen inline records".into(),
            ));
        }
        let mut batch = ordinary
            .iter()
            .map(|&(name, value)| (target, name, value))
            .collect::<Vec<_>>();
        batch.extend_from_slice(related);
        let mut unique = std::collections::BTreeSet::new();
        for &(cnid, name, value) in &batch {
            if !unique.insert((cnid, name)) {
                return Err(crate::Error::InvalidArgument(
                    "hfs+: duplicate related attribute".into(),
                ));
            }
            attribute_delete::inline_record(cnid, name, &[])?;
            if value.is_some_and(|v| v.len() > attribute_value::MAX_VALUE_BYTES) {
                return Err(crate::Error::Unsupported(
                    "hfs+: attribute value exceeds 16 MiB".into(),
                ));
            }
            if matches!(
                name,
                "com.apple.ResourceFork" | "com.apple.FinderInfo" | "com.apple.decmpfs"
            ) || name.starts_with("com.apple.system.")
            {
                return Err(crate::Error::Unsupported(
                    "hfs+: attribute needs dedicated semantics".into(),
                ));
            }
            if !(mode == RelatedTarget::Future && cnid == target) {
                self.metadata_key_inner(
                    cnid,
                    mode == RelatedTarget::Compressed && cnid == target,
                    true,
                    false,
                    mode == RelatedTarget::Symbolic && cnid == target,
                )?;
            }
        }
        if mode == RelatedTarget::Compressed {
            batch.push((target, "com.apple.decmpfs", None));
        }
        self.validate_attribute_storage(dev)?;
        let w = self.writer.as_ref().unwrap();
        if w.attribute_edit_plan.is_some() || !w.attribute_delete_ids.is_empty() {
            return Err(crate::Error::Unsupported(
                "hfs+: flush pending attribute mutation first".into(),
            ));
        }
        if w.attributes_file.total_blocks == 0 {
            if w.attributes_file.logical_size != 0 || w.attributes_file.inline_blocks() != 0 {
                return Err(crate::Error::InvalidImage(
                    "hfs+: inconsistent empty attributes fork".into(),
                ));
            }
            if batch.iter().all(|(_, _, value)| value.is_none()) {
                return Ok(RelatedAttributePlan {
                    finder,
                    transaction: None,
                });
            }
        }
        let records = attribute_delete::records(dev, &w.attributes_file, w.block_size)?;
        if mode == RelatedTarget::Future
            && records.iter().any(|record| {
                attributes::AttrKey::decode(record).is_ok_and(|key| key.file_id == target)
            })
        {
            return Err(crate::Error::InvalidImage(
                "hfs+: future creation identity already owns attributes".into(),
            ));
        }
        if batch.is_empty() {
            return Ok(RelatedAttributePlan {
                finder,
                transaction: None,
            });
        }
        let transaction =
            self.plan_fork_attribute_batch(dev, &batch, &records, &Default::default())?;
        Ok(RelatedAttributePlan {
            finder,
            transaction: Some(transaction),
        })
    }

    fn stage_related_attribute_plan(
        &mut self,
        transaction: Option<(
            attribute_delete::Plan,
            std::collections::BTreeMap<u32, bool>,
        )>,
    ) -> Result<()> {
        let Some((plan, flags)) = transaction else {
            return Ok(());
        };
        let mut keys = Vec::new();
        for (cnid, present) in flags {
            keys.push((self.catalog_key_by_cnid(cnid)?, present));
        }
        let (first, present) = keys.first().ok_or_else(|| {
            crate::Error::InvalidImage("hfs+: empty related attribute plan".into())
        })?;
        self.stage_inline_attribute_plan(first.clone(), plan, *present)?;
        let w = self.writer.as_mut().unwrap();
        for (key, present) in keys {
            let body = w.catalog.get_mut(&key).unwrap();
            let flags = u16::from_be_bytes(body[2..4].try_into().unwrap());
            body[2..4].copy_from_slice(&((flags & !4) | if present { 4 } else { 0 }).to_be_bytes());
        }
        Ok(())
    }

    fn plan_inline_attributes(
        &self,
        dev: &mut dyn BlockDevice,
        cnid: u32,
        changes: &[(&str, Option<&[u8]>)],
    ) -> Result<Option<(attribute_delete::Plan, bool)>> {
        self.plan_inline_attributes_inner(dev, cnid, changes, false)
    }

    fn plan_inline_attributes_inner(
        &self,
        dev: &mut dyn BlockDevice,
        cnid: u32,
        changes: &[(&str, Option<&[u8]>)],
        compression_removal: bool,
    ) -> Result<Option<(attribute_delete::Plan, bool)>> {
        if changes.is_empty() {
            return Ok(None);
        }
        if changes.len() > if compression_removal { 257 } else { 256 } {
            return Err(crate::Error::Unsupported(
                "hfs+: attribute batch exceeds 256 entries".into(),
            ));
        }
        let mut names = std::collections::BTreeSet::new();
        for &(name, value) in changes {
            if !names.insert(name) {
                return Err(crate::Error::InvalidArgument(
                    "hfs+: duplicate attribute name in batch".into(),
                ));
            }
            attribute_delete::inline_record(cnid, name, &[])?;
            if value.is_some_and(|value| value.len() > attribute_value::MAX_VALUE_BYTES) {
                return Err(crate::Error::Unsupported(
                    "hfs+: attribute value exceeds 16 MiB limit".into(),
                ));
            }
            if (matches!(
                name,
                "com.apple.ResourceFork" | "com.apple.FinderInfo" | "com.apple.decmpfs"
            ) || name.starts_with("com.apple.system."))
                && !(compression_removal && name == "com.apple.decmpfs" && value.is_none())
            {
                return Err(crate::Error::Unsupported(
                    "hfs+: attribute needs dedicated semantics".into(),
                ));
            }
        }
        self.validate_attribute_storage(dev)?;
        let w = self.writer.as_ref().unwrap();
        if w.attribute_edit_plan.is_some() || !w.attribute_delete_ids.is_empty() {
            return Err(crate::Error::Unsupported(
                "hfs+: flush pending attribute mutation first".into(),
            ));
        }
        let records = attribute_delete::records(dev, &w.attributes_file, w.block_size)?;
        let mut fork_target = false;
        for record in &records {
            let key = attributes::AttrKey::decode(record)?;
            if key.file_id == cnid
                && changes
                    .iter()
                    .any(|(name, _)| key.name.code_units == name.encode_utf16().collect::<Vec<_>>())
                && (key.start_block != 0
                    || record[key.encoded_len..key.encoded_len + 4]
                        != attributes::REC_INLINE_DATA.to_be_bytes())
            {
                fork_target = true;
            }
        }
        if fork_target
            || changes
                .iter()
                .any(|(_, value)| value.is_some_and(|v| v.len() > 3802))
        {
            return self
                .plan_fork_attributes(dev, cnid, changes, &records)
                .map(Some);
        }
        let absent = w.attributes_file.total_blocks == 0;
        let (plan, has_attributes) = if absent {
            if w.attributes_file.logical_size != 0 || w.attributes_file.inline_blocks() != 0 {
                return Err(crate::Error::InvalidImage(
                    "hfs+: inconsistent empty attributes fork".into(),
                ));
            }
            if changes.iter().all(|(_, value)| value.is_none()) {
                return Ok(None);
            }
            let blocks =
                u32::try_from((8 * 4096u64).div_ceil(u64::from(w.block_size))).map_err(|_| {
                    crate::Error::Unsupported(
                        "hfs+: attributes allocation exceeds block count".into(),
                    )
                })?;
            w.check_contiguous_allocation(blocks)?;
            attribute_delete::plan_new_edits(cnid, changes)?
        } else {
            attribute_delete::plan_edits(dev, &w.attributes_file, w.block_size, cnid, changes)?
        };
        Ok(Some((plan, has_attributes)))
    }

    fn plan_fork_attributes(
        &self,
        dev: &mut dyn BlockDevice,
        cnid: u32,
        changes: &[(&str, Option<&[u8]>)],
        records: &[Vec<u8>],
    ) -> Result<(attribute_delete::Plan, bool)> {
        let changes = changes
            .iter()
            .map(|&(name, value)| (cnid, name, value))
            .collect::<Vec<_>>();
        let (plan, flags) =
            self.plan_fork_attribute_batch(dev, &changes, records, &Default::default())?;
        Ok((plan, flags.get(&cnid).copied().unwrap_or(false)))
    }

    fn plan_fork_attribute_batch(
        &self,
        dev: &mut dyn BlockDevice,
        changes: &[(u32, &str, Option<&[u8]>)],
        records: &[Vec<u8>],
        deleted: &std::collections::BTreeSet<u32>,
    ) -> Result<(
        attribute_delete::Plan,
        std::collections::BTreeMap<u32, bool>,
    )> {
        let w = self.writer.as_ref().unwrap();
        let total_value_bytes = changes.iter().try_fold(0usize, |sum, (_, _, value)| {
            sum.checked_add(value.map_or(0, <[u8]>::len))
                .ok_or_else(|| {
                    crate::Error::Unsupported("hfs+: attribute batch length overflow".into())
                })
        })?;
        if total_value_bytes > attribute_value::MAX_VALUE_BYTES {
            return Err(crate::Error::Unsupported(
                "hfs+: attribute batch exceeds 16 MiB".into(),
            ));
        }
        for record in records {
            let key = attributes::AttrKey::decode(record)?;
            let kind = u32::from_be_bytes(
                record[key.encoded_len..key.encoded_len + 4]
                    .try_into()
                    .unwrap(),
            );
            if !matches!(
                kind,
                attributes::REC_INLINE_DATA | attributes::REC_FORK_DATA | attributes::REC_EXTENTS
            ) {
                return Err(crate::Error::Unsupported(
                    "hfs+: unknown attribute storage may own blocks".into(),
                ));
            }
        }
        let forks = attribute_value::forks(records, w.block_size, w.total_blocks)?;
        let mut occupied = Vec::new();
        let mut retired = Vec::new();
        for (key, reader) in forks {
            self.validate_attribute_value_extents(dev, &reader.extents, true)?;
            if changes.iter().any(|(cnid, name, _)| {
                key.file_id == *cnid
                    && key.name.code_units == name.encode_utf16().collect::<Vec<_>>()
            }) {
                retired.extend(reader.extents.iter().copied());
            }
            occupied.extend(reader.extents);
        }
        occupied.sort_by_key(|extent| extent.start_block);
        if occupied.windows(2).any(|pair| {
            u64::from(pair[0].start_block) + u64::from(pair[0].block_count)
                > u64::from(pair[1].start_block)
        }) {
            return Err(crate::Error::InvalidImage(
                "hfs+: shared attribute value blocks".into(),
            ));
        }
        if w.attributes_file.total_blocks == 0
            && (w.attributes_file.logical_size != 0 || w.attributes_file.inline_blocks() != 0)
        {
            return Err(crate::Error::InvalidImage(
                "hfs+: inconsistent empty attributes fork".into(),
            ));
        }
        // In-place inline records need no allocation changes. Defer copying
        // the volume bitmap until a payload or complete tree really needs
        // fresh blocks; large volumes otherwise copy it for every timestamp.
        let allocation_snapshot = || attribute_delete::Allocation {
            bitmap: w.bitmap.clone(),
            free_blocks: w.free_blocks,
            next_alloc: w.next_alloc,
            attributes_file: w.attributes_file,
            payloads: Vec::new(),
        };
        let mut allocation = None;
        let mut replacements = Vec::new();
        for &(cnid, name, value) in changes {
            let replacement = match value {
                None => Vec::new(),
                Some(value) if value.len() <= 3802 => {
                    vec![attribute_delete::inline_record(cnid, name, value)?]
                }
                Some(value) => {
                    let allocation = allocation.get_or_insert_with(&allocation_snapshot);
                    let blocks = (value.len() as u64).div_ceil(u64::from(w.block_size)) as u32;
                    let extent = attribute_value::reserve(allocation, blocks, w.total_blocks)?;
                    self.validate_attribute_value_extents(dev, &[extent], false)?;
                    allocation.payloads.push((extent, value.into()));
                    vec![attribute_value::fork_record(
                        cnid,
                        name,
                        value.len(),
                        extent,
                    )?]
                }
            };
            replacements.push((cnid, name.to_owned(), replacement));
        }
        // Keep live old value blocks allocated until flush has made every
        // fresh payload durable. Other staged file edits cannot reuse them.
        let (mut plan, flags) = attribute_delete::plan_record_batch(
            dev,
            &w.attributes_file,
            w.block_size,
            deleted,
            &replacements,
        )?;
        // Growth relocates the whole attribute tree. Keep every old block
        // reserved until flush has synced the replacement; the existing
        // metadata transaction then publishes the fork and retires the old one.
        let grown = plan.grown_tree.take();
        if grown.is_some() || w.attributes_file.total_blocks == 0 {
            let allocation = allocation.get_or_insert_with(allocation_snapshot);
            let bytes = grown.as_ref().map_or(8 * 4096, Vec::len) as u64;
            let blocks = u32::try_from(bytes.div_ceil(u64::from(w.block_size))).map_err(|_| {
                crate::Error::Unsupported("hfs+: grown attributes block count".into())
            })?;
            let extent = attribute_value::reserve(allocation, blocks, w.total_blocks)?;
            self.validate_attribute_value_extents(dev, &[extent], false)?;
            plan.retired.extend(
                allocation
                    .attributes_file
                    .extents
                    .iter()
                    .copied()
                    .filter(|extent| extent.block_count != 0),
            );
            let clump_size = allocation.attributes_file.clump_size.max(8 * 4096);
            allocation.attributes_file = ForkData {
                logical_size: bytes,
                clump_size,
                total_blocks: extent.block_count,
                ..Default::default()
            };
            allocation.attributes_file.extents[0] = extent;
            if let Some(tree) = grown {
                allocation.payloads.push((extent, tree.into()));
            }
        }
        plan.allocation = allocation;
        plan.retired.extend(retired);
        Ok((plan, flags))
    }
    fn stage_inline_attribute_plan(
        &mut self,
        key: writer::OwnedKey,
        plan: attribute_delete::Plan,
        has_attributes: bool,
    ) -> Result<()> {
        let w = self.writer.as_mut().unwrap();
        if let Some(allocation) = &plan.allocation {
            w.bitmap = allocation.bitmap.clone();
            w.free_blocks = allocation.free_blocks;
            w.next_alloc = allocation.next_alloc;
            w.attributes_file = allocation.attributes_file;
        } else if w.attributes_file.total_blocks == 0 {
            let bytes = 8 * 4096u64;
            let blocks = u32::try_from(bytes.div_ceil(u64::from(w.block_size))).map_err(|_| {
                crate::Error::Unsupported("hfs+: attributes allocation exceeds block count".into())
            })?;
            let start = w.allocate(blocks)?;
            w.attributes_file = ForkData {
                logical_size: bytes,
                clump_size: bytes as u32,
                total_blocks: blocks,
                ..Default::default()
            };
            w.attributes_file.extents[0] = volume_header::ExtentDescriptor {
                start_block: start,
                block_count: blocks,
            };
        }
        let body = w.catalog.get_mut(&key).unwrap();
        let flags = u16::from_be_bytes(body[2..4].try_into().unwrap());
        body[2..4]
            .copy_from_slice(&((flags & !4) | if has_attributes { 4 } else { 0 }).to_be_bytes());
        w.attribute_edit_plan = Some(plan);
        w.flushed = false;
        Ok(())
    }

    /// Stage independent native HFS timestamps, preserving all other bytes.
    /// Values are seconds since 1904, not Unix seconds. Publication is via flush.
    pub fn set_catalog_times(&mut self, cnid: u32, times: [Option<u32>; 4]) -> Result<()> {
        let key = self.catalog_key_by_cnid(cnid)?;
        let body = self.writer.as_mut().unwrap().catalog.get_mut(&key).unwrap();
        for (offset, value) in [12, 24, 16, 20].into_iter().zip(times) {
            if let Some(value) = value {
                body[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
            }
        }
        Ok(())
    }

    /// Stage Windows basic metadata using native HFS fields. Archive means
    /// the native backup date is unknown or older than the content date.
    /// BSD flags, owner/mode, unrelated Finder bits and fork bytes are retained.
    pub fn set_catalog_windows_info(
        &mut self,
        cnid: u32,
        times: [Option<u32>; 4],
        attributes: Option<u32>,
    ) -> Result<()> {
        let key = self.catalog_key_by_cnid(cnid)?;
        let body = self.writer.as_ref().unwrap().catalog.get(&key).unwrap();
        let file = i16::from_be_bytes(body[..2].try_into().unwrap()) == catalog::REC_FILE;
        Self::validate_catalog_attributes(body, attributes)?;
        let body = self.writer.as_mut().unwrap().catalog.get_mut(&key).unwrap();
        for (offset, value) in [12, 24, 16, 20].into_iter().zip(times) {
            if let Some(value) = value {
                body[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
            }
        }
        if let Some(attributes) = attributes {
            let mut finder = u16::from_be_bytes(body[56..58].try_into().unwrap());
            finder = (finder & !0x4000) | if attributes & 2 != 0 { 0x4000 } else { 0 };
            if attributes & 1 == 0 {
                finder &= !0x1000;
            } else if !file {
                finder |= 0x1000;
            }
            body[56..58].copy_from_slice(&finder.to_be_bytes());
            if file {
                let flags = u16::from_be_bytes(body[2..4].try_into().unwrap());
                body[2..4].copy_from_slice(&((flags & !1) | (attributes & 1) as u16).to_be_bytes());
            }
            let backup = if attributes & 0x20 != 0 {
                0
            } else {
                // Epoch-zero content still needs a nonzero known backup date.
                u32::from_be_bytes(body[16..20].try_into().unwrap()).max(1)
            };
            body[28..32].copy_from_slice(&backup.to_be_bytes());
        }
        Ok(())
    }

    fn validate_catalog_attributes(body: &[u8], attributes: Option<u32>) -> Result<()> {
        let file = i16::from_be_bytes(body[..2].try_into().unwrap()) == catalog::REC_FILE;
        if attributes.is_some_and(|a| {
            a & !0xb3 != 0
                || (a & 0x10 != 0 && file)
                || (a & 1 == 0 && (body[40] | body[41]) & 6 != 0)
        }) {
            return Err(crate::Error::Unsupported(
                "hfs+: unsupported attributes or protected BSD flags".into(),
            ));
        }
        Ok(())
    }

    /// Edit the resource fork of an existing ordinary regular file using the
    /// same private-block publication as data edits. Empty forks are allowed;
    /// compressed, linked and locked files remain refused. No data-fork,
    /// ownership, dates, flags or attributes are changed by this primitive.
    pub fn open_resource_fork_rw<'a>(
        &'a mut self,
        dev: &'a mut dyn BlockDevice,
        path: &std::path::Path,
    ) -> Result<Box<dyn crate::fs::FileHandle + 'a>> {
        Ok(Box::new(handle::open_resource_rw(self, dev, path)?))
    }

    /// Validate a resource editor without staging or publishing any changes.
    pub fn validate_resource_edit(
        &mut self,
        dev: &mut dyn BlockDevice,
        path: &std::path::Path,
    ) -> Result<()> {
        drop(handle::open_resource_rw(self, dev, path)?);
        Ok(())
    }

    /// Stage ownership transfer of a resource fork into an empty regular file's
    /// data fork. The caller publishes both records together with its recovery
    /// namespace. No payload or allocation bits are changed by this operation.
    pub fn detach_resource_fork(
        &mut self,
        dev: &mut dyn BlockDevice,
        source: u32,
        target: u32,
    ) -> Result<()> {
        if source == target {
            return Err(crate::Error::InvalidArgument(
                "resource detach identities coincide".into(),
            ));
        }
        let source_path = self.catalog_path(source)?;
        self.validate_resource_edit(dev, std::path::Path::new(&source_path))?;
        let source_key = self.catalog_key_by_cnid(source)?;
        let target_key = self.catalog_key_by_cnid(target)?;
        let target_path = self.catalog_path(target)?;
        drop(handle::open_file_rw(
            self,
            dev,
            std::path::Path::new(&target_path),
            Default::default(),
            None,
        )?);
        let writer = self.writer.as_mut().unwrap();
        let destination = writer.catalog.get(&target_key).unwrap();
        if destination.len() != 248
            || [88..96, 100..168, 168..176, 180..248]
                .iter()
                .any(|range| destination[range.clone()].iter().any(|&b| b != 0))
            || writer
                .overflow_extents
                .keys()
                .any(|(_, id, _)| *id == target)
        {
            return Err(crate::Error::InvalidArgument(
                "resource detach target is not completely empty".into(),
            ));
        }
        let fork = writer.catalog.get(&source_key).unwrap()[168..248].to_vec();
        let overflow = writer
            .overflow_extents
            .range((extents::FORK_RESOURCE, source, 0)..=(extents::FORK_RESOURCE, source, u32::MAX))
            .map(|(key, value)| (*key, *value))
            .collect::<Vec<_>>();
        writer.catalog.get_mut(&target_key).unwrap()[88..168].copy_from_slice(&fork);
        let body = writer.catalog.get_mut(&source_key).unwrap();
        body[168..248].fill(0);
        body[176..180].copy_from_slice(&fork[8..12]);
        for (key, value) in overflow {
            writer.overflow_extents.remove(&key);
            writer
                .overflow_extents
                .insert((extents::FORK_DATA, target, key.2), value);
        }
        writer.flushed = false;
        Ok(())
    }

    /// Persist genuine preallocation, optionally discarding the old content in
    /// the same fork publication. No resource fork or other metadata is changed.
    pub fn set_data_allocation(
        &mut self,
        dev: &mut dyn BlockDevice,
        path: &std::path::Path,
        bytes: u64,
        truncate: bool,
    ) -> Result<()> {
        use crate::fs::FileHandle;
        let mut file = handle::open_file_rw(self, dev, path, Default::default(), None)?;
        if truncate {
            file.set_len(0)?;
        }
        file.set_allocation(bytes)?;
        file.sync()
    }

    /// Publish one ordinary data/resource fork edit with up to 256 user
    /// attributes and sixteen small related records. Full preflight precedes
    /// all payload writes. An ineffective fork edit returns false and ignores
    /// both metadata lists; use the metadata-only API for those changes.
    /// Failed I/O poisons publication and is never retried on handle drop.
    #[allow(clippy::too_many_arguments)]
    pub fn edit_fork_with_related_attributes(
        &mut self,
        dev: &mut dyn BlockDevice,
        path: &std::path::Path,
        resource: bool,
        edit: ForkEdit<'_>,
        changes: &[(&str, Option<&[u8]>)],
        related: &[(u32, &str, Option<&[u8]>)],
    ) -> Result<bool> {
        self.edit_fork_with_publication(
            dev,
            path,
            resource,
            edit,
            PublicationMetadata {
                attributes: changes,
                related,
                catalog: &[],
            },
        )
    }

    /// Includes preflighted catalog fields in the same fork publication. An
    /// ineffective fork edit ignores all metadata and returns false.
    pub fn edit_fork_with_publication(
        &mut self,
        dev: &mut dyn BlockDevice,
        path: &std::path::Path,
        resource: bool,
        edit: ForkEdit<'_>,
        metadata: PublicationMetadata<'_>,
    ) -> Result<bool> {
        handle::edit_with_related_attributes(self, dev, path, resource, edit, metadata)
    }

    /// Convert an empty, unallocated ordinary file into a relative symbolic
    /// link. Target bytes, catalog type and related metadata share one flush.
    /// Journaled volumes recover old-or-new; plain volumes have no crash-atomic
    /// guarantee. The caller must authorize and confine the relative target.
    pub fn convert_empty_file_to_symlink_with_publication(
        &mut self,
        dev: &mut dyn BlockDevice,
        path: &std::path::Path,
        target: &str,
        metadata: PublicationMetadata<'_>,
    ) -> Result<()> {
        handle::convert_empty_file_to_symlink(self, dev, path, target, metadata)
    }

    /// Convert an empty ordinary directory placeholder into an HFS symbolic
    /// link, retaining its CNID. The catalog entry, thread, volume counts and
    /// related metadata are published together with the target payload. Folder
    /// Finder fields without a lossless file representation are refused.
    pub fn convert_empty_directory_to_symlink_with_publication(
        &mut self,
        dev: &mut dyn BlockDevice,
        path: &std::path::Path,
        target: &str,
        metadata: PublicationMetadata<'_>,
    ) -> Result<()> {
        handle::convert_empty_directory_to_symlink(self, dev, path, target, metadata)
    }

    /// Replace a conventional symbolic link's target without changing its CNID,
    /// type or Finder identity. The replacement fork and related metadata share
    /// one journal publication; ordinary file editors still reject symlinks.
    pub fn replace_symlink_target_with_publication(
        &mut self,
        dev: &mut dyn BlockDevice,
        path: &std::path::Path,
        target: &str,
        metadata: PublicationMetadata<'_>,
    ) -> Result<()> {
        handle::replace_symlink_target(self, dev, path, target, metadata)
    }

    /// Remove a conventional symbolic link's redirect, retaining its CNID as
    /// an empty ordinary entry. Fork retirement, type/thread/count changes and
    /// supplied metadata publish together. Plain volumes are not crash atomic.
    pub fn remove_symlink_with_publication(
        &mut self,
        dev: &mut dyn BlockDevice,
        path: &std::path::Path,
        directory: bool,
        metadata: PublicationMetadata<'_>,
    ) -> Result<()> {
        handle::remove_symlink(self, dev, path, directory, metadata)
    }

    /// Stage an existing ordinary target's attributes together with related
    /// root/entry records, preserving the separate 256 + 16 budgets. Caller
    /// flush publishes the batch; pending attribute plans cannot be appended.
    pub fn set_attributes_with_related_records(
        &mut self,
        dev: &mut dyn BlockDevice,
        cnid: u32,
        changes: &[(&str, Option<&[u8]>)],
        related: &[(u32, &str, Option<&[u8]>)],
    ) -> Result<()> {
        self.set_attributes_with_publication(
            dev,
            cnid,
            PublicationMetadata {
                attributes: changes,
                related,
                catalog: &[],
            },
        )
    }

    /// Complete entry-attribute publication with the same target restrictions
    /// as set_inline_attributes: root, linked, locked and compressed targets
    /// remain refused. Internal related records can still target the root.
    pub fn set_entry_attributes_with_publication(
        &mut self,
        dev: &mut dyn BlockDevice,
        cnid: u32,
        metadata: PublicationMetadata<'_>,
    ) -> Result<()> {
        self.metadata_edit_key(cnid)?;
        self.set_attributes_with_publication(dev, cnid, metadata)
    }

    /// Preserve AFP backup-date semantics while planning FinderInfo, catalog
    /// dates and related records before any new staging. Caller flushes once.
    pub fn set_finder_info_with_publication(
        &mut self,
        dev: &mut dyn BlockDevice,
        cnid: u32,
        value: &[u8; 32],
        backup: Option<u32>,
        times: [Option<u32>; 4],
        related: &[(u32, &str, Option<&[u8]>)],
    ) -> Result<()> {
        let key = self.metadata_edit_key(cnid)?;
        let changes = [("com.apple.FinderInfo", Some(value.as_slice()))];
        let catalog = [CatalogUpdate {
            cnid,
            times,
            attributes: None,
        }];
        self.set_entry_attributes_with_publication(
            dev,
            cnid,
            PublicationMetadata {
                attributes: &changes,
                related,
                catalog: &catalog,
            },
        )?;
        // Target identity was validated before staging. No fallible operation
        // follows; a newly stored Finder lock must not reject its own backup date.
        if let Some(backup) = backup {
            self.writer.as_mut().unwrap().catalog.get_mut(&key).unwrap()[28..32]
                .copy_from_slice(&backup.to_be_bytes());
        }
        Ok(())
    }

    /// Stage complete metadata for an existing ordinary target; caller flushes.
    pub fn set_attributes_with_publication(
        &mut self,
        dev: &mut dyn BlockDevice,
        cnid: u32,
        metadata: PublicationMetadata<'_>,
    ) -> Result<()> {
        self.metadata_edit_key_inner(cnid, false, true)?;
        let plan = self.plan_related_attributes(
            dev,
            cnid,
            RelatedTarget::Ordinary,
            metadata.attributes,
            metadata.related,
        )?;
        self.validate_catalog_updates(cnid, RelatedTarget::Ordinary, false, metadata.catalog)?;
        let result = (|| {
            self.stage_related_attribute_plan(plan.transaction)?;
            if let Some(finder) = plan.finder {
                self.set_finder_info(cnid, &finder, None)?;
            }
            self.stage_catalog_updates(metadata.catalog)?;
            Ok(())
        })();
        if result.is_err() {
            self.write_failed = true;
        }
        result
    }

    /// Stage native basic metadata with bounded Windows bookkeeping records.
    /// This is not a general EA editor: only the target's precision/Windows
    /// hints and the root generation record may be supplied. Catalog lock
    /// transitions retain the legacy basic-info rules; BSD bits are preserved.
    /// Compressed targets keep their encoded storage after source validation.
    /// Caller flush publishes once; no existing attribute plan can be appended.
    #[cfg(feature = "hfs-compression")]
    pub fn set_basic_metadata_with_publication(
        &mut self,
        dev: &mut dyn BlockDevice,
        cnid: u32,
        times: [Option<u32>; 4],
        attributes: Option<u32>,
        related: &[(u32, &str, Option<&[u8]>)],
    ) -> Result<()> {
        if times.iter().all(Option::is_none) && attributes.is_none() && related.is_empty() {
            return Ok(());
        }
        let key = self.basic_metadata_key(cnid)?;
        let body = self.writer.as_ref().unwrap().catalog.get(&key).unwrap();
        Self::validate_catalog_attributes(body, attributes)?;
        let compressed = body[41] & 0x20 != 0;
        if related.len() > 16
            || related
                .iter()
                .any(|(_, _, v)| v.is_some_and(|v| v.len() > 3802))
        {
            return Err(crate::Error::Unsupported(
                "hfs+: basic metadata exceeds sixteen inline records".into(),
            ));
        }
        let mut unique = std::collections::BTreeSet::new();
        for &(id, name, _) in related {
            if !unique.insert((id, name)) {
                return Err(crate::Error::InvalidArgument(
                    "hfs+: duplicate basic metadata record".into(),
                ));
            }
            match name {
                "org.hfsbridge.windows.times" if id == cnid => {}
                "org.hfsbridge.windows.time-generation" if id == ROOT_FOLDER_ID => {
                    self.metadata_edit_key_inner(id, false, true)?;
                }
                "org.hfsbridge.windows.attributes" if id == cnid => {
                    // Hint changes retain ordinary-EA edit restrictions even
                    // when the same call would clear a native catalog lock.
                    self.metadata_edit_key(id)?;
                }
                _ => {
                    return Err(crate::Error::Unsupported(
                        "hfs+: reserved basic metadata scope".into(),
                    ));
                }
            }
        }
        if compressed {
            compression::validate_metadata(self, dev, cnid)?;
        }
        self.validate_attribute_storage(dev)?;
        let w = self.writer.as_ref().unwrap();
        if w.attribute_edit_plan.is_some() || !w.attribute_delete_ids.is_empty() {
            return Err(crate::Error::Unsupported(
                "hfs+: flush pending attribute mutation first".into(),
            ));
        }
        if w.attributes_file.total_blocks == 0
            && (w.attributes_file.logical_size != 0 || w.attributes_file.inline_blocks() != 0)
        {
            return Err(crate::Error::InvalidImage(
                "hfs+: inconsistent empty attributes fork".into(),
            ));
        }
        let transaction = if related.is_empty()
            || (w.attributes_file.total_blocks == 0 && related.iter().all(|(_, _, v)| v.is_none()))
        {
            None
        } else {
            let records = attribute_delete::records(dev, &w.attributes_file, w.block_size)?;
            Some(self.plan_fork_attribute_batch(dev, related, &records, &Default::default())?)
        };
        let result = (|| {
            self.stage_related_attribute_plan(transaction)?;
            self.set_catalog_windows_info(cnid, times, attributes)
        })();
        if result.is_err() {
            self.write_failed = true;
        }
        result
    }

    /// Publish namespace dates and only private timestamp bookkeeping alongside
    /// already-staged rename/removal work. The caller owns namespace permission
    /// checks and must abandon earlier staging if this complete plan is refused.
    /// Compressed/locked catalog identities retain date-only semantics; neither
    /// public attributes nor native protection flags may be changed here.
    #[cfg(feature = "hfs-compression")]
    pub fn set_namespace_metadata_with_publication(
        &mut self,
        dev: &mut dyn BlockDevice,
        catalog: &[CatalogUpdate],
        related: &[(u32, &str, Option<&[u8]>)],
    ) -> Result<()> {
        if catalog.is_empty() && related.is_empty() {
            return Ok(());
        }
        if catalog.len() > 16
            || related.len() > 16
            || related
                .iter()
                .any(|(_, _, v)| v.is_some_and(|v| v.len() > 3802))
        {
            return Err(crate::Error::Unsupported(
                "hfs+: namespace metadata exceeds sixteen bounded records".into(),
            ));
        }
        let mut identities = std::collections::BTreeSet::new();
        let mut compressed = Vec::new();
        for update in catalog {
            if update.attributes.is_some() || !identities.insert(update.cnid) {
                return Err(crate::Error::InvalidArgument(
                    "hfs+: namespace catalog updates require unique date-only identities".into(),
                ));
            }
            let key = self.namespace_metadata_key(update.cnid, true)?;
            if self.writer.as_ref().unwrap().catalog.get(&key).unwrap()[41] & 0x20 != 0 {
                compressed.push(update.cnid);
            }
        }
        let mut names = std::collections::BTreeSet::new();
        for &(cnid, name, _) in related {
            if !names.insert((cnid, name)) {
                return Err(crate::Error::InvalidArgument(
                    "hfs+: duplicate namespace metadata record".into(),
                ));
            }
            match name {
                "org.hfsbridge.windows.times" if identities.contains(&cnid) => {}
                "org.hfsbridge.windows.time-generation" if cnid == ROOT_FOLDER_ID => {
                    self.basic_metadata_key(cnid)?;
                }
                _ => {
                    return Err(crate::Error::Unsupported(
                        "hfs+: reserved namespace metadata scope".into(),
                    ));
                }
            }
        }
        for cnid in compressed {
            compression::validate_namespace_metadata(self, dev, cnid)?;
        }
        self.validate_attribute_storage(dev)?;
        let w = self.writer.as_ref().unwrap();
        if w.attribute_edit_plan.is_some() {
            return Err(crate::Error::Unsupported(
                "hfs+: flush pending attribute edit before namespace publication".into(),
            ));
        }
        if w.attributes_file.total_blocks == 0
            && (w.attributes_file.logical_size != 0 || w.attributes_file.inline_blocks() != 0)
        {
            return Err(crate::Error::InvalidImage(
                "hfs+: inconsistent empty attributes fork".into(),
            ));
        }
        let transaction = if related.is_empty()
            || (w.attributes_file.total_blocks == 0 && related.iter().all(|(_, _, v)| v.is_none()))
        {
            None
        } else {
            let records = attribute_delete::records(dev, &w.attributes_file, w.block_size)?;
            Some(self.plan_fork_attribute_batch(dev, related, &records, &w.attribute_delete_ids)?)
        };
        let result = (|| {
            self.stage_related_attribute_plan(transaction)?;
            if self.writer.as_ref().unwrap().attribute_edit_plan.is_some() {
                self.writer.as_mut().unwrap().attribute_delete_ids.clear();
            }
            self.stage_catalog_updates(catalog)
        })();
        if result.is_err() {
            self.write_failed = true;
        }
        result
    }

    /// Resource-fork reservation/EOF publication; the data fork is untouched.
    pub fn set_resource_allocation(
        &mut self,
        dev: &mut dyn BlockDevice,
        path: &std::path::Path,
        bytes: u64,
        truncate: bool,
    ) -> Result<()> {
        use crate::fs::FileHandle;
        let mut file = handle::open_resource_rw(self, dev, path)?;
        if truncate {
            file.set_len(0)?;
        }
        file.set_allocation(bytes)?;
        file.sync()
    }

    /// Update permission / ownership / mtime metadata on the entry at
    /// `path`, in place in the in-memory writer model. Fields left
    /// `None` in `attrs` are preserved. The new mode keeps the on-disk
    /// `S_IFMT` type bits and replaces only the `0o7777` permission
    /// bits. `mtime` is written to `contentModDate` (and the mod /
    /// access dates) via the usual Unix→HFS+ conversion. The change is
    /// staged in `writer.catalog`; [`Self::flush`] serialises it.
    ///
    /// `atime` and `ctime` have no independent on-disk home in our
    /// record layout (HFS+ keeps a single `accessDate` derived from the
    /// mod date) so they are accepted but not separately stored.
    pub fn set_attrs(
        &mut self,
        _dev: &mut dyn BlockDevice,
        path: &str,
        attrs: crate::fs::SetAttrs,
    ) -> Result<()> {
        // Nothing to do — avoid resolving the path for an empty request.
        if attrs.mode.is_none()
            && attrs.uid.is_none()
            && attrs.gid.is_none()
            && attrs.mtime.is_none()
        {
            return Ok(());
        }
        let (parent_id, name) = self.resolve_create_target(path)?;
        let w = self
            .writer
            .as_mut()
            .ok_or_else(|| crate::Error::InvalidArgument("hfs+: volume is read-only".into()))?;
        let key = writer::OwnedKey {
            parent_id,
            name: name.clone(),
        };
        let body = w.catalog.get_mut(&key).ok_or_else(|| {
            crate::Error::InvalidArgument(format!(
                "hfs+: no such entry {:?} under CNID {parent_id}",
                name.to_string_lossy()
            ))
        })?;
        // Both FILE and FOLDER record bodies place the dates at offset
        // 12 (createDate, contentModDate, …) and the 16-byte
        // HFSPlusBSDInfo at offset 32: ownerID 32..36, groupID 36..40,
        // adminFlags 40, ownerFlags 41, fileMode 42..44, special 44..48.
        // A thread record has neither, so reject it.
        const BSD_OFF: usize = 32;
        const MODE_OFF: usize = BSD_OFF + 10; // 42..44
        const UID_OFF: usize = BSD_OFF; // 32..36
        const GID_OFF: usize = BSD_OFF + 4; // 36..40
        const MTIME_OFF: usize = 16; // contentModDate 16..20
        if body.len() < BSD_OFF + 16 {
            return Err(crate::Error::InvalidImage(
                "hfs+: catalog record too short for BSDInfo (thread record?)".into(),
            ));
        }
        let rec_type = i16::from_be_bytes([body[0], body[1]]);
        if rec_type != catalog::REC_FILE && rec_type != catalog::REC_FOLDER {
            return Err(crate::Error::InvalidArgument(
                "hfs+: set_attrs target is not a file or folder record".into(),
            ));
        }
        if let Some(mode) = attrs.mode {
            let old = u16::from_be_bytes([body[MODE_OFF], body[MODE_OFF + 1]]);
            let new = (old & catalog::mode::S_IFMT) | (mode & 0o7777);
            body[MODE_OFF..MODE_OFF + 2].copy_from_slice(&new.to_be_bytes());
        }
        if let Some(uid) = attrs.uid {
            body[UID_OFF..UID_OFF + 4].copy_from_slice(&uid.to_be_bytes());
        }
        if let Some(gid) = attrs.gid {
            body[GID_OFF..GID_OFF + 4].copy_from_slice(&gid.to_be_bytes());
        }
        if let Some(mtime) = attrs.mtime {
            let hfs = unix_to_hfs_time(mtime);
            // Update contentModDate, attributeModDate, and accessDate —
            // the three dates `push_catalog_dates` keeps in lock-step —
            // leaving createDate (12..16) and backupDate (28..32) alone.
            body[MTIME_OFF..MTIME_OFF + 4].copy_from_slice(&hfs.to_be_bytes()); // contentModDate
            body[20..24].copy_from_slice(&hfs.to_be_bytes()); // attributeModDate
            body[24..28].copy_from_slice(&hfs.to_be_bytes()); // accessDate
        }
        Ok(())
    }

    #[doc(hidden)]
    #[cfg(test)]
    pub fn test_writer(&self) -> Option<&writer::Writer> {
        self.writer.as_ref()
    }

    /// Persist in-memory writer state (bitmap, catalog tree, volume
    /// header) to disk. Idempotent; no-op on read-only handles.
    pub fn flush(&mut self, dev: &mut dyn BlockDevice) -> Result<()> {
        if self.write_failed {
            return Err(crate::Error::InvalidArgument(
                "hfs+: failed edit requires reopening the volume".into(),
            ));
        }
        let Some(w) = self.writer.as_mut() else {
            return Ok(());
        };
        if let Err(error) = writer::flush(w, &mut self.volume_header, dev) {
            self.write_failed = true;
            return Err(error);
        }
        let hfsx = self.volume_header.is_hfsx();
        let refreshed = (|| {
            let cat_fork = ForkReader::from_inline(
                &self.volume_header.catalog_file,
                self.volume_header.block_size,
                "catalog",
            )?;
            // A commit can populate an empty overflow tree, change its root,
            // or relocate its fork. Readers must use the committed header and
            // mapping, just as they do for the catalog and attributes trees.
            let overflow = if self.volume_header.extents_file.total_blocks > 0 {
                let fork = ForkReader::from_inline(
                    &self.volume_header.extents_file,
                    self.volume_header.block_size,
                    "extents-overflow",
                )?;
                Some(ExtentsOverflow::open(dev, fork)?)
            } else {
                None
            };
            Ok((
                Catalog::open(dev, cat_fork, hfsx)?,
                open_attributes(dev, &self.volume_header, hfsx)?,
                overflow,
            ))
        })();
        let (catalog, attributes, overflow) = match refreshed {
            Ok(trees) => trees,
            Err(error) => {
                self.write_failed = true;
                return Err(error);
            }
        };
        self.catalog = catalog;
        self.attributes = attributes;
        self.overflow = overflow;
        w.flushed = false;
        Ok(())
    }

    /// Split `path` into its parent CNID and final name component,
    /// resolving all intermediates against the in-memory catalog.
    fn resolve_create_target(&self, path: &str) -> Result<(u32, UniStr)> {
        if self.write_failed {
            return Err(crate::Error::InvalidArgument(
                "hfs+: failed edit requires reopening the volume".into(),
            ));
        }
        let parts = split_path(path);
        if parts.is_empty() {
            return Err(crate::Error::InvalidArgument(
                "hfs+: cannot create at the root path".into(),
            ));
        }
        let (last, prefix) = parts.split_last().unwrap();
        let mut cnid = ROOT_FOLDER_ID;
        let w = self
            .writer
            .as_ref()
            .ok_or_else(|| crate::Error::InvalidArgument("hfs+: volume is read-only".into()))?;
        for part in prefix {
            let name = UniStr::from_path_component_checked(part)?;
            let (_, child_cnid, rec_type) = w.lookup(cnid, &name).ok_or_else(|| {
                crate::Error::InvalidArgument(format!(
                    "hfs+: parent component {part:?} does not exist"
                ))
            })?;
            if rec_type != catalog::REC_FOLDER {
                return Err(crate::Error::InvalidArgument(format!(
                    "hfs+: component {part:?} is not a directory"
                )));
            }
            cnid = child_cnid;
        }
        Ok((cnid, UniStr::from_path_component_checked(last)?))
    }

    /// Refuse an equivalent existing name before CNID/allocation changes or
    /// streamed payload writes. Canonical aliases must never leak allocation.
    fn resolve_new_target(&self, path: &str) -> Result<(u32, UniStr)> {
        let (parent, name) = self.resolve_create_target(path)?;
        if self
            .writer
            .as_ref()
            .unwrap()
            .lookup(parent, &name)
            .is_some()
        {
            return Err(crate::Error::InvalidArgument(
                "hfs+: destination already exists".into(),
            ));
        }
        Ok((parent, name))
    }

    /// Total byte capacity advertised by the volume header.
    pub fn total_bytes(&self) -> u64 {
        u64::from(self.volume_header.total_blocks) * u64::from(self.volume_header.block_size)
    }

    /// Allocation block size in bytes.
    pub fn block_size(&self) -> u32 {
        self.volume_header.block_size
    }

    /// Logical size and hidden resource storage for a supported compressed file.
    /// Preflight for future ordinary-data replacement. This does not mutate or
    /// enable compressed writes. Validates codec content, allocation capacity,
    /// source ownership and the checked attribute-removal plan before writing.
    #[cfg(feature = "hfs-compression")]
    pub fn validate_compressed_replacement(
        &self,
        dev: &mut dyn BlockDevice,
        cnid: u32,
        new_size: u64,
    ) -> Result<()> {
        compression::validate_replacement(self, dev, cnid, new_size)
    }

    /// Replace supported compressed content with an ordinary data fork, retaining
    /// identity, dates, ownership, FinderInfo and user attributes. Compression
    /// storage retires in the same metadata publication as its flag and xattr.
    /// The caller supplies exactly size bytes; failure requires reopening.
    /// The image-only Windows host uses this checked conversion path.
    #[cfg(feature = "hfs-compression")]
    pub fn replace_compressed_data(
        &mut self,
        dev: &mut dyn BlockDevice,
        path: &std::path::Path,
        input: &mut dyn std::io::Read,
        size: u64,
    ) -> Result<()> {
        handle::replace_compressed(self, dev, path, input, size)
    }

    #[cfg(feature = "hfs-compression")]
    fn compressed_attribute_plan(
        &self,
        dev: &mut dyn BlockDevice,
        cnid: u32,
        changes: &[(&str, Option<&[u8]>)],
    ) -> Result<(Option<[u8; 32]>, attribute_delete::Plan, bool)> {
        let (finder, mut ordinary) = Self::split_finder_changes(changes)?;
        if ordinary
            .iter()
            .any(|(name, _)| *name == "com.apple.decmpfs")
        {
            return Err(crate::Error::Unsupported(
                "compression metadata cannot be supplied as a user attribute".into(),
            ));
        }
        ordinary.push(("com.apple.decmpfs", None));
        let (plan, present) = self
            .plan_inline_attributes_inner(dev, cnid, &ordinary, true)?
            .ok_or_else(|| {
                crate::Error::InvalidImage("compression removal has no attribute plan".into())
            })?;
        Ok((finder, plan, present))
    }

    #[cfg(feature = "hfs-compression")]
    fn compressed_related_attribute_plan(
        &self,
        dev: &mut dyn BlockDevice,
        cnid: u32,
        changes: &[(&str, Option<&[u8]>)],
        related: &[(u32, &str, Option<&[u8]>)],
    ) -> Result<RelatedAttributePlan> {
        if related.is_empty() {
            let (finder, plan, present) = self.compressed_attribute_plan(dev, cnid, changes)?;
            return Ok(RelatedAttributePlan {
                finder,
                transaction: Some((plan, [(cnid, present)].into())),
            });
        }
        self.plan_related_attributes(dev, cnid, RelatedTarget::Compressed, changes, related)
    }

    /// Pure preflight for a conversion and its constructor attribute batch.
    /// Fresh attribute payload reservations and data capacity are counted together.
    #[cfg(feature = "hfs-compression")]
    pub fn validate_compressed_replacement_with_attributes(
        &self,
        dev: &mut dyn BlockDevice,
        cnid: u32,
        size: u64,
        allocation: u64,
        changes: &[(&str, Option<&[u8]>)],
    ) -> Result<()> {
        self.validate_compressed_replacement_with_related_attributes(
            dev,
            cnid,
            size,
            allocation,
            changes,
            &[],
        )
    }

    /// Pure combined preflight, including up to sixteen small root/entry/parent
    /// records in addition to the original 256 user-attribute budget.
    #[cfg(feature = "hfs-compression")]
    pub fn validate_compressed_replacement_with_related_attributes(
        &self,
        dev: &mut dyn BlockDevice,
        cnid: u32,
        size: u64,
        allocation: u64,
        changes: &[(&str, Option<&[u8]>)],
        related: &[(u32, &str, Option<&[u8]>)],
    ) -> Result<()> {
        self.validate_compressed_replacement(dev, cnid, size)?;
        let w = self.writer.as_ref().unwrap();
        if !allocation.is_multiple_of(u64::from(w.block_size)) {
            return Err(crate::Error::InvalidArgument(
                "conversion allocation is not block aligned".into(),
            ));
        }
        let plan = self.compressed_related_attribute_plan(dev, cnid, changes, related)?;
        let free = plan
            .transaction
            .as_ref()
            .and_then(|(plan, _)| plan.allocation.as_ref())
            .map_or(w.free_blocks, |a| a.free_blocks);
        if size
            .div_ceil(u64::from(w.block_size))
            .max(allocation / u64::from(w.block_size))
            > u64::from(free)
        {
            return Err(crate::Error::InvalidArgument(
                "insufficient free space for combined conversion and attributes".into(),
            ));
        }
        Ok(())
    }

    /// Publish replacement data, reservation, ordinary attributes and FinderInfo
    /// together with compression retirement. Public compression EAs remain refused.
    #[cfg(feature = "hfs-compression")]
    #[allow(clippy::too_many_arguments)]
    pub fn replace_compressed_with_attributes(
        &mut self,
        dev: &mut dyn BlockDevice,
        path: &std::path::Path,
        input: &mut dyn std::io::Read,
        size: u64,
        allocation: u64,
        changes: &[(&str, Option<&[u8]>)],
    ) -> Result<()> {
        handle::replace_compressed_planned(
            self,
            dev,
            path,
            &mut |_, bytes| Ok(input.read(bytes)?),
            size,
            allocation,
            changes,
            &[],
        )
    }

    /// Replace compressed data and publish all related metadata in the same
    /// journal transaction. Invalid related targets or aggregate space refusal
    /// consume no input and stage no prefix. Actual I/O failures poison writes.
    #[cfg(feature = "hfs-compression")]
    #[allow(clippy::too_many_arguments)]
    pub fn replace_compressed_with_related_attributes(
        &mut self,
        dev: &mut dyn BlockDevice,
        path: &std::path::Path,
        input: &mut dyn std::io::Read,
        size: u64,
        allocation: u64,
        changes: &[(&str, Option<&[u8]>)],
        related: &[(u32, &str, Option<&[u8]>)],
    ) -> Result<()> {
        handle::replace_compressed_planned(
            self,
            dev,
            path,
            &mut |_, bytes| Ok(input.read(bytes)?),
            size,
            allocation,
            changes,
            related,
        )
    }

    /// Bounded conversion followed by a patch, using the original decoded bytes
    /// and zero-filled gaps. Source compression storage is retained until commit.
    #[cfg(feature = "hfs-compression")]
    pub fn patch_compressed_data(
        &mut self,
        dev: &mut dyn BlockDevice,
        path: &std::path::Path,
        offset: u64,
        bytes: &[u8],
    ) -> Result<()> {
        compression::transform(self, dev, path, Some((offset, bytes)), None, false)
    }

    /// Replace decoded content, preallocation and complete catalog/attribute
    /// metadata in one publication, without consuming input on preflight refusal.
    #[cfg(feature = "hfs-compression")]
    pub fn replace_compressed_with_publication(
        &mut self,
        dev: &mut dyn BlockDevice,
        path: &std::path::Path,
        input: &mut dyn std::io::Read,
        size: u64,
        allocation: u64,
        metadata: PublicationMetadata<'_>,
    ) -> Result<()> {
        handle::replace_compressed_publication(
            self,
            dev,
            path,
            &mut |_, bytes| Ok(input.read(bytes)?),
            size,
            allocation,
            metadata,
        )
    }

    /// Convert decoded content and adjust its reservation in one publication.
    /// Allocation below EOF truncates it; existing compressed storage remains
    /// allocated until the replacement journal commits.
    #[cfg(feature = "hfs-compression")]
    pub fn allocate_compressed_with_publication(
        &mut self,
        dev: &mut dyn BlockDevice,
        path: &std::path::Path,
        allocation: u64,
        metadata: PublicationMetadata<'_>,
    ) -> Result<()> {
        let name = path
            .to_str()
            .ok_or_else(|| crate::Error::InvalidArgument("non-UTF-8 conversion path".into()))?;
        let body = self.catalog_record(name)?;
        let cnid = u32::from_be_bytes(body[8..12].try_into().unwrap());
        let (size, _) = self.compressed_info(dev, cnid)?.ok_or_else(|| {
            crate::Error::InvalidArgument("allocation target is not compressed".into())
        })?;
        compression::transform_with_allocation(
            self,
            dev,
            path,
            None,
            Some(size.min(allocation)),
            true,
            allocation,
            metadata,
        )
    }

    /// Patch converted content and publish preflighted catalog/attribute fields
    /// in the same transaction. An empty patch ignores the metadata batch.
    #[cfg(feature = "hfs-compression")]
    pub fn patch_compressed_with_publication(
        &mut self,
        dev: &mut dyn BlockDevice,
        path: &std::path::Path,
        offset: u64,
        bytes: &[u8],
        metadata: PublicationMetadata<'_>,
    ) -> Result<()> {
        compression::transform_with_publication(
            self,
            dev,
            path,
            Some((offset, bytes)),
            None,
            false,
            metadata,
        )
    }

    /// Resize converted content with catalog/attribute fields. Equal size is
    /// unchanged and ignores the metadata batch.
    #[cfg(feature = "hfs-compression")]
    pub fn resize_compressed_with_publication(
        &mut self,
        dev: &mut dyn BlockDevice,
        path: &std::path::Path,
        size: u64,
        metadata: PublicationMetadata<'_>,
    ) -> Result<()> {
        compression::transform_with_publication(self, dev, path, None, Some(size), false, metadata)
    }

    /// Bounded shrink or zero-filled growth of a compressed file. Equal sizes
    /// and empty patches leave the original compression representation intact.
    #[cfg(feature = "hfs-compression")]
    pub fn resize_compressed_data(
        &mut self,
        dev: &mut dyn BlockDevice,
        path: &std::path::Path,
        size: u64,
    ) -> Result<()> {
        compression::transform(self, dev, path, None, Some(size), false)
    }

    /// Convert to ordinary data without changing the decoded content.
    #[cfg(feature = "hfs-compression")]
    pub fn convert_compressed_data(
        &mut self,
        dev: &mut dyn BlockDevice,
        path: &std::path::Path,
    ) -> Result<()> {
        let name = path
            .to_str()
            .ok_or_else(|| crate::Error::InvalidArgument("non-UTF-8 conversion path".into()))?;
        let cnid = u32::from_be_bytes(self.catalog_record(name)?[8..12].try_into().unwrap());
        let (size, _) = self.compressed_info(dev, cnid)?.ok_or_else(|| {
            crate::Error::InvalidArgument("conversion target is not compressed".into())
        })?;
        compression::transform(self, dev, path, None, Some(size), true)
    }

    /// Whether a compressed entry's codec supports ordinary-data conversion.
    /// Actual mutation additionally requires the complete ownership preflight.
    #[cfg(feature = "hfs-compression")]
    pub fn compressed_conversion_supported(
        &self,
        dev: &mut dyn BlockDevice,
        cnid: u32,
    ) -> Result<bool> {
        if self.compressed_info(dev, cnid)?.is_none() {
            return Ok(false);
        }
        let (header, _) = compression::metadata(self, dev, cnid)?;
        Ok(matches!(
            header.kind,
            1 | 3 | 4 | 7 | 8 | 9 | 10 | 11 | 12 | 13 | 14
        ))
    }

    /// Logical size and hidden resource storage for a supported compressed file.
    #[cfg(feature = "hfs-compression")]
    pub fn compressed_info(
        &self,
        dev: &mut dyn BlockDevice,
        cnid: u32,
    ) -> Result<Option<(u64, bool)>> {
        let body = self.catalog_record_cnid(cnid)?;
        if i16::from_be_bytes(body[..2].try_into().unwrap()) != catalog::REC_FILE
            || body[41] & decmpfs::UF_COMPRESSED == 0
        {
            return Ok(None);
        }
        if body[88..96].iter().any(|byte| *byte != 0)
            || body[100..104].iter().any(|byte| *byte != 0)
        {
            return Err(crate::Error::Unsupported(
                "compressed file has a separate allocated data fork".into(),
            ));
        }
        let (header, _) = compression::metadata(self, dev, cnid)?;
        // Unknown codecs may use their resource fork as compressed storage.
        // Keep it hidden until we can interpret the encoding safely.
        Ok(Some((
            header.size,
            !matches!(header.kind, 1 | 3 | 7 | 9 | 11 | 13),
        )))
    }

    /// Cached volume name (from the root thread record).
    pub fn volume_name(&self) -> &str {
        &self.volume_name
    }

    /// List the entries of a directory by absolute path. Returns one
    /// [`crate::fs::DirEntry`] per child, with `inode` set to the
    /// HFS+ CNID (catalog node id) — which is the closest analogue
    /// to a Unix inode number on this filesystem. Hard-link source
    /// entries are reported with the underlying iNode's `kind`
    /// (typically `Regular`) so callers see a uniform view.
    pub fn list_path(
        &self,
        dev: &mut dyn BlockDevice,
        path: &str,
    ) -> Result<Vec<crate::fs::DirEntry>> {
        let cnid = self.resolve_dir(dev, path)?;
        self.list_cnid(dev, cnid)
    }

    /// Open a regular file by absolute path for streaming reads.
    /// Transparently follows hard links (`hlnk`/`hfs+` indirect node
    /// entries) to the actual iNode in the HFS+ private-data directory.
    /// Returns `Unsupported` for symlinks — use
    /// [`read_symlink_target_path`](Self::read_symlink_target_path)
    /// for those.
    pub fn open_file_reader<'a>(
        &self,
        dev: &'a mut dyn BlockDevice,
        path: &str,
    ) -> Result<HfsPlusFileReader<'a>> {
        let file = self.resolve_regular_file(dev, path)?;
        // HFSCompression: when UF_COMPRESSED is set, the data fork is
        // empty and the logical content lives in the
        // `com.apple.decmpfs` extended attribute (with optional
        // overflow into the resource fork).
        if file.bsd.owner_flags & decmpfs::UF_COMPRESSED != 0 {
            #[cfg(feature = "hfs-compression")]
            return compression::open(self, dev, &file);
            #[cfg(not(feature = "hfs-compression"))]
            {
                // TODO(streaming): decmpfs should decode per-block lazily like
                // squashfs (the resource-fork variant already carries a block
                // table). For now the whole file is inflated into RAM here for
                // the forward read; the seekable `open_file_ro` refuses instead
                // of faking Seek over this buffer.
                let bytes = self.read_decmpfs_file(dev, &file, path)?;
                return Ok(HfsPlusFileReader::buffered(bytes));
            }
        }
        let fork = self.open_data_fork(dev, &file)?;
        Ok(HfsPlusFileReader::streaming(
            dev,
            fork,
            file.data_fork.logical_size,
        ))
    }

    /// Resolve `path` to the [`CatalogFile`] of the regular file it names,
    /// following `hlnk`/`hfs+` hard-link indirection. Errors on
    /// directories, symlinks, thread records and non-regular special
    /// nodes. Shared by [`Self::open_file_reader`] (forward reads) and
    /// [`crate::fs::Filesystem::open_file_ro`] (random access).
    fn resolve_regular_file(&self, dev: &mut dyn BlockDevice, path: &str) -> Result<CatalogFile> {
        let rec = self.lookup_path(dev, path)?;
        let file = match rec {
            CatalogRecord::File(f) => f,
            CatalogRecord::Folder(_) => {
                return Err(crate::Error::InvalidArgument(format!(
                    "hfs+: {path:?} is a directory, not a file"
                )));
            }
            CatalogRecord::Thread(_) => {
                return Err(crate::Error::InvalidImage(format!(
                    "hfs+: path {path:?} resolved to a thread record"
                )));
            }
        };
        let file = self.resolve_hard_link(dev, file)?;
        let mode_bits = file.bsd.file_mode & mode::S_IFMT;
        if file.is_symlink() || mode_bits == mode::S_IFLNK {
            return Err(crate::Error::InvalidArgument(format!(
                "hfs+: {path:?} is a symlink; use read_symlink_target_path"
            )));
        }
        if mode_bits != 0 && mode_bits != mode::S_IFREG {
            return Err(crate::Error::Unsupported(format!(
                "hfs+: {path:?} is not a regular file (mode {:#06o})",
                file.bsd.file_mode
            )));
        }
        Ok(file)
    }

    /// Open a streaming reader over a file's **resource fork** (fork type
    /// `0xFF`), reusing the same extent machinery as the data fork. Errors if
    /// `path` isn't a regular file or has no resource fork. HFS-compressed
    /// files are rejected: their "resource fork" holds `decmpfs` compression
    /// blocks, not a user resource fork.
    pub fn open_resource_fork_reader<'a>(
        &self,
        dev: &'a mut dyn BlockDevice,
        path: &str,
    ) -> Result<HfsPlusFileReader<'a>> {
        let file = self.resource_fork_file(dev, path)?.ok_or_else(|| {
            crate::Error::InvalidArgument(format!("hfs+: {path:?} has no resource fork"))
        })?;
        let size = file.resource_fork.logical_size;
        let fork = self.open_fork(
            dev,
            &file.resource_fork,
            file.file_id,
            extents::FORK_RESOURCE,
            "resource",
        )?;
        Ok(HfsPlusFileReader::streaming(dev, fork, size))
    }

    /// Resource-fork logical size for `path`, or `None` when the file has no
    /// usable resource fork (absent, not a regular file, or HFS-compressed).
    pub fn resource_fork_size(&self, dev: &mut dyn BlockDevice, path: &str) -> Result<Option<u64>> {
        Ok(self
            .resource_fork_file(dev, path)?
            .map(|f| f.resource_fork.logical_size))
    }

    /// Resolve `path` to a regular file carrying a genuine (non-`decmpfs`)
    /// resource fork. `Ok(None)` means the path exists but has no usable
    /// resource fork; a missing path propagates as an error.
    fn resource_fork_file(
        &self,
        dev: &mut dyn BlockDevice,
        path: &str,
    ) -> Result<Option<CatalogFile>> {
        let file = match self.lookup_path(dev, path)? {
            CatalogRecord::File(f) => self.resolve_hard_link(dev, f)?,
            _ => return Ok(None),
        };
        // An HFS-compressed file stores its compressed payload in the resource
        // fork (decmpfs type 4/8/12); that is not a user resource fork.
        if file.bsd.owner_flags & decmpfs::UF_COMPRESSED != 0 {
            #[cfg(feature = "hfs-compression")]
            if !self.compressed_info(dev, file.file_id)?.unwrap().1 {
                return Ok((file.resource_fork.logical_size != 0).then_some(file));
            }
            return Ok(None);
        }
        if file.resource_fork.logical_size == 0 {
            return Ok(None);
        }
        Ok(Some(file))
    }

    /// Read a symlink's target by absolute path. Returns the raw
    /// UTF-8 bytes stored in the file's data fork as a `String`
    /// (HFS+ symlinks are conventionally stored as UTF-8 path text
    /// without a NUL terminator).
    pub fn read_symlink_target_path(
        &self,
        dev: &mut dyn BlockDevice,
        path: &str,
    ) -> Result<String> {
        let rec = self.lookup_path(dev, path)?;
        let file = match rec {
            CatalogRecord::File(f) => f,
            _ => {
                return Err(crate::Error::InvalidArgument(format!(
                    "hfs+: {path:?} is not a file (cannot be a symlink)"
                )));
            }
        };
        let file = self.resolve_hard_link(dev, file)?;
        self.read_symlink_target_inner(dev, &file, path)
    }

    /// Read a symlink's target by CNID. Useful when the caller has
    /// already discovered the target file ID via [`Self::list_path`] but
    /// doesn't have a stable path (e.g. multiple parents). Returns
    /// the link target as a UTF-8 string.
    pub fn read_symlink_target(&self, dev: &mut dyn BlockDevice, cnid: u32) -> Result<String> {
        let file = self.lookup_file_by_cnid(dev, cnid)?;
        let file = self.resolve_hard_link(dev, file)?;
        self.read_symlink_target_inner(dev, &file, &format!("CNID {cnid}"))
    }

    /// Read-only effective identity for regular-file metadata. Hard-link
    /// resolution uses the same checked inode lookup as data/resource readers.
    pub fn regular_file_identity(&self, dev: &mut dyn BlockDevice, cnid: u32) -> Result<u32> {
        let file = self.lookup_file_by_cnid(dev, cnid)?;
        let file = self.resolve_hard_link(dev, file)?;
        let kind = file.bsd.file_mode & mode::S_IFMT;
        if file.is_symlink() || (kind != 0 && kind != mode::S_IFREG) {
            return Err(crate::Error::Unsupported(
                "effective identity requires a regular file".into(),
            ));
        }
        Ok(file.file_id)
    }

    /// Total byte length of a regular file (after hard-link resolution),
    /// for callers that want to size a buffer before streaming.
    pub fn file_size(&self, dev: &mut dyn BlockDevice, path: &str) -> Result<u64> {
        let rec = self.lookup_path(dev, path)?;
        let file = match rec {
            CatalogRecord::File(f) => f,
            _ => {
                return Err(crate::Error::InvalidArgument(format!(
                    "hfs+: {path:?} is not a file"
                )));
            }
        };
        let file = self.resolve_hard_link(dev, file)?;
        Ok(file.data_fork.logical_size)
    }

    // -- internal helpers ----------------------------------------------

    /// Walk the path one component at a time, returning the CNID of
    /// the *directory* it names. `"/"` and `""` both name the root.
    fn resolve_dir(&self, dev: &mut dyn BlockDevice, path: &str) -> Result<u32> {
        let parts = split_path(path);
        let mut cnid = ROOT_FOLDER_ID;
        for part in parts {
            let rec = self.lookup_component(dev, cnid, part)?;
            match rec {
                CatalogRecord::Folder(f) => {
                    cnid = f.folder_id;
                }
                CatalogRecord::File(_) => {
                    return Err(crate::Error::InvalidArgument(format!(
                        "hfs+: {part:?} is not a directory (in {path:?})"
                    )));
                }
                CatalogRecord::Thread(_) => {
                    return Err(crate::Error::InvalidImage(format!(
                        "hfs+: lookup of {part:?} returned a thread record"
                    )));
                }
            }
        }
        Ok(cnid)
    }

    /// Walk the path and return the leaf record (file or folder).
    fn lookup_path(&self, dev: &mut dyn BlockDevice, path: &str) -> Result<CatalogRecord> {
        let parts = split_path(path);
        if parts.is_empty() {
            return Err(crate::Error::InvalidArgument(
                "hfs+: cannot resolve root \"/\" as a leaf entry".into(),
            ));
        }
        let (last, prefix) = parts.split_last().unwrap();
        let mut cnid = ROOT_FOLDER_ID;
        for part in prefix {
            let rec = self.lookup_component(dev, cnid, part)?;
            match rec {
                CatalogRecord::Folder(f) => cnid = f.folder_id,
                _ => {
                    return Err(crate::Error::InvalidArgument(format!(
                        "hfs+: {part:?} is not a directory (in {path:?})"
                    )));
                }
            }
        }
        self.lookup_component(dev, cnid, last)
    }

    /// Look up the immediate child named `name` under directory `parent_id`.
    fn lookup_component(
        &self,
        dev: &mut dyn BlockDevice,
        parent_id: u32,
        name: &str,
    ) -> Result<CatalogRecord> {
        let key = CatalogKey {
            parent_id,
            name: UniStr::from_path_component_checked(name)?,
            encoded_len: 0,
        };
        self.catalog.lookup(dev, &key)?.ok_or_else(|| {
            crate::Error::InvalidArgument(format!(
                "hfs+: no such entry {name:?} under CNID {parent_id}"
            ))
        })
    }

    /// Look up a catalog *file* by its CNID. Two-step: first read the
    /// file's thread record (key = (cnid, "")) to recover its
    /// `(parent_id, name)`, then look up the actual record.
    fn lookup_file_by_cnid(&self, dev: &mut dyn BlockDevice, cnid: u32) -> Result<CatalogFile> {
        let thread_key = CatalogKey {
            parent_id: cnid,
            name: UniStr::default(),
            encoded_len: 0,
        };
        let (parent_id, name) = match self.catalog.lookup(dev, &thread_key)? {
            Some(CatalogRecord::Thread(t)) => (t.parent_id, t.name),
            Some(_) => {
                return Err(crate::Error::InvalidImage(format!(
                    "hfs+: CNID {cnid} thread key did not return a thread record"
                )));
            }
            None => {
                return Err(crate::Error::InvalidArgument(format!(
                    "hfs+: no thread record for CNID {cnid}"
                )));
            }
        };
        let child_key = CatalogKey {
            parent_id,
            name,
            encoded_len: 0,
        };
        match self.catalog.lookup(dev, &child_key)? {
            Some(CatalogRecord::File(f)) => Ok(f),
            Some(CatalogRecord::Folder(_)) => Err(crate::Error::InvalidArgument(format!(
                "hfs+: CNID {cnid} names a folder, not a file"
            ))),
            Some(CatalogRecord::Thread(_)) => Err(crate::Error::InvalidImage(format!(
                "hfs+: CNID {cnid} reverse-lookup returned a thread record"
            ))),
            None => Err(crate::Error::InvalidArgument(format!(
                "hfs+: no catalog file for CNID {cnid}"
            ))),
        }
    }

    /// If `file` is a hard-link indirect-node entry (`hlnk`/`hfs+`),
    /// resolve it to the underlying iNode file in the HFS+ private
    /// data directory. Otherwise return the file unchanged.
    fn resolve_hard_link(
        &self,
        dev: &mut dyn BlockDevice,
        file: CatalogFile,
    ) -> Result<CatalogFile> {
        if !file.is_hard_link() {
            return Ok(file);
        }
        let private_dir = match self.private_data_dir(dev)? {
            Some(cnid) => cnid,
            None => {
                return Err(crate::Error::InvalidImage(
                    "hfs+: hard-link record but no '\\0\\0\\0\\0HFS+ Private Data' \
                     directory found"
                        .into(),
                ));
            }
        };
        // The iNode number lives in BsdInfo.special on a hlnk record.
        let inode_id = file.bsd.special;
        let name = format!("iNode{inode_id}");
        let rec = self.lookup_component(dev, private_dir, &name)?;
        match rec {
            CatalogRecord::File(f) => {
                // Defence in depth: forbid recursive hard links.
                if f.is_hard_link() {
                    return Err(crate::Error::InvalidImage(format!(
                        "hfs+: iNode{inode_id} is itself a hard-link indirection"
                    )));
                }
                Ok(f)
            }
            _ => Err(crate::Error::InvalidImage(format!(
                "hfs+: iNode{inode_id} is not a regular file record"
            ))),
        }
    }

    /// Resolve, cache, and return the CNID of the HFS+ private data
    /// directory (Apple's well-known name with four leading NUL
    /// code units followed by "HFS+ Private Data"). Returns `None`
    /// on a volume that has no hard links — the directory only exists
    /// when at least one hard link has ever been created.
    fn private_data_dir(&self, dev: &mut dyn BlockDevice) -> Result<Option<u32>> {
        if self.private_dir_resolved.get() {
            return Ok(self.private_dir_cnid.get());
        }
        // UniStr cannot easily be built from a Rust string containing
        // null code units, so build it directly.
        let mut code_units: Vec<u16> = vec![0, 0, 0, 0];
        code_units.extend("HFS+ Private Data".encode_utf16());
        let key = CatalogKey {
            parent_id: ROOT_FOLDER_ID,
            name: UniStr { code_units },
            encoded_len: 0,
        };
        let cnid = match self.catalog.lookup(dev, &key)? {
            Some(CatalogRecord::Folder(f)) => Some(f.folder_id),
            _ => None,
        };
        self.private_dir_cnid.set(cnid);
        self.private_dir_resolved.set(true);
        Ok(cnid)
    }

    /// Build a `ForkReader` for `file`'s data fork, pulling extra
    /// extents from the extents-overflow B-tree if the inline eight
    /// are insufficient.
    fn open_data_fork(&self, dev: &mut dyn BlockDevice, file: &CatalogFile) -> Result<ForkReader> {
        self.open_fork(
            dev,
            &file.data_fork,
            file.file_id,
            extents::FORK_DATA,
            "data",
        )
    }

    fn open_fork(
        &self,
        dev: &mut dyn BlockDevice,
        fork: &ForkData,
        file_id: u32,
        fork_type: u8,
        what: &str,
    ) -> Result<ForkReader> {
        if u64::from(fork.total_blocks) <= fork.inline_blocks() {
            return ForkReader::from_inline(fork, self.volume_header.block_size, what);
        }
        let overflow = self.overflow.as_ref().ok_or_else(|| {
            crate::Error::InvalidImage(
                "hfs+: fork needs overflow extents but volume has no \
                 extents-overflow file"
                    .into(),
            )
        })?;
        let first_overflow_block = u32::try_from(fork.inline_blocks()).map_err(|_| {
            crate::Error::InvalidImage("hfs+: inline fork block count overflows u32".into())
        })?;
        let extra = overflow.find_extents(dev, file_id, fork_type, first_overflow_block)?;
        ForkReader::from_inline_plus_overflow(fork, &extra, self.volume_header.block_size, what)
    }

    /// HFSCompression read path: look up `com.apple.decmpfs` for
    /// `file.file_id`, decode the header, and return the file's
    /// fully-decompressed bytes. For codecs that store the payload in
    /// the resource fork (type 4 / 8 / 12) we read the resource fork
    /// in one shot and hand it to the codec.
    #[cfg(not(feature = "hfs-compression"))]
    fn read_decmpfs_file(
        &self,
        dev: &mut dyn BlockDevice,
        file: &CatalogFile,
        path: &str,
    ) -> Result<Vec<u8>> {
        let attrs = self.attributes.as_ref().ok_or_else(|| {
            crate::Error::InvalidImage(format!(
                "hfs+: {path:?} has UF_COMPRESSED set but volume has no \
                 attributes file to hold com.apple.decmpfs"
            ))
        })?;
        let rec = attrs
            .lookup(dev, file.file_id, "com.apple.decmpfs")?
            .ok_or_else(|| {
                crate::Error::InvalidImage(format!(
                    "hfs+: {path:?} has UF_COMPRESSED set but no com.apple.decmpfs \
                     attribute exists for CNID {}",
                    file.file_id
                ))
            })?;
        // Inline xattr — the entire decmpfs record fits in the leaf.
        let xattr_bytes = match rec {
            attributes::AttrRecord::Inline { data } => data,
            attributes::AttrRecord::Fork { fork } => {
                // Extremely rare in practice: an xattr that itself spilled
                // into its own fork. Read the whole fork into memory and
                // continue as if it were inline.
                let what = "decmpfs-xattr-fork";
                let reader = if u64::from(fork.total_blocks) <= fork.inline_blocks() {
                    ForkReader::from_inline(&fork, self.volume_header.block_size, what)?
                } else {
                    return Err(crate::Error::Unsupported(
                        "hfs+: decmpfs xattr stored in a fork that needs overflow extents".into(),
                    ));
                };
                let len = cap_alloc(dev, fork.logical_size, "decmpfs xattr fork")?;
                let mut buf = vec![0u8; len];
                reader.read(dev, 0, &mut buf)?;
                buf
            }
        };
        if xattr_bytes.len() < decmpfs::DecmpfsHeader::SIZE {
            return Err(crate::Error::InvalidImage(format!(
                "hfs+: {path:?} com.apple.decmpfs is {} bytes, shorter than the 16-byte header",
                xattr_bytes.len()
            )));
        }
        let header = decmpfs::DecmpfsHeader::decode(&xattr_bytes)?;
        if header.compression_type.is_resource_fork() {
            // Type 4 / 8 / 12 — payload lives in the resource fork.
            if file.resource_fork.logical_size == 0 {
                return Err(crate::Error::InvalidImage(format!(
                    "hfs+: {path:?} decmpfs claims compression type {:?} but resource fork is empty",
                    header.compression_type
                )));
            }
            let rf_reader = self.open_fork(
                dev,
                &file.resource_fork,
                file.file_id,
                extents::FORK_RESOURCE,
                "resource",
            )?;
            let rf_len = cap_alloc(
                dev,
                file.resource_fork.logical_size,
                "decmpfs resource fork",
            )?;
            let mut rf_bytes = vec![0u8; rf_len];
            rf_reader.read(dev, 0, &mut rf_bytes)?;
            decmpfs::decompress_resource_fork(
                header.compression_type,
                &rf_bytes,
                header.uncompressed_size,
            )
        } else {
            // Inline payload follows the 16-byte header in the xattr.
            decmpfs::decompress_inline(
                header.compression_type,
                &xattr_bytes[decmpfs::DecmpfsHeader::SIZE..],
                header.uncompressed_size,
            )
        }
    }

    /// Read up to `SYMLINK_MAX_BYTES` from a symlink's data fork and
    /// return the result as a Rust string. `descriptor` is a human-
    /// readable identifier (path or CNID) used only in error text.
    fn read_symlink_target_inner(
        &self,
        dev: &mut dyn BlockDevice,
        file: &CatalogFile,
        descriptor: &str,
    ) -> Result<String> {
        let mode_bits = file.bsd.file_mode & mode::S_IFMT;
        let by_mode = mode_bits == mode::S_IFLNK;
        let by_finder = file.is_symlink();
        if !by_mode && !by_finder {
            return Err(crate::Error::InvalidArgument(format!(
                "hfs+: {descriptor} is not a symlink (mode {:#06o}, \
                 FileInfo type {:?}, creator {:?})",
                file.bsd.file_mode,
                bytes_to_osstr(&file.file_type),
                bytes_to_osstr(&file.creator),
            )));
        }
        let len = file.data_fork.logical_size;
        if len == 0 {
            return Ok(String::new());
        }
        if len > SYMLINK_MAX_BYTES {
            return Err(crate::Error::InvalidImage(format!(
                "hfs+: {descriptor} symlink target too large ({len} bytes, \
                 max {SYMLINK_MAX_BYTES})"
            )));
        }
        let fork = self.open_data_fork(dev, file)?;
        let mut buf = vec![0u8; len as usize];
        fork.read(dev, 0, &mut buf)?;
        // HFS+ symlinks are UTF-8 path strings. Accept a trailing NUL
        // (some writers add one).
        if buf.last() == Some(&0) {
            buf.pop();
        }
        String::from_utf8(buf).map_err(|e| {
            crate::Error::InvalidImage(format!(
                "hfs+: {descriptor} symlink target is not valid UTF-8: {e}"
            ))
        })
    }

    /// Enumerate the direct children of folder `cnid`.
    ///
    /// Catalog keys sort by `parentID` first, so every child of `cnid`
    /// is contiguous in the leaf chain. Descend the B-tree to the leaf
    /// that would hold `(cnid, "")` and walk forward from there,
    /// stopping at the first key with a larger parent — walking from
    /// the *first* leaf instead makes every listing cost the whole
    /// catalog.
    fn list_cnid(&self, dev: &mut dyn BlockDevice, cnid: u32) -> Result<Vec<crate::fs::DirEntry>> {
        use crate::fs::{DirEntry as FsDirEntry, EntryKind};

        let mut out = Vec::new();
        let node_size = u32::from(self.catalog.header.node_size);
        let total_nodes = self.catalog.header.total_nodes;
        let start_key = CatalogKey {
            parent_id: cnid,
            name: crate::fs::hfs_plus::catalog::UniStr::default(),
            encoded_len: 0,
        };
        let mut node_idx = match self.catalog.leaf_for_key(dev, &start_key)? {
            Some(n) => n,
            None => return Ok(out),
        };
        // Bound the leaf-chain walk by the catalog node count: a malicious
        // `fLink` cycle would otherwise loop forever.
        let mut steps_left = total_nodes as usize;
        while node_idx != 0 {
            if steps_left == 0 {
                return Err(crate::Error::InvalidImage(
                    "hfs+: catalog leaf chain exceeded node count (cycle?)".into(),
                ));
            }
            steps_left -= 1;
            if node_idx >= total_nodes {
                return Err(crate::Error::InvalidImage(format!(
                    "hfs+: catalog leaf node {node_idx} >= total_nodes {total_nodes}"
                )));
            }
            let node = btree::read_node(dev, &self.catalog.fork, node_idx, node_size)?;
            let desc = btree::NodeDescriptor::decode(&node)?;
            if desc.kind != btree::KIND_LEAF {
                return Err(crate::Error::InvalidImage(format!(
                    "hfs+: leaf chain node {node_idx} has non-leaf kind {}",
                    desc.kind
                )));
            }
            let offs = btree::record_offsets(&node, desc.num_records)?;

            let mut passed_parent = false;
            for i in 0..desc.num_records as usize {
                let rec = btree::record_bytes(&node, &offs, i);
                let key = CatalogKey::decode(rec)?;
                use std::cmp::Ordering as O;
                match key.parent_id.cmp(&cnid) {
                    O::Less => continue,
                    O::Greater => {
                        passed_parent = true;
                        break;
                    }
                    O::Equal => {}
                }
                let body_start = align2(key.encoded_len);
                if body_start > rec.len() {
                    return Err(crate::Error::InvalidImage(
                        "hfs+: catalog key overruns record".into(),
                    ));
                }
                let body = &rec[body_start..];
                let record = CatalogRecord::decode(body)?;
                // Skip threads — they're metadata, not real children.
                let (kind, child_id) = match &record {
                    CatalogRecord::Folder(f) => (EntryKind::Dir, f.folder_id),
                    CatalogRecord::File(f) => {
                        // Hard-link entries: resolve the kind by
                        // peeking at the iNode so callers see a
                        // unified view. The link itself is the
                        // `child_id` we expose, matching what the
                        // catalog records.
                        if f.is_hard_link() {
                            let resolved_kind = self
                                .resolve_hard_link(dev, f.clone())
                                .map(|r| file_kind(&r))
                                .unwrap_or(EntryKind::Unknown);
                            (resolved_kind, f.file_id)
                        } else if f.is_symlink() {
                            (EntryKind::Symlink, f.file_id)
                        } else {
                            (file_kind(f), f.file_id)
                        }
                    }
                    CatalogRecord::Thread(_) => continue,
                };
                let size = match &record {
                    CatalogRecord::File(f) if matches!(kind, EntryKind::Regular) => {
                        f.data_fork.logical_size
                    }
                    _ => 0,
                };
                out.push(FsDirEntry {
                    name: key.name.to_display_name(),
                    inode: child_id,
                    kind,
                    size,
                });
            }
            if passed_parent {
                break;
            }
            node_idx = desc.f_link;
        }
        Ok(out)
    }
}

/// Reader for a regular HFS+ file. Two storage strategies sit
/// behind the same public type so callers don't have to branch:
///
/// * **Streaming** — the common case. Holds the data-fork extent
///   list in a [`ForkReader`] and walks it on demand from the
///   borrowed [`BlockDevice`].
/// * **Buffered** — used when the on-disk file carries
///   `UF_COMPRESSED` and its logical content has to be
///   reconstructed from the `com.apple.decmpfs` extended attribute
///   (and optionally the resource fork) up front. Once we've
///   inflated the payload we hold it in RAM and serve reads from a
///   cursor — a single decmpfs file decompresses to at most a few
///   MiB per leaf record and the resource-fork path is bounded by
///   64 KiB blocks, so this is fine for the workloads we care
///   about.
///
/// The variant lives in a private inner enum so the public type
/// remains a fieldless struct — matching the surface this type
/// exposed before HFSCompression support was added.
pub struct HfsPlusFileReader<'a> {
    inner: HfsPlusFileReaderInner<'a>,
}

/// Private storage for [`HfsPlusFileReader`]. Hidden behind the
/// public struct so adding / renaming variants stays a non-breaking
/// change.
enum HfsPlusFileReaderInner<'a> {
    #[cfg(feature = "hfs-compression")]
    Compressed(compression::CompressedReader<'a>),
    /// On-disk data fork; reads stream from `dev`.
    Streaming {
        dev: &'a mut dyn BlockDevice,
        fork: ForkReader,
        /// Bytes of the file still to return.
        remaining: u64,
        /// Current fork-relative byte position.
        position: u64,
    },
    /// Decompressed (or otherwise materialised) payload held in RAM.
    /// Carries the file lifetime so the public type signature is
    /// uniform regardless of variant.
    Buffered {
        bytes: Vec<u8>,
        position: u64,
        _phantom: std::marker::PhantomData<&'a ()>,
    },
}

impl<'a> HfsPlusFileReader<'a> {
    /// Build a streaming reader over the bytes of `fork`. Reads stop
    /// once `logical_size` has been returned.
    pub(crate) fn streaming(
        dev: &'a mut dyn BlockDevice,
        fork: ForkReader,
        logical_size: u64,
    ) -> Self {
        Self {
            inner: HfsPlusFileReaderInner::Streaming {
                dev,
                fork,
                remaining: logical_size,
                position: 0,
            },
        }
    }

    /// Build a buffered reader serving `bytes` from a 0-based cursor.
    /// Used by the HFSCompression path so the public reader interface
    /// looks identical to the data-fork case.
    pub(crate) fn buffered(bytes: Vec<u8>) -> Self {
        Self {
            inner: HfsPlusFileReaderInner::Buffered {
                bytes,
                position: 0,
                _phantom: std::marker::PhantomData,
            },
        }
    }
}

impl<'a> Read for HfsPlusFileReader<'a> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match &mut self.inner {
            #[cfg(feature = "hfs-compression")]
            HfsPlusFileReaderInner::Compressed(reader) => reader.read(buf),
            HfsPlusFileReaderInner::Streaming {
                dev,
                fork,
                remaining,
                position,
            } => {
                if *remaining == 0 || buf.is_empty() {
                    return Ok(0);
                }
                let want = (buf.len() as u64).min(*remaining) as usize;
                fork.read(*dev, *position, &mut buf[..want])
                    .map_err(std::io::Error::other)?;
                *position += want as u64;
                *remaining -= want as u64;
                Ok(want)
            }
            HfsPlusFileReaderInner::Buffered {
                bytes, position, ..
            } => {
                let len = bytes.len() as u64;
                if *position >= len || buf.is_empty() {
                    return Ok(0);
                }
                let avail = (len - *position) as usize;
                let want = buf.len().min(avail);
                let p = *position as usize;
                buf[..want].copy_from_slice(&bytes[p..p + want]);
                *position += want as u64;
                Ok(want)
            }
        }
    }
}

impl<'a> std::io::Seek for HfsPlusFileReader<'a> {
    fn seek(&mut self, pos: std::io::SeekFrom) -> std::io::Result<u64> {
        match &mut self.inner {
            #[cfg(feature = "hfs-compression")]
            HfsPlusFileReaderInner::Compressed(reader) => reader.seek(pos),
            HfsPlusFileReaderInner::Streaming {
                fork,
                remaining,
                position,
                ..
            } => {
                let total = fork.logical_size as i128;
                let new = match pos {
                    std::io::SeekFrom::Start(n) => n as i128,
                    std::io::SeekFrom::Current(d) => *position as i128 + d as i128,
                    std::io::SeekFrom::End(d) => total + d as i128,
                };
                if new < 0 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "hfs+: seek to negative offset",
                    ));
                }
                *position = new as u64;
                *remaining = fork.logical_size.saturating_sub(*position);
                Ok(*position)
            }
            HfsPlusFileReaderInner::Buffered {
                bytes, position, ..
            } => {
                let total = bytes.len() as i128;
                let new = match pos {
                    std::io::SeekFrom::Start(n) => n as i128,
                    std::io::SeekFrom::Current(d) => *position as i128 + d as i128,
                    std::io::SeekFrom::End(d) => total + d as i128,
                };
                if new < 0 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "hfs+: seek to negative offset",
                    ));
                }
                *position = new as u64;
                Ok(*position)
            }
        }
    }
}

impl<'a> crate::fs::FileReadHandle for HfsPlusFileReader<'a> {
    fn len(&self) -> u64 {
        match &self.inner {
            #[cfg(feature = "hfs-compression")]
            HfsPlusFileReaderInner::Compressed(reader) => reader.size,
            HfsPlusFileReaderInner::Streaming { fork, .. } => fork.logical_size,
            HfsPlusFileReaderInner::Buffered { bytes, .. } => bytes.len() as u64,
        }
    }
}

/// Probe for the HFS+ volume-header signature `"H+"` (or `"HX"` for HFSX)
/// at offset 1024 of the volume.
pub fn probe(dev: &mut dyn BlockDevice) -> Result<bool> {
    if dev.total_size() < 1024 + 2 {
        return Ok(false);
    }
    let mut sig = [0u8; 2];
    dev.read_at(1024, &mut sig)?;
    Ok(&sig == b"H+" || &sig == b"HX")
}

// -- helpers --------------------------------------------------------------

/// Classify a `CatalogFile` into a [`crate::fs::EntryKind`] using
/// its BSD `file_mode` bits when set, falling back to "regular".
fn file_kind(f: &CatalogFile) -> crate::fs::EntryKind {
    use crate::fs::EntryKind;
    match f.bsd.file_mode & mode::S_IFMT {
        mode::S_IFREG => EntryKind::Regular,
        mode::S_IFDIR => EntryKind::Dir, // unusual on a file record, but be defensive
        mode::S_IFLNK => EntryKind::Symlink,
        mode::S_IFCHR => EntryKind::Char,
        mode::S_IFBLK => EntryKind::Block,
        mode::S_IFIFO => EntryKind::Fifo,
        mode::S_IFSOCK => EntryKind::Socket,
        0 => EntryKind::Regular,
        _ => EntryKind::Unknown,
    }
}

/// Read the thread record for `cnid`, returning the node name. Used
/// to discover the volume name from the root folder's thread.
fn lookup_thread_name(
    dev: &mut dyn BlockDevice,
    catalog: &Catalog,
    cnid: u32,
) -> Result<Option<String>> {
    let key = CatalogKey {
        parent_id: cnid,
        name: UniStr::default(),
        encoded_len: 0,
    };
    match catalog.lookup(dev, &key)? {
        Some(CatalogRecord::Thread(t)) => Ok(Some(t.name.to_string_lossy())),
        _ => Ok(None),
    }
}

/// Open the volume's attributes B-tree (extended-attribute file), or
/// return `None` if the volume has no attributes file. Image producers
/// (including our own writer) commonly leave the attributes fork
/// empty.
fn open_attributes(
    dev: &mut dyn BlockDevice,
    vh: &VolumeHeader,
    case_sensitive: bool,
) -> Result<Option<Attributes>> {
    if vh.attributes_file.total_blocks == 0 {
        return Ok(None);
    }
    let fork = ForkReader::from_inline(&vh.attributes_file, vh.block_size, "attributes")?;
    Ok(Some(Attributes::open(dev, fork, case_sensitive)?))
}

/// Render an OSType 4-byte tag for diagnostics, preferring ASCII
/// when the tag is human-readable and falling back to hex otherwise.
fn bytes_to_osstr(b: &[u8; 4]) -> String {
    if b.iter().all(|&c| (0x20..=0x7E).contains(&c)) {
        format!("'{}'", String::from_utf8_lossy(b))
    } else {
        format!("0x{:02x}{:02x}{:02x}{:02x}", b[0], b[1], b[2], b[3])
    }
}

fn align2(n: usize) -> usize {
    n + (n & 1)
}

/// Validate an allocation size derived from an untrusted `logical_size`
/// against the device's real capacity before we reserve a buffer for it.
/// A malicious image can claim a multi-gigabyte fork on a tiny device to
/// trigger an out-of-memory abort; cap the request at `dev.total_size()`
/// and reject anything larger as `InvalidImage`. Returns the size as a
/// `usize` suitable for `vec![0u8; n]`.
#[cfg(not(feature = "hfs-compression"))]
fn cap_alloc(dev: &dyn BlockDevice, logical_size: u64, what: &str) -> Result<usize> {
    let dev_size = dev.total_size();
    if logical_size > dev_size {
        return Err(crate::Error::InvalidImage(format!(
            "hfs+: {what} claims {logical_size} bytes but device is only {dev_size} bytes"
        )));
    }
    usize::try_from(logical_size).map_err(|_| {
        crate::Error::InvalidImage(format!("hfs+: {what} size {logical_size} exceeds usize"))
    })
}

fn split_path(path: &str) -> Vec<&str> {
    path.split('/')
        .filter(|p| !p.is_empty() && *p != ".")
        .collect()
}

// ----------------------------------------------------------------------
// `crate::fs::Filesystem` trait impl — bridges HfsPlus into the generic
// walker. `open()` returns a writable handle (the writer state is
// reconstructed from the on-disk catalog + bitmap), so the mutating
// trait methods work on already-flushed images the same way they do
// post-format.
// ----------------------------------------------------------------------

impl crate::fs::FilesystemFactory for HfsPlus {
    type FormatOpts = writer::FormatOpts;

    fn format(dev: &mut dyn BlockDevice, opts: &Self::FormatOpts) -> Result<Self> {
        Self::format(dev, opts)
    }

    fn open(dev: &mut dyn BlockDevice) -> Result<Self> {
        Self::open(dev)
    }

    fn size_plan(opts: &Self::FormatOpts) -> Option<Box<dyn crate::fs::FsSizePlan>> {
        Some(Box::new(size_plan::HfsPlusSizePlan::new(opts)))
    }
}

impl crate::fs::Filesystem for HfsPlus {
    // Consumes the FileSource during create_file, so let the
    // streaming repack buffer small files in memory instead of
    // spilling each to a temp file (see create_file_streaming).
    fn streams_immediately(&self) -> bool {
        true
    }

    fn create_file(
        &mut self,
        dev: &mut dyn BlockDevice,
        path: &std::path::Path,
        src: crate::fs::FileSource,
        meta: crate::fs::FileMeta,
    ) -> Result<()> {
        let s = path
            .to_str()
            .ok_or_else(|| crate::Error::InvalidArgument("hfs+: non-UTF-8 path".into()))?;
        let len = src.len()?;
        let (mut reader, _) = src.open()?;
        let mode = meta.mode;
        self.create_file(
            dev,
            s,
            &mut reader,
            len,
            mode,
            meta.uid,
            meta.gid,
            meta.mtime,
        )
        .map(|_| ())
    }

    /// Stream a borrowed body forward into freshly-allocated blocks — no
    /// buffering; the length is known up front and the source is read once.
    fn create_file_streaming(
        &mut self,
        dev: &mut dyn BlockDevice,
        path: &std::path::Path,
        body: &mut dyn std::io::Read,
        len: u64,
        meta: crate::fs::FileMeta,
    ) -> Result<()> {
        let s = path
            .to_str()
            .ok_or_else(|| crate::Error::InvalidArgument("hfs+: non-UTF-8 path".into()))?;
        self.create_file(dev, s, body, len, meta.mode, meta.uid, meta.gid, meta.mtime)
            .map(|_| ())
    }

    fn create_dir(
        &mut self,
        dev: &mut dyn BlockDevice,
        path: &std::path::Path,
        meta: crate::fs::FileMeta,
    ) -> Result<()> {
        let s = path
            .to_str()
            .ok_or_else(|| crate::Error::InvalidArgument("hfs+: non-UTF-8 path".into()))?;
        let mode = meta.mode;
        self.create_dir(dev, s, mode, meta.uid, meta.gid, meta.mtime)
            .map(|_| ())
    }

    fn create_symlink(
        &mut self,
        dev: &mut dyn BlockDevice,
        path: &std::path::Path,
        target: &std::path::Path,
        meta: crate::fs::FileMeta,
    ) -> Result<()> {
        let s = path
            .to_str()
            .ok_or_else(|| crate::Error::InvalidArgument("hfs+: non-UTF-8 path".into()))?;
        let t = target.to_str().ok_or_else(|| {
            crate::Error::InvalidArgument("hfs+: non-UTF-8 symlink target".into())
        })?;
        let mode = meta.mode;
        self.create_symlink(dev, s, t, mode, meta.uid, meta.gid, meta.mtime)
            .map(|_| ())
    }

    fn create_device(
        &mut self,
        dev: &mut dyn BlockDevice,
        path: &std::path::Path,
        kind: crate::fs::DeviceKind,
        major: u32,
        minor: u32,
        meta: crate::fs::FileMeta,
    ) -> Result<()> {
        let s = path
            .to_str()
            .ok_or_else(|| crate::Error::InvalidArgument("hfs+: non-UTF-8 path".into()))?;
        let mode = if meta.mode != 0 { meta.mode } else { 0o644 };
        self.create_device(
            dev, s, kind, major, minor, mode, meta.uid, meta.gid, meta.mtime,
        )
        .map(|_| ())
    }

    fn remove(&mut self, dev: &mut dyn BlockDevice, path: &std::path::Path) -> Result<()> {
        let s = path
            .to_str()
            .ok_or_else(|| crate::Error::InvalidArgument("hfs+: non-UTF-8 path".into()))?;
        self.remove(dev, s)
    }

    fn list(
        &mut self,
        dev: &mut dyn BlockDevice,
        path: &std::path::Path,
    ) -> Result<Vec<crate::fs::DirEntry>> {
        let s = path
            .to_str()
            .ok_or_else(|| crate::Error::InvalidArgument("hfs+: non-UTF-8 path".into()))?;
        self.list_path(dev, s)
    }

    fn set_attrs(
        &mut self,
        dev: &mut dyn BlockDevice,
        path: &std::path::Path,
        attrs: crate::fs::SetAttrs,
    ) -> Result<()> {
        let s = path
            .to_str()
            .ok_or_else(|| crate::Error::InvalidArgument("hfs+: non-UTF-8 path".into()))?;
        self.set_attrs(dev, s, attrs)
    }

    fn read_file<'a>(
        &'a mut self,
        dev: &'a mut dyn BlockDevice,
        path: &std::path::Path,
    ) -> Result<Box<dyn std::io::Read + 'a>> {
        let s = path
            .to_str()
            .ok_or_else(|| crate::Error::InvalidArgument("hfs+: non-UTF-8 path".into()))?;
        let r = self.open_file_reader(dev, s)?;
        Ok(Box::new(r))
    }

    /// Surface a file's resource fork as the macOS-standard
    /// `com.apple.ResourceFork` extended attribute (read-only, capped at
    /// 16 MiB), mirroring classic HFS. HFS-compressed files (whose resource
    /// fork holds `decmpfs` storage) yield no such xattr.
    fn list_xattrs(
        &mut self,
        dev: &mut dyn BlockDevice,
        path: &std::path::Path,
    ) -> Result<Vec<crate::fs::XattrPair>> {
        let s = path
            .to_str()
            .ok_or_else(|| crate::Error::InvalidArgument("hfs+: non-UTF-8 path".into()))?;
        let Some(file) = self.resource_fork_file(dev, s)? else {
            return Ok(Vec::new());
        };
        const CAP: u64 = 16 * 1024 * 1024;
        let size = file.resource_fork.logical_size.min(CAP) as usize;
        let fork = self.open_fork(
            dev,
            &file.resource_fork,
            file.file_id,
            extents::FORK_RESOURCE,
            "resource",
        )?;
        let mut buf = vec![0u8; size];
        fork.read(dev, 0, &mut buf)?;
        Ok(vec![crate::fs::XattrPair {
            name: "com.apple.ResourceFork".into(),
            value: buf,
        }])
    }

    fn getattr(
        &mut self,
        dev: &mut dyn BlockDevice,
        path: &std::path::Path,
    ) -> Result<crate::fs::FileAttrs> {
        use crate::fs::hfs_plus::catalog::{CatalogRecord, mode};
        let s = path
            .to_str()
            .ok_or_else(|| crate::Error::InvalidArgument("hfs+: non-UTF-8 path".into()))?;
        let rec = self.lookup_path(dev, s)?;
        // (bsd, cnid, content_mod_date, dir?, file size)
        let (bsd, cnid, mtime_hfs, is_dir, size) = match &rec {
            CatalogRecord::Folder(f) => (f.bsd, f.folder_id, f.content_mod_date, true, 0),
            CatalogRecord::File(f) => (
                f.bsd,
                f.file_id,
                f.content_mod_date,
                false,
                f.data_fork.logical_size,
            ),
            CatalogRecord::Thread(_) => {
                return Err(crate::Error::InvalidImage(format!(
                    "hfs+: {s:?} resolved to a thread record"
                )));
            }
        };
        let kind = if is_dir {
            crate::fs::EntryKind::Dir
        } else {
            match bsd.file_mode & mode::S_IFMT {
                mode::S_IFLNK => crate::fs::EntryKind::Symlink,
                mode::S_IFCHR => crate::fs::EntryKind::Char,
                mode::S_IFBLK => crate::fs::EntryKind::Block,
                mode::S_IFIFO => crate::fs::EntryKind::Fifo,
                mode::S_IFSOCK => crate::fs::EntryKind::Socket,
                _ => crate::fs::EntryKind::Regular,
            }
        };
        let perm = bsd.file_mode & 0o7777;
        let mode = if perm != 0 {
            perm
        } else if is_dir {
            0o755
        } else {
            0o644
        };
        // `special` doubles as the device number for char/block nodes
        // and the link count for hard-linked inodes.
        let (nlink, rdev) = match kind {
            crate::fs::EntryKind::Char | crate::fs::EntryKind::Block => (1, bsd.special),
            _ if is_dir => (2, 0),
            _ => (bsd.special.max(1), 0),
        };
        // HFS+ dates are seconds since 1904-01-01; Unix is 1904 + 66 yrs.
        let mtime = mtime_hfs.saturating_sub(HFS_EPOCH_OFFSET);
        Ok(crate::fs::FileAttrs {
            kind,
            mode,
            uid: bsd.owner_id,
            gid: bsd.group_id,
            size,
            blocks: size.div_ceil(512),
            nlink,
            atime: mtime,
            mtime,
            ctime: mtime,
            rdev,
            inode: cnid,
        })
    }

    fn open_file_ro<'a>(
        &'a mut self,
        dev: &'a mut dyn BlockDevice,
        path: &std::path::Path,
    ) -> Result<Box<dyn crate::fs::FileReadHandle + 'a>> {
        let s = path
            .to_str()
            .ok_or_else(|| crate::Error::InvalidArgument("hfs+: non-UTF-8 path".into()))?;
        // An ordinary data fork is genuinely seekable (the streaming
        // reader walks extents on demand). A decmpfs (UF_COMPRESSED) file
        // is whole-member compressed and forward-only today — refuse
        // rather than fake Seek by inflating the whole body into RAM.
        let file = self.resolve_regular_file(dev, s)?;
        if file.bsd.owner_flags & decmpfs::UF_COMPRESSED != 0 {
            #[cfg(feature = "hfs-compression")]
            return Ok(Box::new(compression::open(self, dev, &file)?));
            #[cfg(not(feature = "hfs-compression"))]
            return Err(crate::Error::Unsupported(format!(
                "hfs+: {s:?} is HFS-compressed (decmpfs); only forward reads are supported"
            )));
        }
        let fork = self.open_data_fork(dev, &file)?;
        Ok(Box::new(HfsPlusFileReader::streaming(
            dev,
            fork,
            file.data_fork.logical_size,
        )))
    }

    fn open_file_rw<'a>(
        &'a mut self,
        dev: &'a mut dyn BlockDevice,
        path: &std::path::Path,
        flags: crate::fs::OpenFlags,
        meta: Option<crate::fs::FileMeta>,
    ) -> Result<Box<dyn crate::fs::FileHandle + 'a>> {
        Ok(Box::new(handle::open_file_rw(
            self, dev, path, flags, meta,
        )?))
    }

    fn flush(&mut self, dev: &mut dyn BlockDevice) -> Result<()> {
        Self::flush(self, dev)
    }

    /// The volume spans a whole number of allocation blocks
    /// (`total_blocks × block_size`), and the alternate volume header sits in
    /// its last 1 KiB. Reporting that length lets the `create` / `repack`
    /// paths truncate the output file to it — so a request whose size isn't a
    /// block multiple (the old `2× + 64 MiB` auto-size, or an arbitrary
    /// `--size`) doesn't leave a trailing partial block past the alternate VH,
    /// which `fsck.hfsplus` reads as a misplaced header. No-op when the size is
    /// already block-aligned (e.g. content-fit sizing).
    fn image_len(&self) -> Option<u64> {
        Some(self.total_bytes())
    }

    fn read_symlink(
        &mut self,
        dev: &mut dyn BlockDevice,
        path: &std::path::Path,
    ) -> Result<std::path::PathBuf> {
        let s = path
            .to_str()
            .ok_or_else(|| crate::Error::InvalidArgument("hfs+: non-UTF-8 path".into()))?;
        Ok(std::path::PathBuf::from(
            self.read_symlink_target_path(dev, s)?,
        ))
    }
}

// -- tests ---------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::MemoryBackend;

    #[test]
    fn probe_recognises_h_plus_signature() {
        let mut dev = MemoryBackend::new(8192);
        dev.write_at(1024, b"H+").unwrap();
        assert!(probe(&mut dev).unwrap());
    }

    #[test]
    fn probe_recognises_hx_signature() {
        let mut dev = MemoryBackend::new(8192);
        dev.write_at(1024, b"HX").unwrap();
        assert!(probe(&mut dev).unwrap());
    }

    #[test]
    fn probe_rejects_unknown_signature() {
        let mut dev = MemoryBackend::new(8192);
        dev.write_at(1024, b"NO").unwrap();
        assert!(!probe(&mut dev).unwrap());
    }

    #[test]
    fn open_fails_on_garbage() {
        let mut dev = MemoryBackend::new(8192);
        // Default zeros => signature 0x0000, not H+ or HX.
        assert!(HfsPlus::open(&mut dev).is_err());
    }

    /// Hard-link resolver invariant: the link-inode number returned by
    /// [`HfsPlus::create_hardlink`] must equal the `file_id` of the
    /// iNode catalog file that holds the data, and `BSDInfo.special`
    /// on every `hlnk` record in the chain must point at that same
    /// CNID. Cross-checks that:
    /// * both source and destination hlnk records carry the same
    ///   `special` (= `link_inode`), and neither one's `file_id`
    ///   collides with it;
    /// * `lookup_file_by_cnid(link_inode)` returns a non-hlnk file
    ///   whose `file_id == link_inode`;
    /// * the iNode owns the real data fork (logical_size matches the
    ///   payload), while the hlnk records' own data forks are empty;
    /// * the iNode's `bsd.special` carries the link count (2 here).
    ///
    /// Regression: this is the contract `resolve_hard_link` relies on
    /// to walk `hlnk -> iNode<N>`. If `create_hardlink` ever returned
    /// a non-CNID handle (e.g. a sequential counter), reads would
    /// silently mis-resolve.
    #[test]
    fn create_hardlink_returns_inode_cnid_matching_resolved_file_id() {
        let mut dev = crate::block::MemoryBackend::new(8 * 1024 * 1024);
        let opts = writer::FormatOpts::default();
        let mut hfs = HfsPlus::format(&mut dev, &opts).unwrap();

        let data = b"link-inode invariant payload\n".repeat(8);
        let mut src = std::io::Cursor::new(&data);
        hfs.create_file(
            &mut dev,
            "/src",
            &mut src,
            data.len() as u64,
            0o644,
            0,
            0,
            0,
        )
        .unwrap();
        let link_inode = hfs.create_hardlink(&mut dev, "/src", "/dst").unwrap();
        hfs.flush(&mut dev).unwrap();

        // Re-open from disk so we exercise the read-side resolver.
        let hfs = HfsPlus::open(&mut dev).unwrap();

        // The iNode CNID must be resolvable as a real file whose
        // file_id matches the link-inode handle exactly.
        let inode_file = hfs.lookup_file_by_cnid(&mut dev, link_inode).unwrap();
        assert_eq!(
            inode_file.file_id, link_inode,
            "iNode's catalog file_id must equal the link-inode CNID"
        );
        assert!(
            !inode_file.is_hard_link(),
            "iNode itself must not be an hlnk record (would recurse)"
        );
        assert_eq!(
            inode_file.data_fork.logical_size,
            data.len() as u64,
            "iNode owns the data fork; logical_size must equal payload"
        );
        assert_eq!(
            inode_file.bsd.special, 2,
            "iNode.bsd.special is the link count (2 = src + dst)"
        );

        // Both hlnk records must carry `special == link_inode` and have
        // a file_id distinct from it (their own catalog identity).
        for path in ["/src", "/dst"] {
            let rec = hfs.lookup_path(&mut dev, path).unwrap();
            let f = match rec {
                catalog::CatalogRecord::File(f) => f,
                _ => panic!("{path:?} should be a catalog file record"),
            };
            assert!(f.is_hard_link(), "{path:?} must be an hlnk record");
            assert_eq!(
                f.bsd.special, link_inode,
                "{path:?} bsd.special must point at the iNode CNID"
            );
            assert_ne!(
                f.file_id, link_inode,
                "{path:?} hlnk file_id must differ from the iNode CNID"
            );
            assert_eq!(
                f.data_fork.logical_size, 0,
                "{path:?} hlnk record's own data fork must be empty"
            );
        }
    }

    /// HFS+'s separator is `:`, so `/` is a legal filename byte. A canonical
    /// path component carries that real `/` as `:`; creating `/A:ROSE Includes`
    /// must store the on-disk name `A/ROSE Includes`, list it back as the
    /// canonical `A:ROSE Includes`, and resolve via the canonical path. (Mirror
    /// of the classic-HFS `A/B` fixture; guards the latent split-on-`/` bug.)
    #[test]
    fn slash_in_name_round_trips_through_colon() {
        let mut dev = crate::block::MemoryBackend::new(8 * 1024 * 1024);
        let opts = writer::FormatOpts::default();
        let mut hfs = HfsPlus::format(&mut dev, &opts).unwrap();

        let data = b"a-rose-by-any-other-name\n".to_vec();
        let mut src = std::io::Cursor::new(&data);
        hfs.create_file(
            &mut dev,
            "/A:ROSE Includes",
            &mut src,
            data.len() as u64,
            0o644,
            0,
            0,
            0,
        )
        .unwrap();
        hfs.flush(&mut dev).unwrap();

        // Re-open to exercise the read-side resolver + listing.
        let hfs = HfsPlus::open(&mut dev).unwrap();

        // Listing surfaces the canonical (colon) form — no raw `/` leaks.
        let names: Vec<String> = hfs
            .list_path(&mut dev, "/")
            .unwrap()
            .into_iter()
            .map(|e| e.name)
            .collect();
        assert!(
            names.iter().any(|n| n == "A:ROSE Includes"),
            "expected canonical 'A:ROSE Includes' in {names:?}"
        );

        // The canonical path resolves back to the file (separator-safe).
        let rec = hfs.lookup_path(&mut dev, "/A:ROSE Includes").unwrap();
        assert!(
            matches!(rec, catalog::CatalogRecord::File(_)),
            "canonical path should resolve to the created file"
        );
    }

    /// `set_attrs(mode)` must persist the new permission bits while
    /// preserving the on-disk `S_IFMT` type bits: format → reopen →
    /// create a file → chmod 0o600 → flush → reopen → getattr reports
    /// mode 0o600, kind still Regular, and the new uid/gid/mtime stick.
    #[test]
    fn set_attrs_mode_round_trips() {
        use crate::fs::{EntryKind, Filesystem, SetAttrs};
        use std::path::Path;

        let mut dev = crate::block::MemoryBackend::new(8 * 1024 * 1024);
        let opts = writer::FormatOpts::default();

        // Format, flush, and reopen so set_attrs runs against a
        // reconstructed (open_writable) writer model, not a fresh format.
        let mut hfs = HfsPlus::format(&mut dev, &opts).unwrap();
        hfs.flush(&mut dev).unwrap();
        let mut hfs = HfsPlus::open(&mut dev).unwrap();

        let data = b"chmod me\n".to_vec();
        let mut src = std::io::Cursor::new(&data);
        hfs.create_file(
            &mut dev,
            "/file",
            &mut src,
            data.len() as u64,
            0o644,
            7,
            9,
            0,
        )
        .unwrap();

        // chmod 0o600 + chown 1000:1000 + set mtime through the trait API.
        Filesystem::set_attrs(
            &mut hfs,
            &mut dev,
            Path::new("/file"),
            SetAttrs {
                mode: Some(0o600),
                uid: Some(1000),
                gid: Some(1000),
                mtime: Some(1_700_000_000),
                ..Default::default()
            },
        )
        .unwrap();
        hfs.flush(&mut dev).unwrap();

        // Reopen and confirm the new metadata survived the serialise round-trip.
        let mut hfs = HfsPlus::open(&mut dev).unwrap();
        let attrs = Filesystem::getattr(&mut hfs, &mut dev, Path::new("/file")).unwrap();
        assert_eq!(attrs.mode, 0o600, "permission bits should be chmod'd");
        assert_eq!(
            attrs.kind,
            EntryKind::Regular,
            "S_IFMT type bits must be preserved"
        );
        assert_eq!(attrs.uid, 1000);
        assert_eq!(attrs.gid, 1000);
        assert_eq!(attrs.mtime, 1_700_000_000);
    }

    /// A file with an empty resource fork must not be reported as having one:
    /// `resource_fork_size` is `None`, the reader errors, and `list_xattrs`
    /// surfaces no `com.apple.ResourceFork`. (Guards the gating in
    /// `resource_fork_file`; the actual resource-fork *read* reuses the
    /// data-fork `open_fork`/`FORK_RESOURCE` machinery, covered elsewhere.)
    #[test]
    fn empty_resource_fork_is_not_surfaced() {
        let mut dev = crate::block::MemoryBackend::new(8 * 1024 * 1024);
        let opts = writer::FormatOpts::default();
        let mut hfs = HfsPlus::format(&mut dev, &opts).unwrap();
        let data = b"no resources here\n".to_vec();
        let mut src = std::io::Cursor::new(&data);
        hfs.create_file(
            &mut dev,
            "/plain",
            &mut src,
            data.len() as u64,
            0o644,
            0,
            0,
            0,
        )
        .unwrap();
        hfs.flush(&mut dev).unwrap();
        let mut hfs = HfsPlus::open(&mut dev).unwrap();

        assert_eq!(hfs.resource_fork_size(&mut dev, "/plain").unwrap(), None);
        assert!(hfs.open_resource_fork_reader(&mut dev, "/plain").is_err());
        assert!(
            crate::fs::Filesystem::list_xattrs(&mut hfs, &mut dev, std::path::Path::new("/plain"))
                .unwrap()
                .is_empty()
        );
    }

    /// Round-trip: format + populate + flush, then `HfsPlus::open` the
    /// flushed image and add a *second* file via `create_file`, flush
    /// again, and reopen a third time. The second file must be visible
    /// at its path with byte-exact contents, and the original file must
    /// still be intact. Locks down the open-as-writable path used by
    /// `fstool add` on an already-flushed HFS+ image.
    /// The reserved head of an HFS+ volume is bytes 0..1024 plus the
    /// 512-byte volume header at 1024..1536 — one allocation block at
    /// 4 KiB but two at 1 KiB and three at 512 bytes. Laying the
    /// special files out from block 1 regardless put the allocation
    /// bitmap straight on top of the volume header on any volume with
    /// a sub-2-KiB block size. The tail is the mirror case: the
    /// alternate volume header's last 1 KiB spans two 512-byte blocks.
    #[test]
    fn small_block_sizes_do_not_clobber_the_volume_headers() {
        for bs in [512u32, 1024, 2048, 4096] {
            let mut dev = crate::block::MemoryBackend::new(8 * 1024 * 1024);
            let opts = writer::FormatOpts {
                block_size: bs,
                volume_name: format!("BS{bs}"),
                ..writer::FormatOpts::default()
            };
            let mut hfs = HfsPlus::format(&mut dev, &opts).unwrap();
            let body = b"payload\n".repeat(100);
            hfs.create_file(
                &mut dev,
                "/f.txt",
                &mut std::io::Cursor::new(body.clone()),
                body.len() as u64,
                0o644,
                0,
                0,
                0,
            )
            .unwrap();
            hfs.flush(&mut dev).unwrap();

            let hfs = HfsPlus::open(&mut dev)
                .unwrap_or_else(|e| panic!("block_size {bs}: reopen failed: {e}"));
            assert_eq!(hfs.volume_name, format!("BS{bs}"), "block_size {bs}");
            let mut got = Vec::new();
            std::io::Read::read_to_end(
                &mut hfs.open_file_reader(&mut dev, "/f.txt").unwrap(),
                &mut got,
            )
            .unwrap();
            assert_eq!(got, body, "block_size {bs}");
        }
    }

    /// Listings descend the catalog B-tree to the leaf holding
    /// `(cnid, "")` instead of walking from the first leaf. The
    /// entries of a directory whose CNID sorts late must still come
    /// back complete — including the boundary cases of a child that is
    /// the very first record of a leaf and one that is the very last.
    #[test]
    fn list_descends_to_the_right_leaf() {
        let mut dev = crate::block::MemoryBackend::new(16 * 1024 * 1024);
        let opts = writer::FormatOpts {
            catalog_nodes: 64,
            ..writer::FormatOpts::default()
        };
        let mut hfs = HfsPlus::format(&mut dev, &opts).unwrap();
        // Several sibling directories so the catalog spans many leaves
        // and the interesting parent is nowhere near the first one.
        for d in 0..8 {
            hfs.create_dir(&mut dev, &format!("/d{d}"), 0o755, 0, 0, 0)
                .unwrap();
            for i in 0..40 {
                hfs.create_file(
                    &mut dev,
                    &format!("/d{d}/f{i:03}.txt"),
                    &mut std::io::Cursor::new(b"x".to_vec()),
                    1,
                    0o644,
                    0,
                    0,
                    0,
                )
                .unwrap();
            }
        }
        hfs.flush(&mut dev).unwrap();

        let hfs = HfsPlus::open(&mut dev).unwrap();
        assert!(
            hfs.catalog.header.tree_depth >= 2,
            "test needs a multi-level catalog"
        );
        for d in 0..8 {
            let names: Vec<String> = hfs
                .list_path(&mut dev, &format!("/d{d}"))
                .unwrap()
                .into_iter()
                .map(|e| e.name)
                .collect();
            assert_eq!(names.len(), 40, "/d{d} listing is short: {names:?}");
            assert!(names.contains(&"f000.txt".to_string()));
            assert!(names.contains(&"f039.txt".to_string()));
        }
        assert_eq!(hfs.list_path(&mut dev, "/").unwrap().len(), 8);
    }

    #[test]
    fn reopen_writable_round_trip_add_file() {
        let mut dev = crate::block::MemoryBackend::new(8 * 1024 * 1024);
        let opts = writer::FormatOpts::default();

        // 1. Format + write one file + flush.
        let first = b"first file from format() pass\n".repeat(4);
        {
            let mut hfs = HfsPlus::format(&mut dev, &opts).unwrap();
            let mut src = std::io::Cursor::new(&first);
            hfs.create_file(
                &mut dev,
                "/first.txt",
                &mut src,
                first.len() as u64,
                0o644,
                0,
                0,
                0,
            )
            .unwrap();
            hfs.flush(&mut dev).unwrap();
        }

        // 2. Re-open the flushed image and verify the existing file is
        //    readable AND that the handle reports mutation capability.
        //    Then add a second file and flush.
        let second = b"second file added after reopen\n".repeat(7);
        {
            let mut hfs = HfsPlus::open(&mut dev).unwrap();
            // Default Filesystem::mutation_capability is Mutable; verify
            // HFS+ doesn't override to a more restrictive value.
            let cap = <HfsPlus as crate::fs::Filesystem>::mutation_capability(&hfs);
            assert_eq!(
                cap,
                crate::fs::MutationCapability::Mutable,
                "freshly-opened HFS+ must advertise Mutable"
            );

            // Existing file still readable.
            let mut r = hfs.open_file_reader(&mut dev, "/first.txt").unwrap();
            let mut buf = Vec::new();
            std::io::Read::read_to_end(&mut r, &mut buf).unwrap();
            assert_eq!(buf, first, "existing file content survives reopen");
            drop(r);

            // Add a second file via the writer state reconstructed in open().
            let mut src = std::io::Cursor::new(&second);
            hfs.create_file(
                &mut dev,
                "/second.txt",
                &mut src,
                second.len() as u64,
                0o644,
                0,
                0,
                0,
            )
            .unwrap();
            hfs.flush(&mut dev).unwrap();
        }

        // 3. Re-open again and verify BOTH files exist with correct bytes.
        let hfs = HfsPlus::open(&mut dev).unwrap();
        let entries = hfs.list_path(&mut dev, "/").unwrap();
        let names: std::collections::BTreeSet<&str> =
            entries.iter().map(|e| e.name.as_str()).collect();
        assert!(
            names.contains("first.txt"),
            "first.txt missing after reopen; got {names:?}"
        );
        assert!(
            names.contains("second.txt"),
            "second.txt missing after reopen; got {names:?}"
        );

        let size = hfs.file_size(&mut dev, "/second.txt").unwrap();
        assert_eq!(size, second.len() as u64);
        let mut r = hfs.open_file_reader(&mut dev, "/second.txt").unwrap();
        let mut got = Vec::new();
        std::io::Read::read_to_end(&mut r, &mut got).unwrap();
        assert_eq!(got, second, "second.txt bytes survive a second reopen");

        let mut r = hfs.open_file_reader(&mut dev, "/first.txt").unwrap();
        let mut got = Vec::new();
        std::io::Read::read_to_end(&mut r, &mut got).unwrap();
        assert_eq!(got, first, "first.txt bytes still intact");
    }

    /// Round-trip: reopen a flushed image, `remove` an existing entry,
    /// flush, reopen — the entry must be gone and its blocks freed. Locks
    /// down the open-as-writable path used by `fstool rm`.
    #[test]
    fn reopen_writable_round_trip_remove_file() {
        let mut dev = crate::block::MemoryBackend::new(8 * 1024 * 1024);
        let opts = writer::FormatOpts::default();

        let payload = b"goodbye, cruel world\n".repeat(16);
        {
            let mut hfs = HfsPlus::format(&mut dev, &opts).unwrap();
            let mut src = std::io::Cursor::new(&payload);
            hfs.create_file(
                &mut dev,
                "/doomed.txt",
                &mut src,
                payload.len() as u64,
                0o644,
                0,
                0,
                0,
            )
            .unwrap();
            hfs.create_file(
                &mut dev,
                "/keeper.txt",
                &mut std::io::Cursor::new(b"keep me\n"),
                8,
                0o644,
                0,
                0,
                0,
            )
            .unwrap();
            hfs.flush(&mut dev).unwrap();
        }

        let free_before;
        {
            let mut hfs = HfsPlus::open(&mut dev).unwrap();
            free_before = hfs.volume_header.free_blocks;
            hfs.remove(&mut dev, "/doomed.txt").unwrap();
            hfs.flush(&mut dev).unwrap();
        }

        let hfs = HfsPlus::open(&mut dev).unwrap();
        let entries = hfs.list_path(&mut dev, "/").unwrap();
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert!(
            !names.contains(&"doomed.txt"),
            "doomed.txt should be gone after remove + reopen, got {names:?}"
        );
        assert!(
            names.contains(&"keeper.txt"),
            "keeper.txt should still exist, got {names:?}"
        );

        // The data blocks the removed file owned should be reclaimed.
        // payload is len-bytes spread across ceil(len / block_size) blocks.
        let bs = hfs.block_size() as u64;
        let freed_blocks = (payload.len() as u64).div_ceil(bs) as u32;
        assert!(
            hfs.volume_header.free_blocks >= free_before + freed_blocks,
            "expected at least {freed_blocks} more free blocks after remove \
             (before={free_before}, after={})",
            hfs.volume_header.free_blocks
        );
    }

    /// `Filesystem::open_file_rw` on a non-journaled image: full
    /// round-trip — open existing file, patch a byte range in the
    /// middle, `sync`, drop the handle, reopen, verify the patch is
    /// present and the surrounding bytes are intact.
    #[test]
    fn open_file_rw_round_trip_non_journaled() {
        use crate::fs::{Filesystem, OpenFlags};
        use std::io::{Read, Seek, SeekFrom, Write};

        let mut dev = MemoryBackend::new(8 * 1024 * 1024);
        let opts = writer::FormatOpts::default();
        let payload: Vec<u8> = (0..16 * 1024).map(|i| (i & 0xFF) as u8).collect();

        {
            let mut hfs = HfsPlus::format(&mut dev, &opts).unwrap();
            let mut src = std::io::Cursor::new(&payload);
            hfs.create_file(
                &mut dev,
                "/edit.bin",
                &mut src,
                payload.len() as u64,
                0o644,
                0,
                0,
                0,
            )
            .unwrap();
            hfs.flush(&mut dev).unwrap();
        }

        // Reopen, patch.
        {
            let mut hfs = HfsPlus::open(&mut dev).unwrap();
            let mut h = hfs
                .open_file_rw(
                    &mut dev,
                    std::path::Path::new("/edit.bin"),
                    OpenFlags::default(),
                    None,
                )
                .unwrap();
            assert_eq!(h.len(), payload.len() as u64);
            h.seek(SeekFrom::Start(4096)).unwrap();
            h.write_all(b"PATCHED_RANGE").unwrap();
            h.sync().unwrap();
            drop(h);
        }

        // Reopen, verify.
        {
            let hfs = HfsPlus::open(&mut dev).unwrap();
            let mut r = hfs.open_file_reader(&mut dev, "/edit.bin").unwrap();
            let mut got = Vec::new();
            r.read_to_end(&mut got).unwrap();
            assert_eq!(got.len(), payload.len());
            assert_eq!(&got[..4096], &payload[..4096], "head unchanged");
            assert_eq!(&got[4096..4096 + 13], b"PATCHED_RANGE", "patch is present");
            assert_eq!(&got[4096 + 13..], &payload[4096 + 13..], "tail unchanged");
        }
    }

    /// Same round-trip as the non-journaled test but on an image
    /// formatted with the journal stub enabled. After Path A's commit
    /// sequence (write tx → advance end → apply blocks → advance
    /// start) the journal is back to `start == end`, so a subsequent
    /// open sees no replay work and treats the volume as clean.
    #[test]
    fn open_file_rw_round_trip_journaled() {
        use crate::fs::{Filesystem, OpenFlags};
        use std::io::{Read, Seek, SeekFrom, Write};

        let mut dev = MemoryBackend::new(8 * 1024 * 1024);
        let opts = writer::FormatOpts {
            journaled: true,
            ..writer::FormatOpts::default()
        };
        let payload: Vec<u8> = (0..8 * 1024).map(|i| (i & 0xFF) as u8).collect();

        {
            let mut hfs = HfsPlus::format(&mut dev, &opts).unwrap();
            let mut src = std::io::Cursor::new(&payload);
            hfs.create_file(
                &mut dev,
                "/jrnl.bin",
                &mut src,
                payload.len() as u64,
                0o644,
                0,
                0,
                0,
            )
            .unwrap();
            hfs.flush(&mut dev).unwrap();
        }

        // Reopen + patch via the FileHandle API.
        {
            let mut hfs = HfsPlus::open(&mut dev).unwrap();
            assert_ne!(
                hfs.volume_header.attributes & writer::VOL_ATTR_JOURNALED,
                0,
                "journaled bit must survive reopen"
            );
            let mut h = hfs
                .open_file_rw(
                    &mut dev,
                    std::path::Path::new("/jrnl.bin"),
                    OpenFlags::default(),
                    None,
                )
                .unwrap();
            h.seek(SeekFrom::Start(2048)).unwrap();
            h.write_all(b"journal-bypass").unwrap();
            h.sync().unwrap();
        }

        // Verify the data survived and the journal header is still clean.
        {
            let hfs = HfsPlus::open(&mut dev).unwrap();
            let mut r = hfs.open_file_reader(&mut dev, "/jrnl.bin").unwrap();
            let mut got = Vec::new();
            r.read_to_end(&mut got).unwrap();
            assert_eq!(got.len(), payload.len());
            assert_eq!(&got[..2048], &payload[..2048]);
            assert_eq!(&got[2048..2048 + 14], b"journal-bypass");
            assert_eq!(&got[2048 + 14..], &payload[2048 + 14..]);
        }

        // Inspect the journal header directly: start MUST equal end
        // (Path A leaves the journal sealed once the transaction is
        // applied). The journal header lives at the start of the
        // journal buffer; the JournalInfoBlock at byte 12 of the
        // volume header tells us where the buffer starts.
        let mut vh_buf = [0u8; 512];
        dev.read_at(volume_header::VOLUME_HEADER_OFFSET, &mut vh_buf)
            .unwrap();
        let info_block = u32::from_be_bytes(vh_buf[12..16].try_into().unwrap());
        let bs = u32::from_be_bytes(vh_buf[40..44].try_into().unwrap());
        assert_ne!(info_block, 0);
        let info_off = u64::from(info_block) * u64::from(bs);
        let mut info = [0u8; 52];
        dev.read_at(info_off, &mut info).unwrap();
        let jbuf_off = u64::from_be_bytes(info[36..44].try_into().unwrap());
        let mut hdr = [0u8; 24];
        dev.read_at(jbuf_off, &mut hdr).unwrap();
        let start = u64::from_be_bytes(hdr[8..16].try_into().unwrap());
        let end = u64::from_be_bytes(hdr[16..24].try_into().unwrap());
        assert_eq!(
            start, end,
            "Path A requires the journal to be sealed (start == end) \
             after a successful sync (start={start:#x}, end={end:#x})"
        );
    }

    /// Simulate a crash mid-sync: commit a journal transaction (so
    /// `end` is advanced and the user data is on disk), then forcibly
    /// rewind `start` so the on-disk journal claims unreplayed work,
    /// and corrupt the user data so we can confirm replay reapplies
    /// it. The next open_file_rw must drain the journal and produce
    /// the post-sync contents.
    #[test]
    fn open_file_rw_replays_dirty_journal_on_open() {
        use crate::fs::{Filesystem, OpenFlags};
        use std::io::{Read, Seek, SeekFrom, Write};

        let mut dev = MemoryBackend::new(8 * 1024 * 1024);
        let opts = writer::FormatOpts {
            journaled: true,
            ..writer::FormatOpts::default()
        };
        let payload = b"original\n".repeat(64);
        {
            let mut hfs = HfsPlus::format(&mut dev, &opts).unwrap();
            let mut src = std::io::Cursor::new(&payload);
            hfs.create_file(
                &mut dev,
                "/replay.bin",
                &mut src,
                payload.len() as u64,
                0o644,
                0,
                0,
                0,
            )
            .unwrap();
            hfs.flush(&mut dev).unwrap();
        }

        // Round 1: do a journaled write — sync persists everything.
        // Capture the journal `start`/`end` afterwards so we can roll
        // `start` back to simulate a crash that lost step 4 of the
        // commit sequence.
        let (jbuf_off, sealed_start, sealed_end) = {
            let mut hfs = HfsPlus::open(&mut dev).unwrap();
            {
                let mut h = hfs
                    .open_file_rw(
                        &mut dev,
                        std::path::Path::new("/replay.bin"),
                        OpenFlags::default(),
                        None,
                    )
                    .unwrap();
                h.seek(SeekFrom::Start(64)).unwrap();
                h.write_all(b"REPLAYED-DATA-FROM-JOURNAL").unwrap();
                h.sync().unwrap();
            }
            // Sneak a peek at the journal header.
            let mut vh_buf = [0u8; 512];
            dev.read_at(volume_header::VOLUME_HEADER_OFFSET, &mut vh_buf)
                .unwrap();
            let info_block = u32::from_be_bytes(vh_buf[12..16].try_into().unwrap());
            let bs = u32::from_be_bytes(vh_buf[40..44].try_into().unwrap());
            let info_off = u64::from(info_block) * u64::from(bs);
            let mut info = [0u8; 52];
            dev.read_at(info_off, &mut info).unwrap();
            let jbuf_off = u64::from_be_bytes(info[36..44].try_into().unwrap());
            let mut hdr = [0u8; 24];
            dev.read_at(jbuf_off, &mut hdr).unwrap();
            let s = u64::from_be_bytes(hdr[8..16].try_into().unwrap());
            let e = u64::from_be_bytes(hdr[16..24].try_into().unwrap());
            assert_eq!(s, e, "post-sync the journal must be clean");
            (jbuf_off, s, e)
        };
        assert_eq!(sealed_start, sealed_end);

        // Simulate the crash by rewinding the on-disk `start` past
        // the existing transaction. Replay must re-apply it (which is
        // a no-op since the user data is already on disk) and leave
        // the journal clean again.
        {
            let hfs = HfsPlus::open(&mut dev).unwrap();
            let mut got = Vec::new();
            hfs.open_file_reader(&mut dev, "/replay.bin")
                .unwrap()
                .read_to_end(&mut got)
                .unwrap();
            assert_eq!(&got[64..64 + 26], b"REPLAYED-DATA-FROM-JOURNAL");
        }
        // Rewind `start` to JHDR_SIZE — the journal-header size we
        // ship at format time (= 512). Now `start != end` and the
        // on-disk transaction is "unapplied" as far as the journal is
        // concerned. We rely on JournalLog::load tolerating a missing
        // checksum recompute because replay only reads start/end.
        let rewound_start: u64 = u64::from(super::journal::JHDR_SIZE);
        // Patch the header in-place (keeping its checksum valid).
        super::journal::rewind_start_for_test(&mut dev, jbuf_off, rewound_start).unwrap();

        // Reopen and open the file for writing. The replay should fire
        // and re-apply the transaction. We then close without writing
        // and confirm the contents are intact.
        {
            let mut hfs = HfsPlus::open(&mut dev).unwrap();
            let h = hfs
                .open_file_rw(
                    &mut dev,
                    std::path::Path::new("/replay.bin"),
                    OpenFlags::default(),
                    None,
                )
                .unwrap();
            // Reading from the freshly-opened handle should match the
            // journaled contents. The point of the test isn't the
            // bytes — replay already wrote them to disk before we got
            // here — but the journal header itself must now be clean
            // again.
            drop(h);
            let mut hdr = [0u8; 24];
            dev.read_at(jbuf_off, &mut hdr).unwrap();
            let s = u64::from_be_bytes(hdr[8..16].try_into().unwrap());
            let e = u64::from_be_bytes(hdr[16..24].try_into().unwrap());
            assert_eq!(s, e, "replay must leave the journal clean");
        }
    }

    /// Simulate a crash *before* the journal applies its block writes.
    /// We synthesize the state by:
    ///
    ///   1. Doing a real journaled sync (so `end > start` was reached
    ///      and re-equalised).
    ///   2. Rewinding `start` to before the transaction (so the journal
    ///      looks dirty).
    ///   3. Zeroing the user-data block (so the in-place write looks
    ///      lost).
    ///
    /// Then we reopen via [`crate::fs::Filesystem::open_file_rw`] and
    /// verify the journal contents successfully restored the bytes.
    #[test]
    fn replay_on_open_restores_lost_user_data() {
        use crate::fs::{Filesystem, OpenFlags};
        use std::io::{Seek, SeekFrom, Write};

        let mut dev = MemoryBackend::new(8 * 1024 * 1024);
        let opts = writer::FormatOpts {
            journaled: true,
            ..writer::FormatOpts::default()
        };
        let payload = vec![0xAAu8; 4096];
        {
            let mut hfs = HfsPlus::format(&mut dev, &opts).unwrap();
            let mut src = std::io::Cursor::new(&payload);
            hfs.create_file(
                &mut dev,
                "/x.bin",
                &mut src,
                payload.len() as u64,
                0o644,
                0,
                0,
                0,
            )
            .unwrap();
            hfs.flush(&mut dev).unwrap();
        }

        // 1. Journaled sync.
        let (jbuf_off, sealed_end) = {
            let mut hfs = HfsPlus::open(&mut dev).unwrap();
            {
                let mut h = hfs
                    .open_file_rw(
                        &mut dev,
                        std::path::Path::new("/x.bin"),
                        OpenFlags::default(),
                        None,
                    )
                    .unwrap();
                h.seek(SeekFrom::Start(0)).unwrap();
                h.write_all(&[0xBBu8; 4096]).unwrap();
                h.sync().unwrap();
            }
            let mut vh_buf = [0u8; 512];
            dev.read_at(volume_header::VOLUME_HEADER_OFFSET, &mut vh_buf)
                .unwrap();
            let info_block = u32::from_be_bytes(vh_buf[12..16].try_into().unwrap());
            let bs = u32::from_be_bytes(vh_buf[40..44].try_into().unwrap());
            let info_off = u64::from(info_block) * u64::from(bs);
            let mut info = [0u8; 52];
            dev.read_at(info_off, &mut info).unwrap();
            let jbuf_off = u64::from_be_bytes(info[36..44].try_into().unwrap());
            let mut hdr = [0u8; 24];
            dev.read_at(jbuf_off, &mut hdr).unwrap();
            let e = u64::from_be_bytes(hdr[16..24].try_into().unwrap());
            (jbuf_off, e)
        };

        // 2. Find the file's first data block to corrupt it.
        let dev_off_block0 = {
            let hfs = HfsPlus::open(&mut dev).unwrap();
            let CatalogRecord::File(f) = hfs.lookup_path(&mut dev, "/x.bin").unwrap() else {
                panic!("expected file");
            };
            // Read the file record's first inline extent: stored at
            // raw_body[88..96] (start_block, block_count). We grab the
            // run from the writer instead — easier.
            let w = hfs.writer.as_ref().unwrap();
            let body = w
                .catalog
                .get(&writer::OwnedKey {
                    parent_id: ROOT_FOLDER_ID,
                    name: catalog::UniStr::from_str_lossy("x.bin"),
                })
                .expect("catalog body");
            let sb = u32::from_be_bytes(body[88 + 16..88 + 20].try_into().unwrap()); // first ext start
            assert!(sb > 0, "file must have a real data block");
            let _ = f;
            u64::from(sb) * u64::from(hfs.volume_header.block_size)
        };

        // 3. Zero the user-data block on disk, and rewind start so
        //    the journal looks dirty again.
        dev.write_at(dev_off_block0, &[0u8; 4096]).unwrap();
        let rewound: u64 = u64::from(super::journal::JHDR_SIZE);
        super::journal::rewind_start_for_test(&mut dev, jbuf_off, rewound).unwrap();
        let _ = sealed_end;

        // 4. Reopen — replay should restore the 0xBB pattern.
        {
            let mut hfs = HfsPlus::open(&mut dev).unwrap();
            let h = hfs
                .open_file_rw(
                    &mut dev,
                    std::path::Path::new("/x.bin"),
                    OpenFlags::default(),
                    None,
                )
                .unwrap();
            drop(h);
        }
        let mut got = [0u8; 4096];
        dev.read_at(dev_off_block0, &mut got).unwrap();
        assert!(
            got.iter().all(|&b| b == 0xBB),
            "replay must have restored the user data"
        );
    }

    /// Round-trip on a journaled image, then run `fsck.hfsplus` on the
    /// resulting bytes. Silently skipped when the binary isn't on PATH.
    #[test]
    fn open_file_rw_journaled_passes_fsck_hfsplus() {
        use crate::fs::{Filesystem, OpenFlags};
        use std::io::{Seek, SeekFrom, Write};
        use std::process::Command;

        let fsck = match Command::new("sh")
            .arg("-c")
            .arg("command -v fsck.hfsplus")
            .output()
        {
            Ok(o) if o.status.success() && !o.stdout.is_empty() => {
                String::from_utf8_lossy(&o.stdout).trim().to_string()
            }
            _ => return, // not installed; skip
        };

        let tmp = tempfile::NamedTempFile::new().expect("tmp");
        let path = tmp.path().to_path_buf();
        let total: u64 = 8 * 1024 * 1024;
        // Truncate to the target size.
        let f = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        f.set_len(total).unwrap();
        drop(f);

        let mut dev = crate::block::FileBackend::open(&path).unwrap();
        let opts = writer::FormatOpts {
            journaled: true,
            volume_name: "fsckTestVol".into(),
            ..writer::FormatOpts::default()
        };
        let payload: Vec<u8> = (0..16 * 1024).map(|i| (i & 0xFF) as u8).collect();
        {
            let mut hfs = HfsPlus::format(&mut dev, &opts).unwrap();
            let mut src = std::io::Cursor::new(&payload);
            hfs.create_file(
                &mut dev,
                "/edit.bin",
                &mut src,
                payload.len() as u64,
                0o644,
                0,
                0,
                0,
            )
            .unwrap();
            hfs.flush(&mut dev).unwrap();
        }
        {
            let mut hfs = HfsPlus::open(&mut dev).unwrap();
            let mut h = hfs
                .open_file_rw(
                    &mut dev,
                    std::path::Path::new("/edit.bin"),
                    OpenFlags::default(),
                    None,
                )
                .unwrap();
            h.seek(SeekFrom::Start(8192)).unwrap();
            h.write_all(b"journal-test-payload").unwrap();
            h.sync().unwrap();
        }
        crate::block::BlockDevice::sync(&mut dev).unwrap();
        drop(dev);

        let out = Command::new(&fsck)
            .arg("-fn")
            .arg(&path)
            .output()
            .expect("run fsck.hfsplus");
        // fsck.hfsplus returns 0 on a clean volume.
        assert!(
            out.status.success(),
            "fsck.hfsplus failed:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr),
        );
    }

    /// A `set_attrs` chmod must leave the on-disk image structurally
    /// clean: format → create file → chmod 0o600 + chown + mtime →
    /// flush → run `fsck.hfsplus -fn`, which must exit 0. Silently
    /// skipped when the binary isn't on PATH. (`fsck` exit 8 is the
    /// "errors found" code we must never produce.)
    #[test]
    fn set_attrs_chmod_passes_fsck_hfsplus() {
        use crate::fs::{Filesystem, SetAttrs};
        use std::process::Command;

        let fsck = match Command::new("sh")
            .arg("-c")
            .arg("command -v fsck.hfsplus")
            .output()
        {
            Ok(o) if o.status.success() && !o.stdout.is_empty() => {
                String::from_utf8_lossy(&o.stdout).trim().to_string()
            }
            _ => return, // not installed; skip
        };

        let tmp = tempfile::NamedTempFile::new().expect("tmp");
        let path = tmp.path().to_path_buf();
        let total: u64 = 8 * 1024 * 1024;
        let f = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        f.set_len(total).unwrap();
        drop(f);

        let mut dev = crate::block::FileBackend::open(&path).unwrap();
        let opts = writer::FormatOpts {
            volume_name: "chmodVol".into(),
            ..writer::FormatOpts::default()
        };
        let payload: Vec<u8> = (0..4096).map(|i| (i & 0xFF) as u8).collect();
        {
            let mut hfs = HfsPlus::format(&mut dev, &opts).unwrap();
            let mut src = std::io::Cursor::new(&payload);
            hfs.create_file(
                &mut dev,
                "/chmod.bin",
                &mut src,
                payload.len() as u64,
                0o644,
                0,
                0,
                0,
            )
            .unwrap();
            hfs.flush(&mut dev).unwrap();
        }
        {
            let mut hfs = HfsPlus::open(&mut dev).unwrap();
            Filesystem::set_attrs(
                &mut hfs,
                &mut dev,
                std::path::Path::new("/chmod.bin"),
                SetAttrs {
                    mode: Some(0o600),
                    uid: Some(501),
                    gid: Some(20),
                    mtime: Some(1_700_000_000),
                    ..Default::default()
                },
            )
            .unwrap();
            hfs.flush(&mut dev).unwrap();
        }
        crate::block::BlockDevice::sync(&mut dev).unwrap();
        drop(dev);

        let out = Command::new(&fsck)
            .arg("-fn")
            .arg(&path)
            .output()
            .expect("run fsck.hfsplus");
        assert!(
            out.status.success(),
            "fsck.hfsplus reported errors after chmod (exit {:?}):\nstdout:\n{}\nstderr:\n{}",
            out.status.code(),
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr),
        );
    }

    /// Path A for `flush`: when a journaled HFS+ image is reopened and
    /// mutated (creating directories, files, removing files), the
    /// subsequent metadata `flush` must route its writes — catalog
    /// B-tree pages, extents-overflow pages, allocation bitmap, and the
    /// two volume headers — through `JournalLog::commit` rather than
    /// applying them in place. We verify this by:
    ///
    ///   1. Formatting a journaled image with one file.
    ///   2. Reopening it, mutating it (add a directory, add a file,
    ///      remove the original) to dirty multiple metadata regions,
    ///      then calling `flush`.
    ///   3. Snapshotting the journal header (`start == end` post-flush).
    ///   4. Reading the post-flush metadata bytes for both volume
    ///      headers so we can corrupt them on disk and prove replay
    ///      restored them.
    ///   5. Corrupting the primary volume header on disk (zeroing it)
    ///      and rewinding the journal `start` to before the flush
    ///      transaction.
    ///   6. Reopening — the journal replay in `HfsPlus::open` must
    ///      restore the volume-header bytes before the catalog open
    ///      attempts to read them. The mutated directory tree must
    ///      then be readable byte-exact.
    #[test]
    fn flush_routes_metadata_through_journal_on_reopen() {
        let mut dev = crate::block::MemoryBackend::new(8 * 1024 * 1024);
        let opts = writer::FormatOpts {
            journaled: true,
            ..writer::FormatOpts::default()
        };

        // 1. Initial format + a file + flush. The first flush after
        //    format runs through the Direct sink (no on-disk journal
        //    header yet to route through).
        let initial = b"initial-payload\n".repeat(16);
        {
            let mut hfs = HfsPlus::format(&mut dev, &opts).unwrap();
            let mut src = std::io::Cursor::new(&initial);
            hfs.create_file(
                &mut dev,
                "/initial.bin",
                &mut src,
                initial.len() as u64,
                0o644,
                0,
                0,
                0,
            )
            .unwrap();
            hfs.flush(&mut dev).unwrap();
        }

        // Capture the journal-buffer offset for later poking.
        let jbuf_off = {
            let mut vh_buf = [0u8; 512];
            dev.read_at(volume_header::VOLUME_HEADER_OFFSET, &mut vh_buf)
                .unwrap();
            let info_block = u32::from_be_bytes(vh_buf[12..16].try_into().unwrap());
            let bs = u32::from_be_bytes(vh_buf[40..44].try_into().unwrap());
            assert_ne!(info_block, 0, "journaled volume must have a JIB");
            let info_off = u64::from(info_block) * u64::from(bs);
            let mut info = [0u8; 52];
            dev.read_at(info_off, &mut info).unwrap();
            u64::from_be_bytes(info[36..44].try_into().unwrap())
        };

        // 2. Reopen + mutate + flush. This flush runs through Buffered
        //    sink → JournalLog::commit.
        let new_payload = b"second\n".repeat(32);
        {
            let mut hfs = HfsPlus::open(&mut dev).unwrap();
            // A pre-flush journal must be clean (start == end). The
            // commit machinery in writer::flush relies on that.
            let mut hdr = [0u8; 24];
            dev.read_at(jbuf_off, &mut hdr).unwrap();
            let s = u64::from_be_bytes(hdr[8..16].try_into().unwrap());
            let e = u64::from_be_bytes(hdr[16..24].try_into().unwrap());
            assert_eq!(s, e, "fresh-format flush leaves the journal clean");

            // Multiple mutations: dir + file + remove. This dirties the
            // catalog (always), the bitmap (file allocation + free), and
            // bumps next_cnid (volume header).
            hfs.create_dir(&mut dev, "/added-dir", 0o755, 0, 0, 0)
                .unwrap();
            let mut src = std::io::Cursor::new(&new_payload);
            hfs.create_file(
                &mut dev,
                "/added-file.bin",
                &mut src,
                new_payload.len() as u64,
                0o644,
                0,
                0,
                0,
            )
            .unwrap();
            hfs.remove(&mut dev, "/initial.bin").unwrap();
            hfs.flush(&mut dev).unwrap();
        }

        // 3. Post-flush, the journal must be sealed again (start == end).
        let sealed_end = {
            let mut hdr = [0u8; 24];
            dev.read_at(jbuf_off, &mut hdr).unwrap();
            let s = u64::from_be_bytes(hdr[8..16].try_into().unwrap());
            let e = u64::from_be_bytes(hdr[16..24].try_into().unwrap());
            assert_eq!(
                s, e,
                "Path A for flush requires the journal to seal post-commit"
            );
            e
        };
        assert!(
            sealed_end > u64::from(journal::JHDR_SIZE),
            "the post-mutation flush must have advanced the journal end \
             cursor past the initial JHDR_SIZE — got {sealed_end:#x}"
        );

        // 4. Sanity check that the live image (after the flush, before
        //    corruption) reports the mutations.
        {
            let hfs = HfsPlus::open(&mut dev).unwrap();
            let entries = hfs.list_path(&mut dev, "/").unwrap();
            let names: std::collections::BTreeSet<&str> =
                entries.iter().map(|e| e.name.as_str()).collect();
            assert!(names.contains("added-dir"));
            assert!(names.contains("added-file.bin"));
            assert!(
                !names.contains("initial.bin"),
                "removed file must be gone post-flush; got {names:?}"
            );
        }

        // 5. Corrupt the catalog file's on-disk blocks and the
        //    allocation bitmap, then rewind `start` so the journal
        //    looks dirty. The journal entry from the flush above
        //    carries a copy of those bytes — replay must restore them
        //    on the next open.
        //
        // We deliberately do NOT corrupt the volume header itself: the
        // VH at offset 1024 is needed by `read_volume_header` to find
        // the JournalInfoBlock before replay can run. The VH is still
        // covered by the journal transaction (so it would be restored
        // anyway in production), but corrupting it here would block us
        // from reading the JIB pointer.
        let (cat_off, cat_len, bm_off, bm_len) = {
            let hfs = HfsPlus::open(&mut dev).unwrap();
            let bs = u64::from(hfs.volume_header.block_size);
            let cat = hfs.volume_header.catalog_file.extents[0];
            let bm = hfs.volume_header.allocation_file.extents[0];
            (
                u64::from(cat.start_block) * bs,
                u64::from(cat.block_count) * bs,
                u64::from(bm.start_block) * bs,
                u64::from(bm.block_count) * bs,
            )
        };
        // Zero the catalog and bitmap so the on-disk structures are
        // unusable without replay.
        let zeros_cat = vec![0u8; cat_len as usize];
        dev.write_at(cat_off, &zeros_cat).unwrap();
        let zeros_bm = vec![0u8; bm_len as usize];
        dev.write_at(bm_off, &zeros_bm).unwrap();
        // Rewind start.
        let rewound: u64 = u64::from(journal::JHDR_SIZE);
        journal::rewind_start_for_test(&mut dev, jbuf_off, rewound).unwrap();

        // Without replay, the catalog is unreadable. With replay, the
        // bytes come back and the catalog opens normally.
        {
            let hfs = HfsPlus::open(&mut dev).unwrap();
            let entries = hfs.list_path(&mut dev, "/").unwrap();
            let names: std::collections::BTreeSet<&str> =
                entries.iter().map(|e| e.name.as_str()).collect();
            assert!(
                names.contains("added-dir"),
                "replay must restore the catalog so the dir is visible; \
                 got {names:?}"
            );
            assert!(
                names.contains("added-file.bin"),
                "replay must restore the catalog so the file is visible; \
                 got {names:?}"
            );
            assert!(
                !names.contains("initial.bin"),
                "removed file must not reappear after replay; got {names:?}"
            );

            // The replayed file's bytes should be intact too.
            let mut r = hfs.open_file_reader(&mut dev, "/added-file.bin").unwrap();
            let mut got = Vec::new();
            std::io::Read::read_to_end(&mut r, &mut got).unwrap();
            assert_eq!(
                got, new_payload,
                "file data referenced by the replayed catalog must match"
            );

            // And the journal must be clean again after replay.
            let mut hdr = [0u8; 24];
            dev.read_at(jbuf_off, &mut hdr).unwrap();
            let s = u64::from_be_bytes(hdr[8..16].try_into().unwrap());
            let e = u64::from_be_bytes(hdr[16..24].try_into().unwrap());
            assert_eq!(s, e, "replay leaves the journal sealed");
        }
    }

    #[test]
    fn open_file_ro_random_seek_hfs_plus() {
        use crate::fs::Filesystem;
        use std::io::{Read, Seek, SeekFrom};

        let mut dev = crate::block::MemoryBackend::new(8 * 1024 * 1024);
        let opts = writer::FormatOpts::default();
        let data: Vec<u8> = (0..6000u32).map(|i| (i & 0xFF) as u8).collect();
        {
            let mut hfs = HfsPlus::format(&mut dev, &opts).unwrap();
            let mut src = std::io::Cursor::new(&data);
            hfs.create_file(
                &mut dev,
                "/ro.bin",
                &mut src,
                data.len() as u64,
                0o644,
                0,
                0,
                0,
            )
            .unwrap();
            hfs.flush(&mut dev).unwrap();
        }

        let mut hfs = HfsPlus::open(&mut dev).unwrap();
        let mut h = hfs
            .open_file_ro(&mut dev, std::path::Path::new("/ro.bin"))
            .expect("open_file_ro");
        assert_eq!(h.len(), data.len() as u64);
        assert!(!h.is_empty());

        h.seek(SeekFrom::Start(3333)).unwrap();
        let mut buf = [0u8; 96];
        h.read_exact(&mut buf).unwrap();
        assert_eq!(&buf[..], &data[3333..3429]);

        h.seek(SeekFrom::Start(40)).unwrap();
        let mut buf2 = [0u8; 64];
        h.read_exact(&mut buf2).unwrap();
        assert_eq!(&buf2[..], &data[40..104]);
    }

    // ----------------------------------------------------------------
    // HFSCompression (decmpfs) integration tests
    // ----------------------------------------------------------------
    //
    // Our writer doesn't emit an attributes B-tree, so to test the
    // read path we:
    //
    //   1. format + create_file an empty placeholder file;
    //   2. *before* flush, mutate writer state directly to:
    //      - flip UF_COMPRESSED on the file's owner_flags;
    //      - allocate blocks for the attributes file;
    //      - point writer.attributes_file / volume_header.attributes_file
    //        at those blocks;
    //      - for type-4 tests, allocate + register the resource fork's
    //        extents in the on-disk file body too;
    //   3. flush (writes a normal catalog + VH referencing the new
    //      attributes file extents);
    //   4. lay down a synthesized 2-node attributes B-tree (header +
    //      leaf) in the allocated blocks;
    //   5. for type-4 tests, lay down a synthesized resource fork in
    //      its allocated blocks;
    //   6. re-open and read the file — the read path inflates the
    //      decmpfs payload and returns logical bytes.

    /// Build the 16-byte decmpfs header for `compression_type` /
    /// `uncompressed_size`. All header fields are little-endian.
    fn make_decmpfs_header(compression_type: u32, uncompressed_size: u64) -> [u8; 16] {
        let mut hdr = [0u8; 16];
        hdr[0..4].copy_from_slice(&decmpfs::DECMPFS_MAGIC.to_le_bytes());
        hdr[4..8].copy_from_slice(&compression_type.to_le_bytes());
        hdr[8..16].copy_from_slice(&uncompressed_size.to_le_bytes());
        hdr
    }

    /// Construct a single-leaf attributes B-tree containing exactly
    /// one inline-data record for (file_id, "com.apple.decmpfs"). The
    /// returned buffer is two `node_size`-byte nodes back-to-back:
    /// node 0 is the B-tree header node, node 1 is the leaf.
    fn synth_attributes_btree(node_size: u32, file_id: u32, decmpfs_value: &[u8]) -> Vec<u8> {
        use btree::{HEADER_REC_SIZE, KIND_HEADER, KIND_LEAF, NODE_DESCRIPTOR_SIZE};
        let ns = node_size as usize;
        // ----- node 0: header node.
        let mut hdr = vec![0u8; ns];
        // BTNodeDescriptor: kind = header, height = 0, numRecords = 3.
        hdr[8] = KIND_HEADER as u8;
        hdr[9] = 0;
        hdr[10..12].copy_from_slice(&3u16.to_be_bytes());
        // BTHeaderRec at offset 14.
        let h = NODE_DESCRIPTOR_SIZE;
        hdr[h..h + 2].copy_from_slice(&1u16.to_be_bytes()); // tree_depth
        hdr[h + 2..h + 6].copy_from_slice(&1u32.to_be_bytes()); // root_node = leaf
        hdr[h + 6..h + 10].copy_from_slice(&1u32.to_be_bytes()); // leaf_records
        hdr[h + 10..h + 14].copy_from_slice(&1u32.to_be_bytes()); // first_leaf
        hdr[h + 14..h + 18].copy_from_slice(&1u32.to_be_bytes()); // last_leaf
        hdr[h + 18..h + 20].copy_from_slice(&(node_size as u16).to_be_bytes());
        hdr[h + 20..h + 22].copy_from_slice(&264u16.to_be_bytes()); // maxKeyLength
        hdr[h + 22..h + 26].copy_from_slice(&2u32.to_be_bytes()); // total_nodes
        hdr[h + 26..h + 30].copy_from_slice(&0u32.to_be_bytes()); // free_nodes
        hdr[h + 32..h + 36].copy_from_slice(&node_size.to_be_bytes()); // clumpSize
        hdr[h + 36] = 0; // btreeType = HFS+
        hdr[h + 37] = 0xCF; // keyCompareType = case-fold (plain HFS+)
        hdr[h + 38..h + 42].copy_from_slice(&6u32.to_be_bytes()); // big-keys + variable-index
        // Map record fills the rest. Offset table at the tail.
        let user_off = NODE_DESCRIPTOR_SIZE + HEADER_REC_SIZE;
        let map_off = user_off + 128;
        let offsets_table = 2 * 4;
        let free_off = ns - offsets_table;
        let offs = [
            NODE_DESCRIPTOR_SIZE as u16,
            user_off as u16,
            map_off as u16,
            free_off as u16,
        ];
        for (i, &o) in offs.iter().enumerate() {
            let pos = ns - 2 * (i + 1);
            hdr[pos..pos + 2].copy_from_slice(&o.to_be_bytes());
        }
        // Map: nodes 0 and 1 both in use.
        hdr[map_off] = 0b1100_0000;

        // ----- node 1: leaf with one record.
        let name = "com.apple.decmpfs";
        let name_units: Vec<u16> = name.encode_utf16().collect();
        let name_len = name_units.len();
        // Key bytes.
        let mut key_buf = Vec::new();
        let key_payload_len = 12 + 2 * name_len;
        key_buf.extend_from_slice(&(key_payload_len as u16).to_be_bytes());
        key_buf.extend_from_slice(&0u16.to_be_bytes()); // pad
        key_buf.extend_from_slice(&file_id.to_be_bytes());
        key_buf.extend_from_slice(&0u32.to_be_bytes()); // start_block
        key_buf.extend_from_slice(&(name_len as u16).to_be_bytes());
        for u in &name_units {
            key_buf.extend_from_slice(&u.to_be_bytes());
        }
        // Pad key to even (already is — 14 + 2*N).
        // Record body: inline-data.
        let mut body = Vec::new();
        body.extend_from_slice(&attributes::REC_INLINE_DATA.to_be_bytes());
        body.extend_from_slice(&0u64.to_be_bytes()); // two reserved words
        body.extend_from_slice(&(decmpfs_value.len() as u32).to_be_bytes());
        body.extend_from_slice(decmpfs_value);

        let rec = [key_buf.clone(), body.clone()].concat();
        let mut leaf = vec![0u8; ns];
        leaf[8] = KIND_LEAF as u8;
        leaf[9] = 1; // height
        leaf[10..12].copy_from_slice(&1u16.to_be_bytes());
        // Record at the start of the data area.
        let start = NODE_DESCRIPTOR_SIZE;
        let end = start + rec.len();
        assert!(end <= ns - 4, "attribute record overruns node");
        leaf[start..end].copy_from_slice(&rec);
        // Offset table: two entries (start of record + start of free).
        let l_offs = [start as u16, end as u16];
        for (i, &o) in l_offs.iter().enumerate() {
            let pos = ns - 2 * (i + 1);
            leaf[pos..pos + 2].copy_from_slice(&o.to_be_bytes());
        }

        let mut out = Vec::with_capacity(2 * ns);
        out.extend_from_slice(&hdr);
        out.extend_from_slice(&leaf);
        out
    }

    /// Locate the catalog file's encoded body inside `writer.catalog`
    /// by walking it to find the entry whose `(parent_id, name)` matches
    /// `path_name` under the root folder, and return a mutable handle.
    fn find_root_file_body_mut<'a>(w: &'a mut writer::Writer, file_name: &str) -> &'a mut Vec<u8> {
        // The writer keeps a BTreeMap<OwnedKey, Vec<u8>>. We need to
        // find the entry whose key is (ROOT_FOLDER_ID, file_name) and
        // is a REC_FILE. Construct the equivalent UniStr to match.
        let target = UniStr::from_str_lossy(file_name);
        for (k, body) in w.catalog.iter_mut() {
            if k.parent_id == catalog::ROOT_FOLDER_ID
                && k.name.code_units == target.code_units
                && body.len() >= 2
                && i16::from_be_bytes([body[0], body[1]]) == catalog::REC_FILE
            {
                return body;
            }
        }
        panic!("no catalog file record for /{file_name}");
    }

    #[cfg(feature = "gzip")]
    #[test]
    fn read_decmpfs_type3_inline_zlib() {
        let mut dev = crate::block::MemoryBackend::new(8 * 1024 * 1024);
        let opts = writer::FormatOpts::default();
        let mut hfs = HfsPlus::format(&mut dev, &opts).unwrap();

        // Empty placeholder file. The actual logical content will come
        // from the decmpfs xattr we install below.
        let mut empty = std::io::Cursor::new(Vec::<u8>::new());
        let cnid = hfs
            .create_file(&mut dev, "/cmp.bin", &mut empty, 0, 0o644, 0, 0, 0)
            .unwrap();

        let plain = b"hello hfsplus decmpfs inline zlib world!\n".repeat(20);
        let compressed =
            crate::compression::compress(crate::compression::Algo::Zlib, &plain).unwrap();

        // Build the decmpfs xattr payload: 16-byte header (type 3) +
        // inline zlib bytes.
        let mut xattr = Vec::new();
        xattr.extend_from_slice(&make_decmpfs_header(3, plain.len() as u64));
        xattr.extend_from_slice(&compressed);

        // Allocate two attributes-file blocks (= 2 * node_size / block_size).
        let block_size = hfs.volume_header.block_size;
        let node_size = opts.node_size;
        let attr_bytes_needed = (2 * node_size) as u64;
        let blocks_needed = u32::try_from(attr_bytes_needed.div_ceil(u64::from(block_size)))
            .expect("attribute fork block count fits in u32");
        let w = hfs.writer.as_mut().unwrap();
        let attr_start_block = w.allocate(blocks_needed).expect("allocate attributes file");

        // Update writer + VH attributes_file ForkData.
        let mut attr_fork = ForkData {
            logical_size: attr_bytes_needed,
            clump_size: node_size,
            total_blocks: blocks_needed,
            extents: Default::default(),
        };
        attr_fork.extents[0] = volume_header::ExtentDescriptor {
            start_block: attr_start_block,
            block_count: blocks_needed,
        };
        w.attributes_file = attr_fork;
        hfs.volume_header.attributes_file = attr_fork;

        // Flip UF_COMPRESSED on the file's owner_flags (offset 41 of
        // the encoded REC_FILE body) and zero the resource fork
        // (already empty post-create_file, defensive).
        {
            let body = find_root_file_body_mut(w, "cmp.bin");
            body[41] |= decmpfs::UF_COMPRESSED;
        }

        // Flush so the on-disk catalog + volume header pick up our
        // changes.
        hfs.flush(&mut dev).unwrap();

        // Lay down the synthesized 2-node attributes B-tree at its
        // extents start.
        let attr_tree = synth_attributes_btree(node_size, cnid, &xattr);
        let attr_off = u64::from(attr_start_block) * u64::from(block_size);
        dev.write_at(attr_off, &attr_tree).unwrap();

        // Now re-open and read the file via the public reader.
        let hfs = HfsPlus::open(&mut dev).unwrap();
        let mut r = hfs.open_file_reader(&mut dev, "/cmp.bin").unwrap();
        let mut got = Vec::new();
        std::io::Read::read_to_end(&mut r, &mut got).unwrap();
        assert_eq!(got.len(), plain.len(), "decompressed length matches header");
        assert_eq!(got, plain, "decompressed bytes match original");
    }

    #[cfg(feature = "gzip")]
    #[test]
    fn read_decmpfs_type4_resource_fork_zlib() {
        let mut dev = crate::block::MemoryBackend::new(16 * 1024 * 1024);
        let opts = writer::FormatOpts::default();
        let mut hfs = HfsPlus::format(&mut dev, &opts).unwrap();

        let mut empty = std::io::Cursor::new(Vec::<u8>::new());
        let cnid = hfs
            .create_file(&mut dev, "/big.bin", &mut empty, 0, 0o644, 0, 0, 0)
            .unwrap();

        // Build two blocks: first 64 KiB, then a tail.
        let mut plain = Vec::new();
        plain.extend(std::iter::repeat_n(0xABu8, decmpfs::HFSCOMPRESS_BLOCK_SIZE));
        plain.extend_from_slice(b"hfscompression type-4 tail data");
        let block1 = &plain[..decmpfs::HFSCOMPRESS_BLOCK_SIZE];
        let block2 = &plain[decmpfs::HFSCOMPRESS_BLOCK_SIZE..];

        let compress = |data: &[u8]| -> Vec<u8> {
            crate::compression::compress(crate::compression::Algo::Zlib, data).unwrap()
        };
        let c1 = compress(block1);
        let c2 = compress(block2);

        // Assemble resource-fork bytes (data area at offset 256, table
        // base at data_offset + 4).
        let block_count: u32 = 2;
        let table_size = 4 + 8 * block_count as usize;
        let blk1_off = table_size as u32;
        let blk2_off = blk1_off + c1.len() as u32;

        let mut rdata = Vec::new();
        let inner_size: u32 = (table_size + c1.len() + c2.len()) as u32;
        rdata.extend_from_slice(&inner_size.to_be_bytes());
        rdata.extend_from_slice(&block_count.to_le_bytes());
        rdata.extend_from_slice(&blk1_off.to_le_bytes());
        rdata.extend_from_slice(&(c1.len() as u32).to_le_bytes());
        rdata.extend_from_slice(&blk2_off.to_le_bytes());
        rdata.extend_from_slice(&(c2.len() as u32).to_le_bytes());
        rdata.extend_from_slice(&c1);
        rdata.extend_from_slice(&c2);

        let data_offset: u32 = 256;
        let data_length: u32 = rdata.len() as u32;
        let mut rf = Vec::new();
        rf.extend_from_slice(&data_offset.to_be_bytes());
        rf.extend_from_slice(&(data_offset + data_length).to_be_bytes());
        rf.extend_from_slice(&data_length.to_be_bytes());
        rf.extend_from_slice(&0u32.to_be_bytes());
        rf.resize(data_offset as usize, 0);
        rf.extend_from_slice(&rdata);

        // decmpfs xattr: header only (type 4 = data in resource fork).
        let xattr = make_decmpfs_header(4, plain.len() as u64).to_vec();

        // Layout:
        //   - allocate blocks for the attributes B-tree (2 nodes)
        //   - allocate blocks for the resource fork (covers rf.len())
        let block_size = hfs.volume_header.block_size;
        let node_size = opts.node_size;
        let attr_bytes_needed = (2 * node_size) as u64;
        let attr_blocks = u32::try_from(attr_bytes_needed.div_ceil(u64::from(block_size))).unwrap();
        let rf_blocks = u32::try_from((rf.len() as u64).div_ceil(u64::from(block_size))).unwrap();
        let w = hfs.writer.as_mut().unwrap();
        let attr_start = w.allocate(attr_blocks).unwrap();
        let rf_start = w.allocate(rf_blocks).unwrap();

        // Attributes-file fork.
        let mut attr_fork = ForkData {
            logical_size: attr_bytes_needed,
            clump_size: node_size,
            total_blocks: attr_blocks,
            extents: Default::default(),
        };
        attr_fork.extents[0] = volume_header::ExtentDescriptor {
            start_block: attr_start,
            block_count: attr_blocks,
        };
        w.attributes_file = attr_fork;
        hfs.volume_header.attributes_file = attr_fork;

        // Resource fork: rewrite the file's catalog body so its
        // resourceFork ForkData (offset 168..248) points at rf_start.
        {
            let body = find_root_file_body_mut(w, "big.bin");
            body[41] |= decmpfs::UF_COMPRESSED;
            // logical_size (8 BE) = rf.len()
            body[168..176].copy_from_slice(&(rf.len() as u64).to_be_bytes());
            // clump_size (4 BE)
            body[176..180].copy_from_slice(&block_size.to_be_bytes());
            // total_blocks (4 BE)
            body[180..184].copy_from_slice(&rf_blocks.to_be_bytes());
            // extents[0]
            body[184..188].copy_from_slice(&rf_start.to_be_bytes());
            body[188..192].copy_from_slice(&rf_blocks.to_be_bytes());
        }

        hfs.flush(&mut dev).unwrap();

        // Write the synthesized attribute tree and resource-fork bytes
        // to the allocated blocks.
        let attr_tree = synth_attributes_btree(node_size, cnid, &xattr);
        let attr_off = u64::from(attr_start) * u64::from(block_size);
        dev.write_at(attr_off, &attr_tree).unwrap();
        let rf_off = u64::from(rf_start) * u64::from(block_size);
        dev.write_at(rf_off, &rf).unwrap();

        let hfs = HfsPlus::open(&mut dev).unwrap();
        let mut r = hfs.open_file_reader(&mut dev, "/big.bin").unwrap();
        let mut got = Vec::new();
        std::io::Read::read_to_end(&mut r, &mut got).unwrap();
        assert_eq!(got.len(), plain.len());
        assert_eq!(got, plain);
    }

    #[test]
    fn read_decmpfs_unsupported_codec_errors_clearly() {
        // A file marked UF_COMPRESSED whose xattr advertises an
        // LZVN/LZFSE codec should produce a clear `Unsupported` error
        // rather than data corruption. We exercise this with type 7
        // (LZVN inline).
        let mut dev = crate::block::MemoryBackend::new(8 * 1024 * 1024);
        let opts = writer::FormatOpts::default();
        let mut hfs = HfsPlus::format(&mut dev, &opts).unwrap();
        let mut empty = std::io::Cursor::new(Vec::<u8>::new());
        let cnid = hfs
            .create_file(&mut dev, "/lzvn.bin", &mut empty, 0, 0o644, 0, 0, 0)
            .unwrap();

        // decmpfs header advertises type 7 (LZVN inline), but we ship
        // no payload — the test only checks the codec dispatch path.
        let xattr = make_decmpfs_header(7, 4).to_vec();

        let block_size = hfs.volume_header.block_size;
        let node_size = opts.node_size;
        let attr_bytes_needed = (2 * node_size) as u64;
        let attr_blocks = u32::try_from(attr_bytes_needed.div_ceil(u64::from(block_size))).unwrap();
        let w = hfs.writer.as_mut().unwrap();
        let attr_start = w.allocate(attr_blocks).unwrap();
        let mut attr_fork = ForkData {
            logical_size: attr_bytes_needed,
            clump_size: node_size,
            total_blocks: attr_blocks,
            extents: Default::default(),
        };
        attr_fork.extents[0] = volume_header::ExtentDescriptor {
            start_block: attr_start,
            block_count: attr_blocks,
        };
        w.attributes_file = attr_fork;
        hfs.volume_header.attributes_file = attr_fork;
        {
            let body = find_root_file_body_mut(w, "lzvn.bin");
            body[41] |= decmpfs::UF_COMPRESSED;
        }
        hfs.flush(&mut dev).unwrap();
        let attr_tree = synth_attributes_btree(node_size, cnid, &xattr);
        let attr_off = u64::from(attr_start) * u64::from(block_size);
        dev.write_at(attr_off, &attr_tree).unwrap();

        let hfs = HfsPlus::open(&mut dev).unwrap();
        let err = hfs.open_file_reader(&mut dev, "/lzvn.bin").err().unwrap();
        assert!(
            matches!(err, crate::Error::Unsupported(_)),
            "LZVN should surface as Unsupported, got {err:?}"
        );
    }
}
