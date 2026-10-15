//! Driver-independent Windows callback core. One owner serializes the filesystem
//! and device; callbacks never retain a borrowing editor or acknowledge unsynced
//! mutations. The image factory can only create a new disposable output copy.
use crate::{
    engine,
    image::Image,
    names::{self, DirectoryNames},
    volume,
};
use fstool::{
    block::BlockDevice,
    fs::{Filesystem, hfs_plus::HfsPlus},
};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    io::{Read, Seek, SeekFrom},
    path::Path,
    sync::Arc,
};

mod attribute_archive;
mod deferred;
mod extra_attributes;
mod named;
mod precision;
mod readonly_attributes;
mod security;
mod startup_reads;
mod symbolic;
use attribute_archive::{Archive, archive_path};
use named::named_path;
use precision::now_filetime;

fn mac_private_root_name(parent: u32, name: &str) -> bool {
    parent == 2
        && matches!(
            name,
            "\0\0\0\0HFS+ Private Data" | ".HFS+ Private Directory Data\r"
        )
}

struct PendingDelete {
    parent: u32,
    name: String,
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    InvalidName,
    NotFound,
    Collision,
    AccessDenied,
    SharingViolation,
    DeletePending,
    DirectoryNotEmpty,
    NotDirectory,
    IsDirectory,
    DiskFull,
    InvalidHandle,
    InvalidParameter,
    Unsupported,
    IoError,
    FailedVolume,
    Busy,
}
impl Status {
    pub fn ntstatus(self) -> u32 {
        match self {
            Self::InvalidName => 0xc0000033,
            Self::NotFound => 0xc0000034,
            Self::Collision => 0xc0000035,
            Self::AccessDenied => 0xc0000022,
            Self::SharingViolation => 0xc0000043,
            Self::DeletePending => 0xc0000056,
            Self::DirectoryNotEmpty => 0xc0000101,
            Self::NotDirectory => 0xc0000103,
            Self::IsDirectory => 0xc00000ba,
            Self::DiskFull => 0xc000007f,
            Self::InvalidHandle => 0xc0000008,
            Self::InvalidParameter => 0xc000000d,
            Self::Unsupported => 0xc00000bb,
            Self::IoError | Self::FailedVolume => 0xc0000185,
            Self::Busy => 0xc000009e,
        }
    }
}
#[derive(Debug)]
pub struct Error {
    pub status: Status,
    pub detail: String,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}: {}", self.status, self.detail)
    }
}
impl std::error::Error for Error {}
fn error(status: Status, detail: impl ToString) -> Error {
    Error {
        status,
        detail: detail.to_string(),
    }
}
fn engine_error(e: fstool::Error) -> Error {
    let status = match e {
        fstool::Error::Unsupported(ref message)
            if message.contains("out of space")
                || message == "hfs+: insufficient attribute copy-on-write space" =>
        {
            Status::DiskFull
        }
        fstool::Error::Unsupported(_) => Status::Unsupported,
        fstool::Error::InvalidArgument(_) | fstool::Error::OutOfBounds { .. } => {
            Status::InvalidParameter
        }
        _ => Status::IoError,
    };
    error(status, e)
}

#[derive(Debug, Clone, Copy, Default)]
pub struct Access {
    pub read: bool,
    pub write: bool,
    pub append: bool,
    pub delete: bool,
    pub metadata: bool,
    pub read_ea: bool,
    pub write_ea: bool,
}
impl Access {
    fn participates_in_sharing(self) -> bool {
        self.read || self.write || self.append || self.delete
    }
    pub const READ: Self = Self {
        read: true,
        write: false,
        append: false,
        delete: false,
        metadata: false,
        read_ea: true,
        write_ea: false,
    };
    pub const ALL: Self = Self {
        read: true,
        write: true,
        append: true,
        delete: true,
        metadata: true,
        read_ea: true,
        write_ea: true,
    };
}
#[derive(Debug, Clone, Copy)]
pub struct Share {
    pub read: bool,
    pub write: bool,
    pub delete: bool,
}
impl Share {
    pub const ALL: Self = Self {
        read: true,
        write: true,
        delete: true,
    };
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    File,
    Directory,
}
#[derive(Debug, Clone, Copy)]
pub struct OpenRequest {
    pub access: Access,
    pub share: Share,
    pub kind: Option<Kind>,
}
impl Default for OpenRequest {
    fn default() -> Self {
        Self {
            access: Access::READ,
            share: Share::ALL,
            kind: None,
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Handle(u64);
#[derive(Debug, Clone)]
pub struct FileInfo {
    pub cnid: u32,
    pub identity_cnid: u32,
    pub node: crate::links::Node,
    pub kind: Kind,
    pub size: u64,
    pub allocation_size: u64,
    /// Windows DIRECTORY/READONLY/HIDDEN and ARCHIVE derived from native HFS
    /// backupDate/contentModDate. No fabricated system/reparse/ACL flags.
    pub attributes: u32,
    pub ea_size: u32,
    pub creation_time: u64,
    pub access_time: u64,
    pub write_time: u64,
    pub change_time: u64,
    pub mac_mode: u16,
    pub mac_uid: u32,
    pub mac_gid: u32,
}
#[derive(Debug, Clone)]
pub struct DirectoryEntry {
    pub name: String,
    pub aliased: bool,
    pub info: FileInfo,
}
#[derive(Debug, Clone)]
pub struct VolumeInfo {
    pub label: String,
    pub total_bytes: u64,
    pub free_bytes: u64,
}
#[derive(Debug, Clone, Copy, Default)]
pub struct BasicTimes {
    pub creation: Option<u64>,
    pub access: Option<u64>,
    pub write: Option<u64>,
    pub change: Option<u64>,
}
// Exact day difference 1601-01-01 to 1904-01-01, in seconds.
const HFS_TO_WINDOWS: u64 = 9_561_628_800;
const TICKS: u64 = 10_000_000;
pub fn hfs_to_filetime(seconds: u32) -> u64 {
    (HFS_TO_WINDOWS + u64::from(seconds)) * TICKS
}
pub fn filetime_to_hfs(time: u64) -> Result<u32> {
    let seconds = (time / TICKS)
        .checked_sub(HFS_TO_WINDOWS)
        .ok_or_else(|| error(Status::InvalidParameter, "timestamp predates the HFS epoch"))?;
    u32::try_from(seconds).map_err(|_| {
        error(
            Status::InvalidParameter,
            "timestamp exceeds the HFS date range",
        )
    })
}
fn components(path: &str) -> Result<Vec<&str>> {
    if path == "\\" {
        return Ok(Vec::new());
    }
    if !path.starts_with('\\') || path.encode_utf16().count() > 32767 {
        return Err(error(
            Status::InvalidName,
            "expected a rooted Windows volume path",
        ));
    }
    let parts: Vec<_> = path[1..].split('\\').collect();
    if parts.len() > 1024 || parts.iter().any(|p| !names::windows_component(p)) {
        return Err(error(Status::InvalidName, "invalid Windows path component"));
    }
    Ok(parts)
}
#[derive(Clone, Copy)]
struct Context {
    cnid: u32,
    identity_cnid: u32,
    access: Access,
    share: Share,
    cleaned: bool,
    resource: bool,
    finder: bool,
    archive: Option<u64>,
    named: Option<u64>,
    explicit_times: u8,
    display_cnid: Option<u32>,
    reparse: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Stream {
    Data,
    Resource,
    Finder,
    Archive,
    Named(u64),
}
impl Context {
    fn stream(self) -> Stream {
        if let Some(id) = self.named {
            Stream::Named(id)
        } else if self.archive.is_some() {
            Stream::Archive
        } else if self.finder {
            Stream::Finder
        } else if self.resource {
            Stream::Resource
        } else {
            Stream::Data
        }
    }
}

/// Only the conventional resource stream and explicit unnamed data stream are
/// mapped. Colons elsewhere, unknown stream names and non-data types are refused.
fn stream_path(path: &str) -> Result<(&str, bool)> {
    let Some((base, stream)) = path.split_once(':') else {
        return Ok((path, false));
    };
    components(base)?;
    if base == "\\" {
        return Err(error(Status::InvalidName, "root cannot carry a stream"));
    }
    if stream.eq_ignore_ascii_case(":$DATA") {
        return Ok((base, false));
    }
    if stream.eq_ignore_ascii_case("AFP_Resource")
        || stream.eq_ignore_ascii_case("AFP_Resource:$DATA")
    {
        Ok((base, true))
    } else {
        Err(error(Status::InvalidName, "unsupported Windows stream"))
    }
}
fn finder_path(path: &str) -> Option<&str> {
    let (base, stream) = path.split_once(':')?;
    (stream.eq_ignore_ascii_case("AFP_AfpInfo") || stream.eq_ignore_ascii_case("AFP_AfpInfo:$DATA"))
        .then_some(base)
}

pub struct Adapter<D: BlockDevice> {
    read_only: bool,
    fs: HfsPlus,
    device: D,
    handles: BTreeMap<Handle, Context>,
    next_handle: u64,
    pending_delete: BTreeMap<u32, PendingDelete>,
    holding: Option<u32>,
    failure: Option<String>,
    archives: BTreeMap<u64, Archive>,
    detached_named: BTreeMap<(u32, u64), crate::named_streams::Stream>,
    overwritten_named: BTreeSet<(u32, u64)>,
    // One validated committed container, bounded by the existing 16 MiB codec
    // cap. Never dirty: any publication invalidates it before returning.
    named_cache: Option<(u32, Arc<crate::named_streams::Store>)>,
    ea_import: BTreeMap<u32, Vec<crate::ea::Change>>,
    // CopyFile supplies final read-only attributes before it writes the data.
    // Apply that constructor bit only after all initialization contexts close.
    readonly_on_close: BTreeSet<u32>,
    windows_directory_hints: bool,
    // Nested target-retention and rename work share one outer publication.
    namespace_times: BTreeMap<u32, [Option<u64>; 4]>,
    // Cache committed read metadata only while live identity/write count match.
    // Writable adapters bypass it during staged edits and clear it on publication.
    // The historic readonly_ field names also cover these committed read windows.
    readonly_generation: Option<(
        crate::timestamps::VolumeState,
        Option<crate::timestamps::Generation>,
    )>,
    readonly_attribute_index: Option<(
        crate::timestamps::VolumeState,
        fstool::fs::hfs_plus::AttributeReadIndex,
    )>,
    readonly_attribute_values: BTreeMap<(u32, String), Vec<u8>>,
    readonly_directory_names: BTreeMap<u32, (crate::timestamps::VolumeState, Arc<DirectoryNames>)>,
}
impl Adapter<Image> {
    pub fn copy_image(
        source: &Path,
        output: &Path,
        base: u64,
        length: Option<u64>,
    ) -> crate::Result<Self> {
        let mut original = Image::read_only(source, base, length)?;
        engine::open_checked(&mut original)?;
        let device = Image::copy_new(source, output, base, length)?;
        Ok(Self::from_device(device)?)
    }
}
impl<D: BlockDevice> Adapter<D> {
    /// Development device injection. The production image entry point above
    /// never opens an existing image writable. Physical adapters are absent.
    pub fn from_device(device: D) -> Result<Self> {
        Self::from_device_mode(device, false)
    }
    /// Browse without reclamation, timestamp updates or source syncs. The
    /// wrapper denies writes even if a future callback forgets its mode gate.
    pub fn from_read_only_device(
        device: D,
    ) -> Result<Adapter<crate::read_only_device::ReadOnlyDevice<D>>> {
        Adapter::from_device_mode(crate::read_only_device::ReadOnlyDevice::new(device), true)
    }
    pub fn is_read_only(&self) -> bool {
        self.read_only
    }
    fn from_device_mode(mut device: D, read_only: bool) -> Result<Self> {
        let fs = if read_only {
            let mut startup = startup_reads::StartupReads::new(&mut device)
                .map_err(|e| error(Status::IoError, e))?;
            engine::open_checked(&mut startup)
        } else {
            engine::open_checked(&mut device)
        }
        .map_err(|e| error(Status::IoError, e))?;
        let mut adapter = Self {
            read_only,
            fs,
            device,
            handles: BTreeMap::new(),
            next_handle: 1,
            pending_delete: BTreeMap::new(),
            holding: None,
            failure: None,
            archives: BTreeMap::new(),
            detached_named: BTreeMap::new(),
            overwritten_named: BTreeSet::new(),
            named_cache: None,
            ea_import: BTreeMap::new(),
            readonly_on_close: BTreeSet::new(),
            windows_directory_hints: false,
            namespace_times: BTreeMap::new(),
            readonly_generation: None,
            readonly_attribute_index: None,
            readonly_attribute_values: BTreeMap::new(),
            readonly_directory_names: BTreeMap::new(),
        };
        if read_only {
            adapter.inspect_deferred()?;
        } else {
            adapter.recover_deferred()?;
        }
        Ok(adapter)
    }
    pub fn failure(&self) -> Option<&str> {
        self.failure.as_deref()
    }
    fn healthy(&self) -> Result<()> {
        if let Some(e) = &self.failure {
            return Err(error(Status::FailedVolume, e));
        }
        Ok(())
    }
    fn mutated<T>(&mut self, result: fstool::Result<T>) -> Result<T> {
        self.named_cache = None;
        self.clear_committed_read_cache();
        result.map_err(|e| {
            self.failure = Some(e.to_string());
            engine_error(e)
        })
    }
    /// Complete transaction APIs distinguish pure preflight refusal from
    /// a partially staged or failed write; only the latter poisons the adapter.
    fn publication_result<T>(&mut self, result: fstool::Result<T>) -> Result<T> {
        self.named_cache = None;
        self.clear_committed_read_cache();
        result.map_err(|e| {
            if self.fs.requires_reopen() {
                self.failure = Some(e.to_string());
            }
            engine_error(e)
        })
    }
    fn durable(&mut self) -> Result<()> {
        if self.read_only {
            return self.healthy();
        }
        self.named_cache = None;
        let result = self
            .fs
            .flush(&mut self.device)
            .and_then(|_| self.device.sync());
        self.mutated(result)
    }
    fn clear_committed_read_cache(&mut self) {
        self.readonly_generation = None;
        self.readonly_attribute_index = None;
        self.readonly_attribute_values.clear();
        self.readonly_directory_names.clear();
    }
    /// Attribute bytes and their change date are preflighted together. Related
    /// timestamp bookkeeping must be included here before the one durable flush.
    fn publish_entry_attributes(
        &mut self,
        cnid: u32,
        attributes: &[(&str, Option<&[u8]>)],
        exact: u64,
    ) -> Result<()> {
        let time = filetime_to_hfs(exact)?;
        let catalog = [fstool::fs::hfs_plus::CatalogUpdate {
            cnid,
            times: [None, None, None, Some(time)],
            attributes: None,
        }];
        let precision =
            self.prepare_precision(&catalog, &[(cnid, [None, None, None, Some(exact)])], None)?;
        let related = precision.references();
        let result = self.fs.set_entry_attributes_with_publication(
            &mut self.device,
            cnid,
            fstool::fs::hfs_plus::PublicationMetadata {
                attributes,
                catalog: &catalog,
                related: &related,
            },
        );
        self.publication_result(result)?;
        self.durable()
    }
    fn stage_namespace_times(&mut self, cnid: u32, times: [Option<u64>; 4]) {
        let accumulated = self.namespace_times.entry(cnid).or_default();
        for (old, new) in accumulated.iter_mut().zip(times) {
            if new.is_some() {
                *old = new;
            }
        }
    }
    fn publish_namespace(&mut self) -> Result<()> {
        let catalog = self
            .namespace_times
            .iter()
            .map(|(&cnid, times)| {
                let [a, b, c, d] = times.map(|date| date.map(filetime_to_hfs).transpose());
                Ok(fstool::fs::hfs_plus::CatalogUpdate {
                    cnid,
                    times: [a?, b?, c?, d?],
                    attributes: None,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let exact = self
            .namespace_times
            .iter()
            .map(|(&id, &times)| (id, times))
            .collect::<Vec<_>>();
        let precision = self
            .prepare_precision(&catalog, &exact, None)
            .inspect_err(|e| {
                self.failure = Some(e.to_string());
            })?;
        let related = precision.references();
        let result =
            self.fs
                .set_namespace_metadata_with_publication(&mut self.device, &catalog, &related);
        // A pure planner refusal is fatal here: namespace work preceded it.
        self.mutated(result)?;
        self.durable()?;
        self.namespace_times.clear();
        Ok(())
    }
    fn path(&self, cnid: u32) -> Result<String> {
        self.fs.catalog_path(cnid).map_err(engine_error)
    }
    fn body(&self, cnid: u32) -> Result<Vec<u8>> {
        self.fs.catalog_record_cnid(cnid).map_err(engine_error)
    }
    fn metadata_cnid(&mut self, cnid: u32) -> Result<u32> {
        let body = self.body(cnid)?;
        if volume::be16(&body, 0) == 2 && &body[48..56] == b"hlnkhfs+" {
            return self
                .fs
                .regular_file_identity(&mut self.device, cnid)
                .map_err(engine_error);
        }
        Ok(cnid)
    }
    fn info(&mut self, cnid: u32) -> Result<FileInfo> {
        let raw = self.body(cnid)?;
        let hard = volume::be16(&raw, 0) == 2 && &raw[48..56] == b"hlnkhfs+";
        let identity_cnid = self.metadata_cnid(cnid)?;
        let b = if hard { self.body(identity_cnid)? } else { raw };
        let kind = match volume::be16(&b, 0) {
            1 => Kind::Directory,
            2 => Kind::File,
            _ => return Err(error(Status::Unsupported, "unsupported catalog entry")),
        };
        let mode = volume::be16(&b, 42);
        let node = if hard {
            crate::links::Node::HardLink
        } else if kind == Kind::File && (mode & 0xf000 == 0xa000 || &b[48..56] == b"slnkrhap") {
            crate::links::Node::SymbolicLink
        } else if kind == Kind::File && mode & 0xf000 == 0x1000 {
            crate::links::Node::Fifo
        } else if kind == Kind::File && mode & 0xf000 != 0 && mode & 0xf000 != 0x8000 {
            return Err(error(
                Status::Unsupported,
                "this special node has no validated Windows representation",
            ));
        } else {
            crate::links::Node::Ordinary
        };
        let special = matches!(
            node,
            crate::links::Node::SymbolicLink | crate::links::Node::Fifo
        );
        let link_directory = node == crate::links::Node::SymbolicLink
            && self
                .symbolic_windows_target(cnid)
                .is_ok_and(|(_, directory)| directory);
        let compression = if special {
            None
        } else {
            self.fs
                .compressed_info(&mut self.device, identity_cnid)
                .map_err(engine_error)?
        };
        let convertible = compression.is_some()
            && self
                .fs
                .compressed_conversion_supported(&mut self.device, identity_cnid)
                .map_err(engine_error)?;
        let locked = matches!(
            node,
            crate::links::Node::HardLink | crate::links::Node::Fifo
        ) || (compression.is_some() && !convertible)
            || (b[40] | b[41]) & 0x06 != 0
            || volume::be16(&b, 56) & 0x1000 != 0
            || (kind == Kind::File && volume::be16(&b, 2) & 1 != 0);
        let attributes = u32::from(locked)
            | if special { 0x400 } else { 0 }
            | if kind == Kind::Directory || link_directory {
                0x10
            } else {
                0
            }
            | if volume::be16(&b, 56) & 0x4000 != 0 {
                2
            } else {
                0
            }
            | if volume::be32(&b, 28) == 0 || volume::be32(&b, 28) < volume::be32(&b, 16) {
                0x20
            } else {
                0
            }
            | self.windows_flags(identity_cnid)?;
        let dates = self.precise_dates(identity_cnid, &b)?;
        Ok(FileInfo {
            cnid,
            identity_cnid,
            node,
            kind,
            attributes,
            ea_size: 0,
            size: if kind == Kind::File && !special {
                compression.map_or_else(|| volume::be64(&b, 88), |info| info.0)
            } else {
                0
            },
            allocation_size: if kind == Kind::File && !special {
                u64::from(if compression.is_some_and(|info| info.1) {
                    volume::be32(&b, 180)
                } else {
                    volume::be32(&b, 100)
                }) * u64::from(self.fs.block_size())
            } else {
                0
            },
            creation_time: dates[0],
            access_time: dates[1],
            write_time: dates[2],
            change_time: dates[3],
            mac_mode: mode,
            mac_uid: volume::be32(&b, 32),
            mac_gid: volume::be32(&b, 36),
        })
    }
    fn names(&mut self, cnid: u32) -> Result<Arc<DirectoryNames>> {
        // Keep the live metadata read before every cache hit: a disconnected
        // device or changed header must not be hidden by a saved directory map.
        if self.info(cnid)?.kind != Kind::Directory {
            return Err(error(Status::NotDirectory, "parent is a file"));
        }
        let generation = self.readonly_generation.map(|(state, _)| state);
        if let Some(current) = generation
            && let Some((saved, names)) = self.readonly_directory_names.get(&cnid)
            && *saved == current
        {
            return Ok(names.clone());
        }
        let directory = self.path(cnid)?;
        let entries = self
            .fs
            .list_path(&mut self.device, &directory)
            .map_err(engine_error)?;
        for entry in &entries {
            if mac_private_root_name(cnid, &entry.name) {
                if volume::be16(&self.body(entry.inode)?, 0) != 1 {
                    return Err(error(
                        Status::IoError,
                        "Mac private root entry is not a directory",
                    ));
                }
                continue;
            }
            let path = format!("{}/{}", directory.trim_end_matches('/'), entry.name);
            if self.path(entry.inode)? != path {
                return Err(error(Status::IoError, "directory name/identity mismatch"));
            }
        }
        let names = Arc::new(
            DirectoryNames::build(
                entries
                    .into_iter()
                    .filter(|e| Some(e.inode) != self.holding)
                    .filter(|e| !mac_private_root_name(cnid, &e.name))
                    .map(|e| (e.inode, e.name)),
            )
            .map_err(|e| error(Status::Unsupported, e))?,
        );
        if let Some(generation) = generation
            && names.entries().len() <= 65_536
        {
            // Retain only a bounded set of immutable, fully validated views.
            let entries: usize = self
                .readonly_directory_names
                .values()
                .map(|(_, view)| view.entries().len())
                .sum();
            if self.readonly_directory_names.len() >= 32 || entries + names.entries().len() > 65_536
            {
                self.readonly_directory_names.clear();
            }
            self.readonly_directory_names
                .insert(cnid, (generation, names.clone()));
        }
        Ok(names)
    }
    fn symbolic_windows_target(&mut self, cnid: u32) -> Result<(String, bool)> {
        let link_path = self.path(cnid)?;
        let parent = link_path
            .rsplit_once('/')
            .unwrap()
            .0
            .split('/')
            .filter(|part| !part.is_empty())
            .map(str::to_owned)
            .collect::<Vec<_>>();
        let target = self
            .fs
            .read_symlink_target(&mut self.device, cnid)
            .map_err(engine_error)?;
        let declared_directory = if target.len() <= 1024 {
            self.fs
                .fixed_inline_attribute(
                    &mut self.device,
                    cnid,
                    crate::links::KIND_ATTRIBUTE,
                    13 + target.len(),
                )
                .map_err(engine_error)?
                .as_deref()
                .and_then(|bytes| crate::links::recorded_kind(bytes, cnid, &target))
        } else {
            None
        };
        let mut parts = crate::links::normalize_target(&parent, &target)?;
        // Intermediate Mac links are resolved before translating remaining aliases.
        // The leaf is retained as a link so cycles remain inspectable; WinFsp
        // bounds native leaf resolution. No target can address another volume.
        for _ in 0..32 {
            let mut directory = 2;
            let mut windows = Vec::new();
            let mut restart = false;
            let mut leaf_directory = parts.is_empty();
            for (index, part) in parts.iter().enumerate() {
                let view = self.names(directory)?;
                let raw_path = format!("{}/{}", self.path(directory)?.trim_end_matches('/'), part);
                let body = match self.fs.catalog_record(&raw_path) {
                    Ok(body) => body,
                    Err(fstool::Error::InvalidArgument(message))
                        if message == "hfs+: catalog entry does not exist" =>
                    {
                        for missing in &parts[index..] {
                            windows.push(
                                names::new_windows_component(missing)
                                    .map_err(|e| error(Status::Unsupported, e))?,
                            );
                        }
                        leaf_directory = false;
                        break;
                    }
                    Err(e) => return Err(engine_error(e)),
                };
                let id = volume::be32(&body, 8);
                let entry = view
                    .entries()
                    .iter()
                    .find(|entry| entry.cnid == id)
                    .ok_or_else(|| {
                        error(
                            Status::AccessDenied,
                            "link target is outside the public image namespace",
                        )
                    })?;
                windows.push(entry.windows_name.clone());
                leaf_directory = volume::be16(&body, 0) == 1;
                if index + 1 < parts.len() {
                    let symbolic = volume::be16(&body, 0) == 2
                        && (&body[48..56] == b"slnkrhap"
                            || volume::be16(&body, 42) & 0xf000 == 0xa000);
                    if symbolic {
                        let parent = self
                            .path(id)?
                            .rsplit_once('/')
                            .unwrap()
                            .0
                            .split('/')
                            .filter(|part| !part.is_empty())
                            .map(str::to_owned)
                            .collect::<Vec<_>>();
                        let target = self
                            .fs
                            .read_symlink_target(&mut self.device, id)
                            .map_err(engine_error)?;
                        let mut next = crate::links::normalize_target(&parent, &target)?;
                        next.extend_from_slice(&parts[index + 1..]);
                        parts = next;
                        restart = true;
                        break;
                    }
                    if !leaf_directory {
                        return Err(error(
                            Status::NotDirectory,
                            "link target traverses a nondirectory",
                        ));
                    }
                    directory = id;
                }
            }
            if restart {
                continue;
            }
            let mut relative = vec!["..".to_owned(); parent.len()];
            relative.extend(windows);
            let target = if relative.is_empty() {
                ".".to_owned()
            } else {
                relative.join("\\")
            };
            return Ok((target, declared_directory.unwrap_or(leaf_directory)));
        }
        Err(error(
            Status::Unsupported,
            "intermediate symbolic-link chain exceeds32 steps",
        ))
    }
    pub fn reparse_by_path(&mut self, path: &str) -> Result<Option<Vec<u8>>> {
        self.healthy()?;
        if path.contains(':') {
            return Ok(None);
        }
        let cnid = self.resolve(path)?;
        self.reparse_cnid(cnid)
    }
    fn reparse_cnid(&mut self, cnid: u32) -> Result<Option<Vec<u8>>> {
        match self.info(cnid)?.node {
            crate::links::Node::SymbolicLink => {
                let (target, _) = self.symbolic_windows_target(cnid)?;
                Ok(Some(crate::links::symbolic_packet(&target)?))
            }
            crate::links::Node::Fifo => {
                let mut packet = 0x80000024u32.to_le_bytes().to_vec();
                packet.extend_from_slice(&[0; 4]);
                Ok(Some(packet))
            }
            _ => Ok(None),
        }
    }
    pub fn reparse_by_handle(&mut self, handle: Handle) -> Result<Option<Vec<u8>>> {
        self.healthy()?;
        let context = self.context(handle)?;
        if context.resource
            || context.finder
            || context.archive.is_some()
            || context.named.is_some()
        {
            return Ok(None);
        }
        self.reparse_cnid(context.cnid)
    }
    fn resolve_parts(&mut self, parts: &[&str]) -> Result<u32> {
        let mut cnid = 2;
        for part in parts {
            if self.pending_name(cnid, part)? {
                return Err(error(Status::DeletePending, "name awaits final close"));
            }
            cnid = self
                .names(cnid)?
                .resolve(part)
                .map_err(|e| error(Status::NotFound, e))?
                .cnid;
            if self.pending_delete.contains_key(&cnid) {
                return Err(error(Status::DeletePending, "entry awaits final close"));
            }
        }
        Ok(cnid)
    }
    fn resolve(&mut self, path: &str) -> Result<u32> {
        self.resolve_parts(&components(path)?)
    }
    fn new_target(&mut self, path: &str, same: Option<u32>) -> Result<(u32, String)> {
        let parts = components(path)?;
        let (name, prefix) = parts
            .split_last()
            .ok_or_else(|| error(Status::AccessDenied, "cannot replace volume root"))?;
        let name = names::new_windows_component(name).map_err(|e| error(Status::InvalidName, e))?;
        let parent = self.resolve_parts(prefix)?;
        if self.pending_name(parent, &name)? {
            return Err(error(Status::DeletePending, "name awaits final close"));
        }
        if parent == 2
            && names::same_windows_name(&name, deferred::DIRECTORY)
                .map_err(|e| error(Status::InvalidName, e))?
        {
            return Err(error(Status::AccessDenied, "reserved recovery directory"));
        }
        if self.namespace_locked(parent)? {
            return Err(error(Status::AccessDenied, "parent is locked"));
        }
        if let Ok(existing) = self.names(parent)?.resolve(&name) {
            if self.pending_delete.contains_key(&existing.cnid) {
                return Err(error(Status::DeletePending, "name is pending deletion"));
            }
            if Some(existing.cnid) != same {
                return Err(error(Status::Collision, "Windows name already exists"));
            }
        }
        let path = format!("{}/{}", self.path(parent)?.trim_end_matches('/'), name);
        // HFS equivalence can be broader than Windows ordinal comparison.
        if let Ok(b) = self.fs.catalog_record(&path)
            && Some(volume::be32(&b, 8)) != same
        {
            return Err(error(
                Status::Collision,
                "equivalent HFS name already exists",
            ));
        }
        Ok((parent, path))
    }
    fn context(&self, handle: Handle) -> Result<Context> {
        self.handles
            .get(&handle)
            .copied()
            .ok_or_else(|| error(Status::InvalidHandle, "closed or unknown handle"))
    }
    fn check_open(&mut self, cnid: u32, request: OpenRequest, stream: Stream) -> Result<()> {
        self.check_open_inner(cnid, request, stream, false)
    }
    fn check_open_inner(
        &mut self,
        cnid: u32,
        request: OpenRequest,
        stream: Stream,
        reparse: bool,
    ) -> Result<()> {
        let info = self.info(cnid)?;
        let link_namespace =
            reparse && stream == Stream::Data && info.node == crate::links::Node::SymbolicLink;
        if info.node != crate::links::Node::Ordinary
            && (request.access.write
                || request.access.append
                || (request.access.delete && !link_namespace)
                || (request.access.metadata && !link_namespace)
                || request.access.write_ea)
        {
            return Err(error(
                Status::AccessDenied,
                "existing links and special nodes are read-only",
            ));
        }
        if self.body(cnid)?[41] & 0x20 != 0
            && (request.access.metadata || request.access.write_ea)
            && !(request.access.write || request.access.append)
            && (request.access.write_ea
                || !self
                    .fs
                    .compressed_conversion_supported(&mut self.device, cnid)
                    .map_err(engine_error)?)
        {
            return Err(error(
                Status::AccessDenied,
                "compressed metadata is currently read-only",
            ));
        }
        if let Some(kind) = request.kind
            && kind != info.kind
        {
            return Err(error(
                if info.kind == Kind::Directory {
                    Status::IsDirectory
                } else {
                    Status::NotDirectory
                },
                "open kind mismatch",
            ));
        }
        if self.namespace_locked(cnid)?
            && (request.access.write || request.access.append || request.access.delete)
        {
            return Err(error(Status::AccessDenied, "entry is locked"));
        }
        for old in self.handles.values().filter(|c| {
            !c.cleaned
                && (c.cnid == cnid
                    || (info.node == crate::links::Node::HardLink
                        && c.identity_cnid == info.identity_cnid))
        }) {
            let a = request.access;
            let b = old.access;
            // Metadata-only opens do not enter Windows data-sharing counts.
            if !a.participates_in_sharing() || !b.participates_in_sharing() {
                continue;
            }
            let old_stream = old.stream();
            let same_stream =
                stream == old_stream && !old.archive.is_some_and(|id| self.archives[&id].detached);
            // Read/write sharing belongs to a stream. Base-file DELETE access
            // additionally requires delete sharing from every open stream, in
            // either open order. A detached archive has its own retained id.
            if (same_stream
                && ((a.read && !old.share.read)
                    || ((a.write || a.append) && !old.share.write)
                    || (b.read && !request.share.read)
                    || ((b.write || b.append) && !request.share.write)))
                || ((same_stream || stream == Stream::Data) && a.delete && !old.share.delete)
                || ((same_stream || old_stream == Stream::Data)
                    && b.delete
                    && !request.share.delete)
            {
                return Err(error(
                    Status::SharingViolation,
                    "incompatible access/share modes",
                ));
            }
        }
        Ok(())
    }
    fn handle_slot(&self) -> Result<Handle> {
        self.next_handle
            .checked_add(1)
            .ok_or_else(|| error(Status::Busy, "handle space exhausted"))?;
        Ok(Handle(self.next_handle))
    }
    fn add_handle(&mut self, cnid: u32, request: OpenRequest) -> Result<Handle> {
        let handle = self.handle_slot()?;
        let identity_cnid = self.metadata_cnid(cnid)?;
        self.next_handle += 1;
        self.handles.insert(
            handle,
            Context {
                cnid,
                identity_cnid,
                access: request.access,
                share: request.share,
                cleaned: false,
                resource: false,
                finder: false,
                archive: None,
                named: None,
                explicit_times: 0,
                display_cnid: None,
                reparse: false,
            },
        );
        Ok(handle)
    }
    pub fn open(&mut self, path: &str, request: OpenRequest) -> Result<Handle> {
        self.healthy()?;
        if let Some((base, name)) = named_path(path)? {
            return self.open_named(base, name, request, false, 0);
        }
        if let Some(base) = archive_path(path) {
            return self.open_archive(base, request, false, 0);
        }
        let finder = finder_path(path);
        let (base, resource) = stream_path(finder.unwrap_or(path))?;
        let cnid = self.resolve(base)?;
        let stream = if finder.is_some() {
            Stream::Finder
        } else if resource {
            Stream::Resource
        } else {
            Stream::Data
        };
        self.check_open(cnid, request, stream)?;
        if (resource || finder.is_some())
            && self.body(cnid)?[41] & 0x20 != 0
            && (request.access.write
                || request.access.append
                || request.access.metadata
                || request.access.write_ea
                || request.access.delete)
        {
            return Err(error(
                Status::AccessDenied,
                "compressed metadata streams require ordinary-data conversion first",
            ));
        }
        if finder.is_some() {
            if self.info(cnid)?.kind != Kind::File {
                return Err(error(
                    Status::Unsupported,
                    "directory Finder streams are not supported",
                ));
            }
            if !self.finder_present(cnid)? {
                return Err(error(Status::NotFound, "Finder stream is absent"));
            }
            let handle = self.add_handle(cnid, request)?;
            self.handles.get_mut(&handle).unwrap().finder = true;
            return Ok(handle);
        }
        if resource {
            let info = self.fork_info(cnid, true)?;
            if info.size == 0
                && info.allocation_size == 0
                && !self.handles.values().any(|c| c.cnid == cnid && c.resource)
            {
                return Err(error(Status::NotFound, "resource stream is absent"));
            }
        }
        let handle = self.add_handle(cnid, request)?;
        self.handles.get_mut(&handle).unwrap().resource = resource;
        Ok(handle)
    }
    pub fn create(&mut self, path: &str, kind: Kind, request: OpenRequest) -> Result<Handle> {
        self.create_initialized(path, kind, request, None, 0)
    }
    /// Creation attributes/allocation are internal creation metadata, independent
    /// of the granted rights for subsequent operations on the returned handle.
    pub fn create_initialized(
        &mut self,
        path: &str,
        kind: Kind,
        request: OpenRequest,
        attributes: Option<u32>,
        allocation: u64,
    ) -> Result<Handle> {
        self.create_initialized_with_ea(path, kind, request, attributes, allocation, &[])
    }
    pub fn create_initialized_with_ea(
        &mut self,
        path: &str,
        kind: Kind,
        request: OpenRequest,
        attributes: Option<u32>,
        allocation: u64,
        initial: &[crate::ea::Change],
    ) -> Result<Handle> {
        Self::reject_private_changes(initial)?;
        self.create_entry(path, kind, request, attributes, allocation, initial)
    }
    fn create_entry(
        &mut self,
        path: &str,
        kind: Kind,
        request: OpenRequest,
        attributes: Option<u32>,
        allocation: u64,
        initial: &[crate::ea::Change],
    ) -> Result<Handle> {
        self.healthy()?;
        if let Some((base, name)) = named_path(path)? {
            if kind != Kind::File || !initial.is_empty() {
                return Err(error(
                    Status::Unsupported,
                    "named streams require file creation without EAs",
                ));
            }
            return self.open_named(base, name, request, true, allocation);
        }
        if let Some(base) = archive_path(path) {
            if kind != Kind::File || !initial.is_empty() {
                return Err(error(
                    Status::Unsupported,
                    "metadata stream requires file creation without EAs",
                ));
            }
            return self.open_archive(base, request, true, allocation);
        }
        let finder = finder_path(path);
        let (base, resource) = stream_path(finder.unwrap_or(path))?;
        if finder.is_some() {
            if kind != Kind::File || !initial.is_empty() {
                return Err(error(
                    Status::Unsupported,
                    "Finder stream creation requires an ordinary file and no EAs",
                ));
            }
            let cnid = self.resolve(base)?;
            self.check_open(cnid, request, Stream::Finder)?;
            if self.info(cnid)?.kind != Kind::File || self.info(cnid)?.attributes & 1 != 0 {
                return Err(error(
                    Status::AccessDenied,
                    "Finder stream target is locked or not a file",
                ));
            }
            if self.finder_present(cnid)? {
                return Err(error(Status::Collision, "Finder stream exists"));
            }
            self.validate_finder_allocation(allocation)?;
            let handle = self.add_handle(cnid, request)?;
            self.handles.get_mut(&handle).unwrap().finder = true;
            return Ok(handle);
        }
        if resource {
            if !initial.is_empty() {
                return Err(error(
                    Status::Unsupported,
                    "resource creation cannot replace base extended attributes",
                ));
            }
            if kind != Kind::File {
                return Err(error(Status::NotDirectory, "resource stream is a file"));
            }
            let cnid = self.resolve(base)?;
            self.check_open(cnid, request, Stream::Resource)?;
            if self.info(cnid)?.attributes & 1 != 0 {
                return Err(error(Status::AccessDenied, "base file is locked"));
            }
            let current = self.fork_info(cnid, true)?;
            if current.size != 0
                || current.allocation_size != 0
                || self.handles.values().any(|c| c.cnid == cnid && c.resource)
            {
                return Err(error(Status::Collision, "resource stream exists"));
            }
            if let Some(attrs) = attributes {
                self.validate_attributes(cnid, attrs)?;
            }
            self.validate_allocation(allocation, 0)?;
            self.handle_slot()?;
            let path = self.path(cnid)?;
            let precision = self.prepare_precision(&[], &[], None)?;
            let related = precision.references();
            let result = self.fs.edit_fork_with_publication(
                &mut self.device,
                Path::new(&path),
                true,
                fstool::fs::hfs_plus::ForkEdit::Allocate {
                    bytes: allocation,
                    truncate: false,
                },
                fstool::fs::hfs_plus::PublicationMetadata {
                    related: &related,
                    ..Default::default()
                },
            );
            self.publication_result(result)?;
            let handle = self.add_handle(cnid, request)?;
            self.handles.get_mut(&handle).unwrap().resource = true;
            return Ok(handle);
        }
        let path = base;
        let initial_values = self.creation_windows_attributes(kind, attributes, initial)?;
        let initial = initial_values.as_slice();
        self.handle_slot()?;
        if let Some(attributes) = attributes {
            Self::validate_attribute_bits(kind, attributes)?;
        }
        self.validate_allocation(allocation, 0)?;
        self.validate_constructor_ea_space(allocation, initial)?;
        if kind == Kind::Directory && allocation != 0 {
            return Err(error(Status::InvalidParameter, "directory allocation hint"));
        }
        if request.kind.is_some_and(|k| k != kind) {
            return Err(error(Status::InvalidParameter, "create kind mismatch"));
        }
        let (parent, path) = self.new_target(path, None)?;
        // A Windows token has no meaningful Mac UID. New entries retain the
        // destination folder's Mac ownership rather than inventing root-owned
        // children. Existing entries and their permissions are never changed.
        let parent_info = self.info(parent)?;
        let exact = now_filetime()?;
        let time = filetime_to_hfs(exact)?;
        let import = initial
            .iter()
            .filter(|c| c.name != crate::security_descriptor::ATTRIBUTE)
            .cloned()
            .collect();
        let initial = initial
            .iter()
            .map(|change| (change.name.as_str(), change.value.as_deref()))
            .collect::<Vec<_>>();
        let deferred_readonly = kind == Kind::File
            && attributes.is_some_and(|attributes| attributes & 1 != 0)
            && (request.access.write || request.access.append);
        let native = attributes.map(|attributes| {
            let attributes = attributes & !0x104;
            if deferred_readonly || (kind == Kind::Directory && self.windows_directory_hints) {
                attributes & !1
            } else {
                attributes
            }
        });
        let cnid = self.fs.creation_cnid(&path).map_err(engine_error)?;
        let catalog = [
            fstool::fs::hfs_plus::CatalogUpdate {
                cnid,
                times: [Some(time); 4],
                attributes: native,
            },
            fstool::fs::hfs_plus::CatalogUpdate {
                cnid: parent,
                times: [None, None, Some(time), Some(time)],
                attributes: None,
            },
        ];
        let precision = self.prepare_precision(
            &catalog,
            &[
                (cnid, [Some(exact); 4]),
                (parent, [None, None, Some(exact), Some(exact)]),
            ],
            Some((cnid, kind)),
        )?;
        let related = precision.references();
        let result = self.fs.create_entry_with_publication(
            &mut self.device,
            &path,
            cnid,
            kind == Kind::Directory,
            parent_info.mac_uid,
            parent_info.mac_gid,
            time - 2_082_844_800,
            allocation,
            fstool::fs::hfs_plus::PublicationMetadata {
                attributes: &initial,
                catalog: &catalog,
                related: &related,
            },
        );
        let cnid = self.publication_result(result)?;
        self.durable()?;
        let handle = self.add_handle(cnid, request)?;
        self.ea_import.insert(cnid, import);
        if deferred_readonly {
            self.readonly_on_close.insert(cnid);
        }
        Ok(handle)
    }
    pub fn file_info(&mut self, handle: Handle) -> Result<FileInfo> {
        self.healthy()?;
        let context = self.context(handle)?;
        let mut info = if context.named.is_some() {
            let (size, allocation) =
                self.with_named_record(context, |r| (r.data.len(), r.allocation))?;
            let mut info = self.info(context.cnid)?;
            info.kind = Kind::File;
            info.attributes &= !0x10;
            info.size = size as u64;
            info.allocation_size = allocation;
            info.ea_size = 0;
            info
        } else if let Some(id) = context.archive {
            let mut info = self.info(context.cnid)?;
            info.kind = Kind::File;
            info.attributes &= !0x10;
            info.size = self.archives[&id].data.len() as u64;
            info.allocation_size = 0;
            info
        } else if context.finder {
            self.finder_info(context.cnid)?
        } else {
            self.fork_info(context.cnid, context.resource)?
        };
        info.cnid = context.display_cnid.unwrap_or(info.cnid);
        info.identity_cnid = context.display_cnid.unwrap_or(info.identity_cnid);
        if context.finder
            || context.resource
            || context.archive.is_some()
            || context.named.is_some()
        {
            info.node = crate::links::Node::Ordinary;
            info.attributes &= !0x400;
        }
        Ok(info)
    }
    fn ea_values(&mut self, handle: Handle) -> Result<Vec<(String, Vec<u8>)>> {
        self.healthy()?;
        let context = self.context(handle)?;
        if context.resource
            || context.finder
            || context.archive.is_some()
            || context.named.is_some()
            || context.display_cnid.is_some()
        {
            return Err(error(
                Status::Unsupported,
                "extended attributes require a base-file context",
            ));
        }
        let mut values = Vec::new();
        let mut total = 0usize;
        let metadata_cnid = self.metadata_cnid(context.cnid)?;
        let compressed = self.body(metadata_cnid)?[41] & 0x20 != 0;
        for name in self.read_attribute_names(metadata_cnid)? {
            if name == crate::security_descriptor::ATTRIBUTE
                || crate::timestamps::is_private_attribute(&name)
                || name == crate::named_streams::ATTRIBUTE
                || (compressed && name == "com.apple.decmpfs")
            {
                continue;
            }
            let value = self
                .read_attribute(metadata_cnid, &name)?
                .ok_or_else(|| error(Status::IoError, "listed attribute is missing"))?;
            total = total
                .checked_add(value.len())
                .filter(|&n| n <= crate::attribute_archive::MAX_VALUE_BYTES)
                .ok_or_else(|| error(Status::Unsupported, "aggregate attributes exceed 16MiB"))?;
            if values.len() == crate::attribute_archive::MAX_RECORDS {
                return Err(error(Status::Unsupported, "too many attributes"));
            }
            values.push((name, value));
        }
        Ok(values)
    }
    /// Metadata size for native FileInfo, independent of FILE_READ_EA rights.
    pub fn file_info_with_ea(&mut self, handle: Handle) -> Result<FileInfo> {
        let mut info = self.file_info(handle)?;
        let context = self.context(handle)?;
        if !context.resource
            && !context.finder
            && context.archive.is_none()
            && context.named.is_none()
            && context.display_cnid.is_none()
        {
            let records = crate::ea::records(&self.ea_values(handle)?)?;
            info.ea_size = crate::ea::encode(&records)?.len() as u32;
        }
        Ok(info)
    }
    /// WinFsp keeps shared basic attributes on the main file node. Returning
    /// hidden/system on a stream response would reject its overwrite request
    /// (named-stream create attributes are always zero in the kernel protocol).
    #[cfg(feature = "native-mount")]
    pub(crate) fn file_info_native(&mut self, handle: Handle) -> Result<FileInfo> {
        let mut info = self.file_info_native_shared(handle)?;
        let context = self.context(handle)?;
        if context.finder
            || context.resource
            || context.archive.is_some()
            || context.named.is_some()
        {
            info.attributes = 0x80;
        }
        Ok(info)
    }
    /// Subsequent native responses update the shared main-file basic-info cache.
    /// The NORMAL-only mask is needed for stream open/overwrite admission, not
    /// for GetFileInfo or SetBasicInfo replies, which must retain real attributes.
    #[cfg(feature = "native-mount")]
    pub(crate) fn file_info_native_shared(&mut self, handle: Handle) -> Result<FileInfo> {
        let mut info = self.file_info(handle)?;
        let context = self.context(handle)?;
        if !context.resource
            && !context.finder
            && context.archive.is_none()
            && context.named.is_none()
            && context.display_cnid.is_none()
        {
            info.ea_size = crate::ea::encode(&self.native_ea_records(handle)?)?.len() as u32;
        }
        Ok(info)
    }
    pub fn extended_attributes(&mut self, handle: Handle) -> Result<Vec<crate::ea::Record>> {
        if !self.context(handle)?.access.read_ea {
            return Err(error(Status::AccessDenied, "FILE_READ_EA is required"));
        }
        crate::ea::records(&self.ea_values(handle)?)
    }
    pub fn set_extended_attributes(&mut self, handle: Handle, packet: &[u8]) -> Result<()> {
        self.healthy()?;
        let context = self.context(handle)?;
        if !context.access.write_ea {
            return Err(error(Status::AccessDenied, "FILE_WRITE_EA is required"));
        }
        self.check_archive_ea_edit(context.cnid)?;
        let names = self
            .ea_values(handle)?
            .into_iter()
            .map(|(name, _)| name)
            .collect::<Vec<_>>();
        let changes = crate::ea::changes(packet, &names)?;
        Self::reject_private_changes(&changes)?;
        let kind = self.info(context.cnid)?.kind;
        self.validate_windows_attribute_changes(kind, &changes)?;
        if changes.is_empty() {
            return Ok(());
        }
        let references = changes
            .iter()
            .map(|c| (c.name.as_str(), c.value.as_deref()))
            .collect::<Vec<_>>();
        let time = now_filetime()?;
        self.publish_entry_attributes(context.cnid, &references, time)?;
        if let Some(import) = self.ea_import.get_mut(&context.cnid) {
            for change in changes {
                import.retain(|old| old.name != change.name);
                import.push(change);
            }
        }
        Ok(())
    }
    /// Kernel-authorized create/overwrite metadata, independent of the rights
    /// granted to the resulting descriptor for later SetEa operations.
    #[cfg(all(windows, feature = "native-mount"))]
    pub(crate) fn creation_ea_changes(
        &mut self,
        handle: Handle,
        packet: &[u8],
    ) -> Result<Vec<crate::ea::Change>> {
        let names = self
            .ea_values(handle)?
            .into_iter()
            .map(|(name, _)| name)
            .collect::<Vec<_>>();
        crate::ea::changes(packet, &names)
    }
    /// Name lookup for kernel security checks, without allocating an open context.
    #[cfg(feature = "native-mount")]
    pub(crate) fn normalized_windows_path(&mut self, path: &str) -> Result<String> {
        self.healthy()?;
        let (base, suffix) = path
            .split_once(':')
            .map_or((path, ""), |(base, _)| (base, &path[base.len()..]));
        let mut cnid = 2;
        let mut spelling = Vec::new();
        for part in components(base)? {
            let view = self.names(cnid)?;
            let entry = view.resolve(part).map_err(|e| error(Status::NotFound, e))?;
            spelling.push(entry.windows_name.clone());
            cnid = entry.cnid;
        }
        if let Some((_, name)) = named_path(path)? {
            let store = self.named_store(cnid)?;
            let record = store
                .find(name)?
                .ok_or_else(|| error(Status::NotFound, "named stream absent"))?;
            return Ok(format!("\\{}:{}", spelling.join("\\"), record.name));
        }
        Ok(format!("\\{}{suffix}", spelling.join("\\")))
    }
    /// Name lookup for kernel security checks, without allocating an open context.
    pub fn path_info(&mut self, path: &str) -> Result<FileInfo> {
        self.healthy()?;
        if let Some((base, name)) = named_path(path)? {
            return self.named_info_path(base, name);
        }
        if let Some(base) = archive_path(path) {
            let cnid = self.resolve(base)?;
            return self.archive_info(cnid, None);
        }
        let finder = finder_path(path);
        let (base, resource) = stream_path(finder.unwrap_or(path))?;
        let cnid = self.resolve(base)?;
        if finder.is_some() {
            return self.finder_info(cnid);
        }
        self.fork_info(cnid, resource)
    }
    fn fork_info(&mut self, cnid: u32, resource: bool) -> Result<FileInfo> {
        let mut info = self.info(cnid)?;
        if resource {
            let metadata_cnid = self.metadata_cnid(cnid)?;
            if info.kind != Kind::File {
                return Err(error(
                    Status::IsDirectory,
                    "directory resource streams unsupported",
                ));
            }
            if self
                .fs
                .compressed_info(&mut self.device, metadata_cnid)
                .map_err(engine_error)?
                .is_some_and(|info| info.1)
            {
                info.size = 0;
                info.allocation_size = 0;
                return Ok(info);
            }
            let body = self.body(metadata_cnid)?;
            info.size = volume::be64(&body, 168);
            info.allocation_size =
                u64::from(volume::be32(&body, 180)) * u64::from(self.fs.block_size());
        }
        Ok(info)
    }
    pub fn streams(&mut self, handle: Handle) -> Result<Vec<(String, FileInfo)>> {
        self.healthy()?;
        let cnid = self.context(handle)?.cnid;
        let data = self.info(cnid)?;
        if matches!(
            data.node,
            crate::links::Node::SymbolicLink | crate::links::Node::Fifo
        ) {
            // These nodes expose reparse metadata rather than file streams.
            // In particular the private slnk/rhap marker is not Finder data.
            return Ok(Vec::new());
        }
        let archive = self.archive_info(cnid, None)?;
        let mut named = Vec::new();
        for record in &self.named_store(cnid)?.streams {
            let info = self.named_info_record(cnid, record)?;
            named.push((record.name.clone(), info));
        }
        if data.kind == Kind::Directory {
            if archive.size != 0 {
                named.insert(0, (crate::attribute_archive::STREAM.into(), archive));
            }
            return Ok(named);
        }
        let resource = self.fork_info(cnid, true)?;
        // WinFsp supplies the surrounding colon/$DATA syntax itself.
        let mut streams = vec![(String::new(), data)];
        if archive.size != 0 {
            streams.push((crate::attribute_archive::STREAM.into(), archive));
        }
        if self.finder_present(cnid)? {
            streams.push(("AFP_AfpInfo".into(), self.finder_info(cnid)?));
        }
        if resource.size != 0
            || resource.allocation_size != 0
            || self.handles.values().any(|c| c.cnid == cnid && c.resource)
        {
            streams.push(("AFP_Resource".into(), resource));
        }
        streams.extend(named);
        Ok(streams)
    }
    fn finder_info(&mut self, cnid: u32) -> Result<FileInfo> {
        let mut info = self.info(cnid)?;
        if info.kind != Kind::File {
            return Err(error(
                Status::Unsupported,
                "directory Finder streams are not supported",
            ));
        }
        info.size = 60;
        info.allocation_size = 0;
        info.ea_size = 0;
        Ok(info)
    }
    fn finder_present(&mut self, cnid: u32) -> Result<bool> {
        let cnid = self.metadata_cnid(cnid)?;
        Ok(fstool::fs::hfs_plus::attributes::public_finder_info(
            self.body(cnid)?[48..80].try_into().unwrap(),
        )
        .iter()
        .any(|b| *b != 0)
            || self.handles.values().any(|c| c.cnid == cnid && c.finder))
    }
    fn finder_bytes(&mut self, cnid: u32) -> Result<[u8; 60]> {
        let cnid = self.metadata_cnid(cnid)?;
        let body = self.body(cnid)?;
        crate::afp::encode(
            &fstool::fs::hfs_plus::attributes::public_finder_info(body[48..80].try_into().unwrap()),
            volume::be32(&body, 28),
        )
    }
    fn validate_finder_allocation(&self, allocation: u64) -> Result<()> {
        if allocation > 65536 || !allocation.is_multiple_of(u64::from(self.fs.block_size())) {
            return Err(error(
                Status::Unsupported,
                "Finder metadata has fixed catalog storage",
            ));
        }
        Ok(())
    }
    fn store_finder(&mut self, cnid: u32, value: &[u8; 32], backup: Option<u32>) -> Result<()> {
        let exact = now_filetime()?;
        let time = filetime_to_hfs(exact)?;
        let times = [None, None, None, Some(time)];
        let catalog = [fstool::fs::hfs_plus::CatalogUpdate {
            cnid,
            times,
            attributes: None,
        }];
        let precision =
            self.prepare_precision(&catalog, &[(cnid, [None, None, None, Some(exact)])], None)?;
        let related = precision.references();
        let result = self.fs.set_finder_info_with_publication(
            &mut self.device,
            cnid,
            value,
            backup,
            times,
            &related,
        );
        self.publication_result(result)?;
        self.durable()
    }
    pub fn block_size(&self) -> u32 {
        self.fs.block_size()
    }
    /// The directory buffer uses this only for the synthetic '..' entry.
    pub fn parent_info(&mut self, handle: Handle) -> Result<FileInfo> {
        self.healthy()?;
        let cnid = self.context(handle)?.cnid;
        let path = self.path(cnid)?;
        let parent = path.rsplit_once('/').unwrap().0;
        let parent = if parent.is_empty() {
            2
        } else {
            volume::be32(&self.fs.catalog_record(parent).map_err(engine_error)?, 8)
        };
        self.info(parent)
    }
    pub fn volume_info(&mut self) -> Result<VolumeInfo> {
        self.healthy()?;
        let facts = volume::inspect(&mut self.device).map_err(|e| error(Status::IoError, e))?;
        Ok(VolumeInfo {
            label: self.fs.volume_name().into(),
            total_bytes: self.fs.total_bytes(),
            free_bytes: u64::from(facts.header.free_blocks) * u64::from(self.fs.block_size()),
        })
    }
    /// Persist a Windows-visible label without changing volume identity or files.
    pub fn set_volume_label(&mut self, label: &str) -> Result<()> {
        self.healthy()?;
        let units = fstool::fs::hfs_plus::unicode::normalize_units(label);
        if units.is_empty()
            || units.len() > 32
            || label
                .chars()
                .any(|c| c.is_control() || "\\/:*?\"<>|".contains(c))
        {
            return Err(error(
                Status::InvalidName,
                "volume labels require 1..32 normalized UTF-16 units without reserved characters",
            ));
        }
        if self.namespace_locked(2)? {
            return Err(error(Status::AccessDenied, "volume root is locked"));
        }
        if units == fstool::fs::hfs_plus::unicode::normalize_units(self.fs.volume_name()) {
            return Ok(());
        }
        // Validation and root rekeying issue no device writes. Refusals leave
        // the adapter usable; a publication failure follows the sticky policy.
        self.fs.set_volume_name(label).map_err(engine_error)?;
        self.publish_namespace()
    }
    pub fn read_directory(&mut self, handle: Handle) -> Result<Vec<DirectoryEntry>> {
        self.healthy()?;
        let context = self.context(handle)?;
        if context.named.is_some() {
            return Err(error(
                Status::NotDirectory,
                "named stream cannot enumerate a directory",
            ));
        }
        if !context.access.read {
            return Err(error(Status::AccessDenied, "handle cannot enumerate"));
        }
        let view = self.names(context.cnid)?;
        let mut entries = Vec::new();
        for entry in view.entries() {
            if !self.pending_delete.contains_key(&entry.cnid) {
                entries.push(DirectoryEntry {
                    name: entry.windows_name.clone(),
                    aliased: entry.aliased,
                    info: self.info(entry.cnid)?,
                });
            }
        }
        // Native binding will page this snapshot through WinFsp's directory
        // buffer helper. No marker is compared against changing live listings.
        Ok(entries)
    }
    /// Resolve one visible child without loading every sibling's metadata.
    /// Use the same alias map and deletion filter as full enumeration.
    pub fn directory_entry(&mut self, handle: Handle, name: &str) -> Result<DirectoryEntry> {
        self.healthy()?;
        let context = self.context(handle)?;
        if context.named.is_some() {
            return Err(error(
                Status::NotDirectory,
                "named stream cannot enumerate a directory",
            ));
        }
        if !context.access.read {
            return Err(error(Status::AccessDenied, "handle cannot enumerate"));
        }
        let parent = context.cnid;
        if self.info(parent)?.kind != Kind::Directory {
            return Err(error(Status::NotDirectory, "parent is a file"));
        }
        if name == "." || name == ".." {
            if parent == 2 {
                return Err(error(Status::NotFound, "root has no dot entries"));
            }
            return Ok(DirectoryEntry {
                name: name.into(),
                aliased: false,
                info: if name == "." {
                    self.info(parent)?
                } else {
                    self.parent_info(handle)?
                },
            });
        }
        if !names::windows_component(name) {
            return Err(error(
                Status::InvalidName,
                "expected one Windows directory component",
            ));
        }
        let view = self.names(parent)?;
        let entry = view.resolve(name).map_err(|e| error(Status::NotFound, e))?;
        if self.pending_delete.contains_key(&entry.cnid) {
            return Err(error(Status::NotFound, "entry is absent from enumeration"));
        }
        Ok(DirectoryEntry {
            name: entry.windows_name.clone(),
            aliased: entry.aliased,
            info: self.info(entry.cnid)?,
        })
    }
    pub fn read(&mut self, handle: Handle, offset: u64, buffer: &mut [u8]) -> Result<usize> {
        self.read_inner(handle, offset, buffer, false)
    }
    /// WinFsp checks user read access before dispatch. The cache manager can
    /// issue an authorized paging read on a descriptor opened only for writes.
    #[cfg(feature = "native-mount")]
    pub(crate) fn read_native(
        &mut self,
        handle: Handle,
        offset: u64,
        buffer: &mut [u8],
    ) -> Result<usize> {
        self.read_inner(handle, offset, buffer, true)
    }
    fn read_inner(
        &mut self,
        handle: Handle,
        offset: u64,
        buffer: &mut [u8],
        kernel_authorized: bool,
    ) -> Result<usize> {
        self.healthy()?;
        let context = self.context(handle)?;
        if !context.access.read && !kernel_authorized {
            return Err(error(Status::AccessDenied, "handle cannot read"));
        }
        if context.named.is_some() {
            return self.with_named_record(context, |record| {
                let start = offset.min(record.data.len() as u64) as usize;
                let count = buffer.len().min(record.data.len() - start);
                buffer[..count].copy_from_slice(&record.data[start..start + count]);
                count
            });
        }
        if let Some(id) = context.archive {
            return self.archive_read(id, offset, buffer);
        }
        let info = self.info(context.cnid)?;
        if matches!(
            info.node,
            crate::links::Node::SymbolicLink | crate::links::Node::Fifo
        ) {
            return Err(error(
                Status::Unsupported,
                "reparse nodes do not expose ordinary data streams",
            ));
        }
        if info.kind != Kind::File {
            return Err(error(Status::IsDirectory, "cannot read a directory"));
        }
        if context.finder {
            let bytes = self.finder_bytes(context.cnid)?;
            let start = usize::try_from(offset.min(60)).unwrap();
            let count = buffer.len().min(60 - start);
            buffer[..count].copy_from_slice(&bytes[start..start + count]);
            return Ok(count);
        }
        let path = self.path(context.cnid)?;
        if context.resource {
            if self.fork_info(context.cnid, true)?.size == 0 {
                return Ok(0);
            }
            let mut file = self
                .fs
                .open_resource_fork_reader(&mut self.device, &path)
                .map_err(engine_error)?;
            file.seek(SeekFrom::Start(offset))
                .map_err(|e| error(Status::IoError, e))?;
            return file.read(buffer).map_err(|e| error(Status::IoError, e));
        }
        let mut file = self
            .fs
            .open_file_ro(&mut self.device, Path::new(&path))
            .map_err(engine_error)?;
        file.seek(SeekFrom::Start(offset))
            .map_err(|e| error(Status::IoError, e))?;
        file.read(buffer).map_err(|e| error(Status::IoError, e))
    }
    fn editable(&mut self, handle: Handle) -> Result<(Context, FileInfo)> {
        let context = self.context(handle)?;
        let info = self.file_info(handle)?;
        if info.kind != Kind::File {
            return Err(error(Status::IsDirectory, "cannot edit a directory"));
        }
        if info.attributes & 1 != 0 || info.node != crate::links::Node::Ordinary {
            return Err(error(Status::AccessDenied, "file is locked"));
        }
        Ok((context, info))
    }
    fn compressed_data_context(&self, context: Context) -> Result<bool> {
        Ok(!context.resource
            && !context.finder
            && context.archive.is_none()
            && context.named.is_none()
            && self.body(context.cnid)?[41] & 0x20 != 0)
    }
    fn validate_compressed_space(&mut self, context: Context, size: u64) -> Result<()> {
        let block = u64::from(self.fs.block_size());
        self.validate_allocation(size.div_ceil(block) * block, 0)?;
        self.fs
            .validate_compressed_replacement(&mut self.device, context.cnid, size)
            .map_err(engine_error)
    }
    /// Writes use explicit offsets. Append is calculated while the serialized
    /// owner is held; constrained I/O clips at EOF and never extends the file.
    pub fn write(
        &mut self,
        handle: Handle,
        offset: u64,
        bytes: &[u8],
        append: bool,
        constrained: bool,
    ) -> Result<usize> {
        self.healthy()?;
        let (context, info) = self.editable(handle)?;
        if !(context.access.write || (append && context.access.append)) {
            return Err(error(
                Status::AccessDenied,
                "handle cannot perform this write",
            ));
        }
        let offset = if append { info.size } else { offset };
        let bytes = if constrained {
            &bytes[..bytes.len().min(info.size.saturating_sub(offset) as usize)]
        } else {
            bytes
        };
        if bytes.is_empty() {
            return Ok(0);
        }
        let end = offset
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| error(Status::InvalidParameter, "write offset overflow"))?;
        if context.named.is_some() {
            self.edit_named(
                context,
                |store, id, unit| {
                    store
                        .into_write(id, offset, bytes, false, false, unit)
                        .map(|(store, _)| store)
                },
                Some(now_filetime()?),
                true,
            )?;
            return Ok(bytes.len());
        }
        if let Some(id) = context.archive {
            return self.archive_write(id, offset, bytes);
        }
        if context.finder {
            if end > 60 {
                return Err(error(
                    Status::Unsupported,
                    "Finder metadata stream has fixed 60-byte length",
                ));
            }
            let mut data = self.finder_bytes(context.cnid)?;
            data[offset as usize..end as usize].copy_from_slice(bytes);
            let (finder, backup) = crate::afp::decode(&data)?;
            self.store_finder(context.cnid, &finder, Some(backup))?;
            return Ok(bytes.len());
        }
        if end > self.fs.total_bytes() {
            return Err(error(Status::DiskFull, "write exceeds volume capacity"));
        }
        let compressed = self.compressed_data_context(context)?;
        if compressed {
            self.validate_compressed_space(context, info.size.max(end))?;
        } else {
            self.validate_edit_space(&info, offset.min(info.size), end)?;
        }
        let exact = now_filetime()?;
        let time = filetime_to_hfs(exact)?;
        let path = self.path(context.cnid)?;
        let update = fstool::fs::hfs_plus::CatalogUpdate {
            cnid: context.cnid,
            times: [None, None, Some(time), Some(time)],
            attributes: self
                .native_windows_attributes(context.cnid, Some(info.attributes | 0x20))
                .map_err(engine_error)?,
        };
        let precision = self.prepare_precision(
            &[update],
            &[(context.cnid, [None, None, Some(exact), Some(exact)])],
            None,
        )?;
        let related = precision.references();
        let result = if compressed {
            self.fs.patch_compressed_with_publication(
                &mut self.device,
                Path::new(&path),
                offset,
                bytes,
                fstool::fs::hfs_plus::PublicationMetadata {
                    catalog: &[update],
                    related: &related,
                    ..Default::default()
                },
            )
        } else {
            self.fs
                .edit_fork_with_publication(
                    &mut self.device,
                    Path::new(&path),
                    context.resource,
                    fstool::fs::hfs_plus::ForkEdit::Write { offset, bytes },
                    fstool::fs::hfs_plus::PublicationMetadata {
                        catalog: &[update],
                        related: &related,
                        ..Default::default()
                    },
                )
                .map(|_| ())
        };
        self.mutated(result)?;
        Ok(bytes.len())
    }
    pub fn set_size(&mut self, handle: Handle, size: u64) -> Result<()> {
        self.healthy()?;
        let (context, info) = self.editable(handle)?;
        if !context.access.write {
            return Err(error(Status::AccessDenied, "handle cannot resize"));
        }
        if context.named.is_some() {
            if size == info.size {
                return Ok(());
            }
            return self.edit_named(
                context,
                |store, id, unit| store.with_size(id, size, unit),
                Some(now_filetime()?),
                true,
            );
        }
        if let Some(id) = context.archive {
            return self.reset_archive(id, size);
        }
        if context.finder {
            return match size {
                60 => Ok(()),
                0 => self.store_finder(context.cnid, &[0; 32], Some(0)),
                _ => Err(error(
                    Status::Unsupported,
                    "Finder stream length must be 0 or 60",
                )),
            };
        }
        if size > self.fs.total_bytes() {
            return Err(error(Status::DiskFull, "size exceeds volume capacity"));
        }
        if size == info.size {
            return Ok(());
        }
        let compressed = self.compressed_data_context(context)?;
        if compressed {
            self.validate_compressed_space(context, size)?;
        } else if size > info.size {
            self.validate_edit_space(&info, info.size, size)?;
        }
        let exact = now_filetime()?;
        let time = filetime_to_hfs(exact)?;
        let path = self.path(context.cnid)?;
        let update = fstool::fs::hfs_plus::CatalogUpdate {
            cnid: context.cnid,
            times: [None, None, Some(time), Some(time)],
            attributes: self
                .native_windows_attributes(context.cnid, Some(info.attributes | 0x20))
                .map_err(engine_error)?,
        };
        let precision = self.prepare_precision(
            &[update],
            &[(context.cnid, [None, None, Some(exact), Some(exact)])],
            None,
        )?;
        let related = precision.references();
        let result = if compressed {
            self.fs.resize_compressed_with_publication(
                &mut self.device,
                Path::new(&path),
                size,
                fstool::fs::hfs_plus::PublicationMetadata {
                    catalog: &[update],
                    related: &related,
                    ..Default::default()
                },
            )
        } else {
            self.fs
                .edit_fork_with_publication(
                    &mut self.device,
                    Path::new(&path),
                    context.resource,
                    fstool::fs::hfs_plus::ForkEdit::Resize(size),
                    fstool::fs::hfs_plus::PublicationMetadata {
                        catalog: &[update],
                        related: &related,
                        ..Default::default()
                    },
                )
                .map(|_| ())
        };
        self.mutated(result)?;
        Ok(())
    }
    pub fn set_basic_times(&mut self, handle: Handle, times: BasicTimes) -> Result<()> {
        self.set_basic_info(handle, times, None)
    }
    fn validate_attribute_bits(kind: Kind, attributes: u32) -> Result<()> {
        if attributes & !0x1b7 != 0
            || (kind == Kind::File && attributes & 0x10 != 0)
            || (kind == Kind::Directory && attributes & 0x100 != 0)
        {
            return Err(error(Status::Unsupported, "unsupported Windows attributes"));
        }
        Ok(())
    }
    fn validate_attributes(&mut self, cnid: u32, attributes: u32) -> Result<()> {
        Self::validate_attribute_bits(self.info(cnid)?.kind, attributes)?;
        let body = self.body(cnid)?;
        if attributes & 1 == 0 && (body[40] | body[41]) & 6 != 0 {
            return Err(error(
                Status::AccessDenied,
                "protected Mac BSD flags cannot be cleared through Windows attributes",
            ));
        }
        Ok(())
    }
    pub fn set_basic_info(
        &mut self,
        handle: Handle,
        times: BasicTimes,
        attributes: Option<u32>,
    ) -> Result<()> {
        self.healthy()?;
        let context = self.context(handle)?;
        if !context.access.metadata {
            return Err(error(Status::AccessDenied, "handle cannot set timestamps"));
        }
        let exact = [times.creation, times.access, times.write, times.change];
        let times = exact.map(|t| {
            t.map(crate::timestamps::catalog_seconds)
                .transpose()
                .map_err(|e| error(Status::InvalidParameter, e))
        });
        let [a, b, c, d] = times;
        let times = [a?, b?, c?, d?]; // validate every date before staging any field
        if let Some(attributes) = attributes {
            self.validate_attributes(context.cnid, attributes)?;
        }
        if times.iter().all(Option::is_none) && attributes.is_none() {
            return Ok(());
        }
        if self.body(context.cnid)?[41] & 0x20 != 0
            && !self
                .fs
                .compressed_conversion_supported(&mut self.device, context.cnid)
                .map_err(engine_error)?
        {
            return Err(error(
                Status::AccessDenied,
                "unsupported compressed metadata target",
            ));
        }
        let changes = if let Some(attributes) = attributes {
            self.replacement_windows_attributes(context.cnid, attributes, &[])?
        } else {
            Vec::new()
        };
        if !changes.is_empty() {
            self.check_archive_ea_edit(context.cnid)?;
        }
        let native = self
            .native_windows_attributes(
                context.cnid,
                attributes.map(|attributes| {
                    if self.readonly_on_close.contains(&context.cnid) {
                        attributes & !1
                    } else {
                        attributes
                    }
                }),
            )
            .map_err(engine_error)?;
        let catalog = [fstool::fs::hfs_plus::CatalogUpdate {
            cnid: context.cnid,
            times,
            attributes: native,
        }];
        let precision = self.prepare_precision(&catalog, &[(context.cnid, exact)], None)?;
        let mut related = changes
            .iter()
            .map(|change| (context.cnid, change.name.as_str(), change.value.as_deref()))
            .collect::<Vec<_>>();
        related.extend(precision.references());
        let result = self.fs.set_basic_metadata_with_publication(
            &mut self.device,
            context.cnid,
            times,
            native,
            &related,
        );
        self.publication_result(result)?;
        self.durable()?;
        if attributes.is_some_and(|attributes| attributes & 1 == 0) {
            self.readonly_on_close.remove(&context.cnid);
        }
        for (index, value) in exact.iter().enumerate() {
            if value.is_some() {
                self.handles.get_mut(&handle).unwrap().explicit_times |= 1 << index;
            }
        }
        Ok(())
    }
    fn validate_allocation(&mut self, allocation: u64, current: u64) -> Result<()> {
        if !allocation.is_multiple_of(u64::from(self.fs.block_size())) {
            return Err(error(
                Status::InvalidParameter,
                "allocation size must be block aligned",
            ));
        }
        if allocation > current && allocation - current > self.volume_info()?.free_bytes {
            return Err(error(
                Status::DiskFull,
                "insufficient free space for allocation",
            ));
        }
        Ok(())
    }
    fn validate_constructor_ea_space(
        &mut self,
        allocation: u64,
        changes: &[crate::ea::Change],
    ) -> Result<()> {
        let refs = changes
            .iter()
            .map(|c| (c.name.as_str(), c.value.as_deref()))
            .collect::<Vec<_>>();
        let metadata = self
            .fs
            .inline_attribute_allocation_bytes(&refs)
            .map_err(engine_error)?;
        let combined = allocation
            .checked_add(metadata)
            .ok_or_else(|| error(Status::InvalidParameter, "combined allocation overflow"))?;
        self.validate_allocation(combined, 0)
    }
    /// Each callback opens a fresh editor. Protect blocks below committed EOF,
    /// including its partial last block; full reserved tail blocks stay hidden.
    /// Count growth plus visible blocks touched by payload or zero-filled holes,
    /// before the editor can stage allocation or poison a healthy volume.
    fn validate_edit_space(&mut self, info: &FileInfo, start: u64, end: u64) -> Result<()> {
        let block = u64::from(self.fs.block_size());
        let growth = end
            .max(info.size)
            .div_ceil(block)
            .saturating_sub(info.allocation_size / block);
        let visible_end = end
            .min(info.allocation_size)
            .div_ceil(block)
            .min(info.size.div_ceil(block));
        let replacements = visible_end.saturating_sub(start / block);
        let needed = growth
            .checked_add(replacements)
            .and_then(|n| n.checked_mul(block))
            .ok_or_else(|| error(Status::InvalidParameter, "edit allocation overflow"))?;
        if needed > self.volume_info()?.free_bytes {
            return Err(error(
                Status::DiskFull,
                "insufficient free space for copy-on-write edit",
            ));
        }
        Ok(())
    }
    pub fn set_allocation_size(&mut self, handle: Handle, allocation: u64) -> Result<()> {
        self.healthy()?;
        let (context, info) = self.editable(handle)?;
        if !context.access.write {
            return Err(error(
                Status::AccessDenied,
                "handle cannot reserve allocation",
            ));
        }
        if context.named.is_some() {
            let block = u64::from(self.fs.block_size());
            let rounded = allocation
                .div_ceil(block)
                .checked_mul(block)
                .ok_or_else(|| error(Status::InvalidParameter, "allocation overflow"))?;
            return self.edit_named(
                context,
                |store, id, unit| store.with_allocation(id, allocation, unit),
                Some(now_filetime()?),
                rounded < info.size,
            );
        }
        if context.archive.is_some() {
            return if allocation <= crate::attribute_archive::MAX_BYTES as u64 {
                Ok(())
            } else {
                Err(error(
                    Status::Unsupported,
                    "metadata stream allocation limit",
                ))
            };
        }
        if context.finder {
            return self.validate_finder_allocation(allocation);
        }
        self.validate_allocation(allocation, info.allocation_size)?;
        let path = self.path(context.cnid)?;
        let exact = now_filetime()?;
        let time = filetime_to_hfs(exact)?;
        let catalog = if allocation < info.size {
            vec![fstool::fs::hfs_plus::CatalogUpdate {
                cnid: context.cnid,
                times: [None, None, Some(time), Some(time)],
                attributes: self
                    .native_windows_attributes(context.cnid, Some(info.attributes | 0x20))
                    .map_err(engine_error)?,
            }]
        } else {
            Vec::new()
        };
        let precision = self.prepare_precision(
            &catalog,
            &[(context.cnid, [None, None, Some(exact), Some(exact)])],
            None,
        )?;
        let related = precision.references();
        let metadata = fstool::fs::hfs_plus::PublicationMetadata {
            catalog: &catalog,
            related: &related,
            ..Default::default()
        };
        let result = if self.compressed_data_context(context)? {
            self.fs.allocate_compressed_with_publication(
                &mut self.device,
                Path::new(&path),
                allocation,
                metadata,
            )
        } else {
            self.fs
                .edit_fork_with_publication(
                    &mut self.device,
                    Path::new(&path),
                    context.resource,
                    fstool::fs::hfs_plus::ForkEdit::Allocate {
                        bytes: allocation,
                        truncate: false,
                    },
                    metadata,
                )
                .map(|_| ())
        };
        self.publication_result(result)
    }
    /// Windows overwrite replaces the data fork, preserves the resource fork,
    /// and replaces or merges basic attributes after validating the full request.
    pub fn overwrite(
        &mut self,
        handle: Handle,
        attributes: u32,
        replace: bool,
        allocation: u64,
    ) -> Result<()> {
        self.overwrite_with_ea(handle, attributes, replace, allocation, &[])
    }
    /// Constructor EAs share the overwrite publication; later EA edits still
    /// require FILE_WRITE_EA on the opened descriptor.
    pub fn overwrite_with_ea(
        &mut self,
        handle: Handle,
        attributes: u32,
        replace: bool,
        allocation: u64,
        changes: &[crate::ea::Change],
    ) -> Result<()> {
        self.healthy()?;
        Self::reject_private_changes(changes)?;
        let (context, info) = self.editable(handle)?;
        if !context.access.write {
            return Err(error(Status::AccessDenied, "handle cannot overwrite"));
        }
        if context.named.is_some() {
            if !changes.is_empty() {
                return Err(error(Status::Unsupported, "named streams cannot carry EAs"));
            }
            return self.edit_named(
                context,
                |store, id, unit| {
                    store
                        .with_size(id, 0, unit)?
                        .with_allocation(id, allocation, unit)
                },
                Some(now_filetime()?),
                true,
            );
        }
        if let Some(id) = context.archive {
            if !changes.is_empty() || allocation > crate::attribute_archive::MAX_BYTES as u64 {
                return Err(error(
                    Status::Unsupported,
                    "metadata stream overwrite parameters",
                ));
            }
            return self.reset_archive(id, 0);
        }
        if context.finder {
            if !changes.is_empty() {
                return Err(error(
                    Status::Unsupported,
                    "Finder streams cannot carry EAs",
                ));
            }
            self.validate_finder_allocation(allocation)?;
            return self.store_finder(context.cnid, &[0; 32], Some(0));
        }
        let attributes = if replace {
            attributes
        } else {
            info.attributes | attributes
        };
        self.validate_attributes(context.cnid, attributes)?;
        if context.resource && !changes.is_empty() {
            return Err(error(
                Status::Unsupported,
                "resource streams cannot carry EAs",
            ));
        }
        let replacement = self.replacement_windows_attributes(context.cnid, attributes, changes)?;
        let changes = replacement.as_slice();
        // Overwriting the unnamed file removes its ordinary named streams.
        // Preserve the next ID and retain old open objects independently, so a
        // later same-name stream cannot be edited by an old metadata/mapping handle.
        let removed_streams = if !context.resource {
            self.named_store(context.cnid)?.as_ref().clone()
        } else {
            crate::named_streams::Store::default()
        };
        let empty_streams = if removed_streams.streams.is_empty() {
            None
        } else {
            Some(crate::named_streams::encode(
                &crate::named_streams::Store {
                    next_id: removed_streams.next_id,
                    streams: Vec::new(),
                },
            )?)
        };
        // Truncation retains old allocated blocks until publication. Do not count
        // those blocks as reusable space for the replacement allocation.
        self.validate_allocation(allocation, 0)?;
        self.validate_constructor_ea_space(allocation, changes)?;
        let exact = now_filetime()?;
        let time = filetime_to_hfs(exact)?;
        let path = self.path(context.cnid)?;
        if !changes.is_empty() {
            self.check_archive_ea_edit(context.cnid)?;
        }
        let mut references = changes
            .iter()
            .map(|c| (c.name.as_str(), c.value.as_deref()))
            .collect::<Vec<_>>();
        if let Some(bytes) = &empty_streams {
            references.push((crate::named_streams::ATTRIBUTE, Some(bytes.as_slice())));
        }
        let catalog = [fstool::fs::hfs_plus::CatalogUpdate {
            cnid: context.cnid,
            times: [None, None, Some(time), Some(time)],
            attributes: self
                .native_windows_attributes(context.cnid, Some((attributes | 0x20) & !1))
                .map_err(engine_error)?,
        }];
        let precision = self.prepare_precision(
            &catalog,
            &[(context.cnid, [None, None, Some(exact), Some(exact)])],
            None,
        )?;
        let related = precision.references();
        let metadata = fstool::fs::hfs_plus::PublicationMetadata {
            attributes: &references,
            catalog: &catalog,
            related: &related,
        };
        if self.compressed_data_context(context)? {
            let result = self.fs.replace_compressed_with_publication(
                &mut self.device,
                Path::new(&path),
                &mut std::io::empty(),
                0,
                allocation,
                metadata,
            );
            self.publication_result(result)?;
        } else {
            let result = self.fs.edit_fork_with_publication(
                &mut self.device,
                Path::new(&path),
                context.resource,
                fstool::fs::hfs_plus::ForkEdit::Allocate {
                    bytes: allocation,
                    truncate: true,
                },
                metadata,
            );
            // Overwrite changes dates/attributes even if its empty fork needs
            // no edit. The fork API deliberately ignores metadata on a no-op.
            if !self.publication_result(result)? {
                let result = self.fs.set_attributes_with_publication(
                    &mut self.device,
                    context.cnid,
                    metadata,
                );
                self.publication_result(result)?;
                self.durable()?;
            }
        }
        if !context.resource {
            self.ea_import.insert(context.cnid, changes.to_vec());
        }
        for record in removed_streams.streams {
            if self
                .handles
                .values()
                .any(|c| c.identity_cnid == context.identity_cnid && c.named == Some(record.id))
            {
                self.overwritten_named
                    .insert((context.identity_cnid, record.id));
                self.detached_named
                    .insert((context.identity_cnid, record.id), record);
            }
        }
        if attributes & 1 != 0 {
            self.readonly_on_close.insert(context.cnid);
        } else {
            self.readonly_on_close.remove(&context.cnid);
        }
        Ok(())
    }
    fn allow_namespace_change(&mut self, handle: Handle, context: Context) -> Result<()> {
        if self.info(context.cnid)?.node == crate::links::Node::SymbolicLink {
            if !context.reparse {
                return Err(error(
                    Status::AccessDenied,
                    "explicit reparse handle required",
                ));
            }
            // Complete conventional identity/ownership must be validated before
            // even a rename; a later timestamp refusal cannot follow staging.
            self.fs
                .validate_remove_attributes(&mut self.device, context.cnid)
                .map_err(engine_error)?;
        }
        if context.resource
            || context.finder
            || context.archive.is_some()
            || context.named.is_some()
            || context.display_cnid.is_some()
        {
            return Err(error(
                Status::Unsupported,
                "resource-stream rename/delete requires a separate lifetime protocol",
            ));
        }
        if !context.access.delete || context.cnid == 2 || self.namespace_locked(context.cnid)? {
            return Err(error(
                Status::AccessDenied,
                "handle cannot change this namespace entry",
            ));
        }
        if self.handles.iter().any(|(id, c)| {
            *id != handle
                && c.cnid == context.cnid
                && !c.cleaned
                && c.access.participates_in_sharing()
                && !c.share.delete
        }) {
            return Err(error(
                Status::SharingViolation,
                "an open handle denies rename/delete",
            ));
        }
        Ok(())
    }
    pub fn rename(&mut self, handle: Handle, destination: &str) -> Result<()> {
        self.rename_with_replace(handle, destination, false)
    }
    /// Replace only a closed regular file. Target reclamation, source rename and
    /// parent metadata are staged together and published by one metadata flush.
    pub fn rename_with_replace(
        &mut self,
        handle: Handle,
        destination: &str,
        replace: bool,
    ) -> Result<()> {
        self.rename_inner(handle, destination, replace, false)
    }
    #[cfg(feature = "native-mount")]
    pub(crate) fn rename_native(
        &mut self,
        handle: Handle,
        destination: &str,
        replace: bool,
    ) -> Result<()> {
        self.rename_inner(handle, destination, replace, true)
    }
    fn rename_inner(
        &mut self,
        handle: Handle,
        destination: &str,
        replace: bool,
        kernel_authorized: bool,
    ) -> Result<()> {
        self.healthy()?;
        let context = self.context(handle)?;
        self.allow_namespace_change(handle, context)?;
        if self.pending_delete.contains_key(&context.cnid) {
            return Err(error(Status::DeletePending, "entry awaits deletion"));
        }
        let source = self.path(context.cnid)?;
        let target = match self.resolve(destination) {
            Ok(cnid) if cnid != context.cnid => Some(cnid),
            Ok(_) => None,
            Err(e) if e.status == Status::NotFound => None,
            Err(e) => return Err(e),
        };
        if target.is_some() && !replace {
            return Err(error(Status::Collision, "destination already exists"));
        }
        let (parent, mut destination) = if let Some(target) = target {
            let parts = components(destination)?;
            let (_, prefix) = parts
                .split_last()
                .ok_or_else(|| error(Status::AccessDenied, "cannot replace volume root"))?;
            let parent = self.resolve_parts(prefix)?;
            if self.namespace_locked(parent)? {
                return Err(error(Status::AccessDenied, "destination parent is locked"));
            }
            (parent, self.path(target)?)
        } else {
            self.new_target(destination, Some(context.cnid))?
        };
        if let Some(target) = target {
            let target_info = self.info(target)?;
            if self.info(context.cnid)?.kind != Kind::File || target_info.kind != Kind::File {
                return Err(error(
                    Status::AccessDenied,
                    "replacement requires two regular files",
                ));
            }
            if target_info.attributes & 1 != 0 {
                return Err(error(Status::AccessDenied, "replacement target is locked"));
            }
            if self
                .handles
                .values()
                .any(|c| c.cnid == target && (!kernel_authorized || !c.cleaned))
            {
                return Err(error(
                    Status::SharingViolation,
                    "replacement target has live contexts",
                ));
            }
            // Aliases refer to the existing Mac name. Never create a literal alias
            // by replacing the target using its displayed Windows spelling.
            destination = self.path(target)?;
            self.fs
                .validate_remove_attributes(&mut self.device, target)
                .map_err(engine_error)?;
        }
        if source == destination {
            return Ok(());
        }
        if self.info(context.cnid)?.kind == Kind::Directory
            && destination.starts_with(&format!("{source}/"))
        {
            return Err(error(
                Status::InvalidParameter,
                "cannot move a directory into itself",
            ));
        }
        let old_parent = source.rsplit_once('/').unwrap().0;
        let old_parent = if old_parent.is_empty() {
            2
        } else {
            volume::be32(
                &self.fs.catalog_record(old_parent).map_err(engine_error)?,
                8,
            )
        };
        if self.namespace_locked(old_parent)? {
            return Err(error(Status::AccessDenied, "source parent is locked"));
        }
        let exact = now_filetime()?;
        let retained = if let Some(target) = target {
            if self.handles.values().any(|c| c.cnid == target) {
                let (holding, mut pending) = self.stage_deferred_delete(target)?;
                // The new source owns this name; the replaced mapping owns only
                // its retained CNID until final close.
                pending.parent = 0;
                pending.name.clear();
                Some((target, holding, pending))
            } else {
                let result = self.fs.remove(&mut self.device, &destination);
                self.mutated(result)?;
                None
            }
        } else {
            None
        };
        let result = self.fs.rename(&mut self.device, &source, &destination);
        self.mutated(result)?;
        for (cnid, contents) in [(context.cnid, false), (old_parent, true), (parent, true)] {
            self.stage_namespace_times(cnid, [None, None, contents.then_some(exact), Some(exact)]);
        }
        self.publish_namespace()?;
        if let Some((target, holding, pending)) = retained {
            self.holding = Some(holding);
            self.pending_delete.insert(target, pending);
        }
        Ok(())
    }
    /// Eligibility only: this never changes namespace, handle or device state.
    pub fn can_delete(&mut self, handle: Handle) -> Result<()> {
        self.healthy()?;
        let context = self.context(handle)?;
        self.can_delete_context(handle, context)
    }
    fn can_delete_context(&mut self, handle: Handle, context: Context) -> Result<()> {
        if context.named.is_some() {
            return self.can_delete_named(handle, context);
        }
        if let Some(id) = context.archive {
            if !context.access.delete || self.namespace_locked(context.cnid)? {
                return Err(error(Status::AccessDenied, "metadata stream cannot delete"));
            }
            if self.handles.iter().any(|(other, c)| {
                *other != handle
                    && c.archive == Some(id)
                    && !c.cleaned
                    && c.access.participates_in_sharing()
                    && !c.share.delete
            }) {
                return Err(error(
                    Status::SharingViolation,
                    "metadata stream denies deletion",
                ));
            }
            return Ok(());
        }
        if context.finder {
            if !context.access.delete || self.namespace_locked(context.cnid)? {
                return Err(error(Status::AccessDenied, "Finder stream cannot delete"));
            }
            if self.handles.iter().any(|(id, c)| {
                *id != handle
                    && c.cnid == context.cnid
                    && c.finder
                    && !c.cleaned
                    && c.access.participates_in_sharing()
                    && !c.share.delete
            }) {
                return Err(error(
                    Status::SharingViolation,
                    "Finder handle denies deletion",
                ));
            }
            return Ok(());
        }
        if context.resource {
            if !context.access.delete || self.namespace_locked(context.cnid)? {
                return Err(error(Status::AccessDenied, "resource handle cannot delete"));
            }
            if self.handles.iter().any(|(id, c)| {
                *id != handle
                    && c.cnid == context.cnid
                    && c.resource
                    && !c.cleaned
                    && c.access.participates_in_sharing()
                    && !c.share.delete
            }) {
                return Err(error(
                    Status::SharingViolation,
                    "resource handle denies deletion",
                ));
            }
            self.validate_resource_deletion(context.cnid)?;
            return Ok(());
        }
        if context.display_cnid.is_some() && self.pending_delete.contains_key(&context.cnid) {
            return Ok(());
        }
        self.allow_namespace_change(handle, context)?;
        let path = self.path(context.cnid)?;
        let parent = path.rsplit_once('/').unwrap().0;
        let parent = if parent.is_empty() {
            2
        } else {
            volume::be32(&self.fs.catalog_record(parent).map_err(engine_error)?, 8)
        };
        if self.namespace_locked(parent)? {
            return Err(error(Status::AccessDenied, "parent is locked"));
        }
        if self.info(context.cnid)?.kind == Kind::Directory
            && !self.names(context.cnid)?.entries().is_empty()
        {
            return Err(error(
                Status::DirectoryNotEmpty,
                "directory contains entries",
            ));
        }
        self.fs
            .validate_remove_attributes(&mut self.device, context.cnid)
            .map_err(engine_error)?;
        Ok(())
    }
    /// Durably unlink the original name, retaining a validated holding entry
    /// for post-cleanup I/O until the last context closes.
    pub fn cleanup(&mut self, handle: Handle, delete: bool) -> Result<()> {
        self.cleanup_inner(handle, delete, false)
    }
    /// The kernel already authorized disposition and may deliver its final
    /// delete cleanup through a different, non-DELETE-access file object.
    #[cfg(feature = "native-mount")]
    pub(crate) fn cleanup_native(&mut self, handle: Handle, flags: u32) -> Result<()> {
        if self.read_only {
            self.healthy()?;
            let context = self
                .handles
                .get_mut(&handle)
                .ok_or_else(|| error(Status::InvalidHandle, "unknown handle"))?;
            context.cleaned = true;
            return Ok(());
        }
        let delete = flags & 1 != 0;
        if !delete && flags & 2 != 0 {
            self.trim_native_allocation(handle)?;
        }
        self.cleanup_inner(handle, delete, true)
    }
    /// The kernel requests trimming on the last cleanup, which may belong to a
    /// read-only handle. Keep file size and timestamps; free only unused blocks.
    #[cfg(feature = "native-mount")]
    fn trim_native_allocation(&mut self, handle: Handle) -> Result<()> {
        self.healthy()?;
        let context = self.context(handle)?;
        if context.cleaned {
            return Err(error(Status::InvalidParameter, "duplicate cleanup"));
        }
        if context.named.is_some() {
            return self.trim_named(handle, context);
        }
        if context.finder || context.archive.is_some() {
            return Ok(());
        }
        let info = self.fork_info(context.cnid, context.resource)?;
        if info.kind != Kind::File
            || info.node != crate::links::Node::Ordinary
            || self
                .fs
                .compressed_info(&mut self.device, context.cnid)
                .map_err(engine_error)?
                .is_some()
            || self.handles.iter().any(|(id, other)| {
                *id != handle
                    && other.cnid == context.cnid
                    && !other.cleaned
                    && other.resource == context.resource
                    && !other.finder
                    && other.archive.is_none()
                    && other.named.is_none()
            })
        {
            return Ok(());
        }
        let block = u64::from(self.fs.block_size());
        let allocation = info
            .size
            .div_ceil(block)
            .checked_mul(block)
            .ok_or_else(|| error(Status::InvalidParameter, "allocation size overflow"))?;
        if allocation < info.allocation_size {
            let path = self.path(context.cnid)?;
            let precision = self.prepare_precision(&[], &[], None)?;
            let related = precision.references();
            let result = self.fs.edit_fork_with_publication(
                &mut self.device,
                Path::new(&path),
                context.resource,
                fstool::fs::hfs_plus::ForkEdit::Allocate {
                    bytes: allocation,
                    truncate: false,
                },
                fstool::fs::hfs_plus::PublicationMetadata {
                    related: &related,
                    ..Default::default()
                },
            );
            self.publication_result(result)?;
        }
        Ok(())
    }
    fn cleanup_inner(
        &mut self,
        handle: Handle,
        delete: bool,
        kernel_authorized: bool,
    ) -> Result<()> {
        self.healthy()?;
        let mut context = self.context(handle)?;
        if context.cleaned {
            return Err(error(Status::InvalidParameter, "duplicate cleanup"));
        }
        if delete && !self.pending_delete.contains_key(&context.cnid) {
            if kernel_authorized {
                context.access.delete = true;
            }
            if let Err(error) = self.can_delete_context(handle, context) {
                // FILE_DELETE_ON_CLOSE skips SetDelete/CanDelete. Windows
                // permits opening a nonempty directory with that flag and
                // leaves it intact at cleanup. This eligibility refusal happens
                // before any mutation; persistence failures still propagate.
                if kernel_authorized && error.status == Status::DirectoryNotEmpty {
                    self.handles.get_mut(&handle).unwrap().cleaned = true;
                    return Ok(());
                }
                return Err(error);
            }
            if context.named.is_some() {
                self.delete_named(context)?;
            } else if let Some(id) = context.archive {
                self.delete_archive(id)?;
            } else if context.finder {
                self.store_finder(context.cnid, &[0; 32], Some(0))?;
            } else if context.resource {
                self.defer_resource(context.cnid)?;
            } else {
                self.defer_delete(context.cnid)?;
                if kernel_authorized {
                    // The final kernel cleanup unlinks the name even if mapped
                    // I/O keeps the old file object alive until Close.
                    let pending = self.pending_delete.get_mut(&context.cnid).unwrap();
                    pending.parent = 0;
                    pending.name.clear();
                }
            }
        }
        self.handles.get_mut(&handle).unwrap().cleaned = true;
        Ok(())
    }
    /// Final close reclaims a pending entry only after every context has closed.
    /// A native void callback must surface any error through host failure state.
    pub fn close(&mut self, handle: Handle) -> Result<()> {
        let context = self
            .handles
            .remove(&handle)
            .ok_or_else(|| error(Status::InvalidHandle, "unknown handle"))?;
        self.healthy()?;
        if self.read_only {
            if let Some(id) = context.archive
                && !self.handles.values().any(|other| other.archive == Some(id))
            {
                self.archives.remove(&id);
            }
            return Ok(());
        }
        if context.archive.is_none()
            && context.named.is_none()
            && !context.finder
            && !context.resource
            && !self.handles.values().any(|c| {
                c.cnid == context.cnid
                    && c.archive.is_none()
                    && c.named.is_none()
                    && !c.finder
                    && !c.resource
            })
        {
            self.ea_import.remove(&context.cnid);
        }
        if let Some(id) = context.named
            && !self
                .handles
                .values()
                .any(|c| c.identity_cnid == context.identity_cnid && c.named == Some(id))
        {
            self.detached_named.remove(&(context.identity_cnid, id));
            self.overwritten_named.remove(&(context.identity_cnid, id));
        }
        if let Some(id) = context.archive
            && !self.handles.values().any(|c| c.archive == Some(id))
        {
            if let Err(e) = self.publish_archive(id, true) {
                self.failure = Some(e.to_string());
                return Err(e);
            }
            self.archives.remove(&id);
        }
        if self.pending_delete.contains_key(&context.cnid)
            && !self.handles.values().any(|c| c.cnid == context.cnid)
        {
            let path = self.path(context.cnid)?;
            let time = now_filetime()?;
            let result = self.fs.remove(&mut self.device, &path);
            self.mutated(result)?;
            if self.pending_delete.len() == 1 {
                self.remove_holding(time)?;
            }
            self.publish_namespace()?;
            self.pending_delete.remove(&context.cnid);
            self.readonly_on_close.remove(&context.cnid);
            if self.pending_delete.is_empty() {
                self.holding = None;
            }
        }
        if self.readonly_on_close.contains(&context.cnid)
            && !self
                .handles
                .values()
                .any(|context_other| context_other.cnid == context.cnid)
        {
            let attributes = self.info(context.cnid)?.attributes | 1;
            let native = self
                .native_windows_attributes(context.cnid, Some(attributes))
                .map_err(engine_error)?;
            let precision = self.prepare_precision(&[], &[], None)?;
            let related = precision.references();
            let result = self.fs.set_basic_metadata_with_publication(
                &mut self.device,
                context.cnid,
                [None; 4],
                native,
                &related,
            );
            self.mutated(result)?;
            self.durable()?;
            self.readonly_on_close.remove(&context.cnid);
        }
        Ok(())
    }
    pub fn flush(&mut self, handle: Option<Handle>) -> Result<()> {
        self.healthy()?;
        if self.read_only {
            if let Some(handle) = handle {
                self.context(handle)?;
            }
            return Ok(());
        }
        if let Some(handle) = handle {
            if let Some(id) = self.context(handle)?.archive {
                self.publish_archive(id, true)?;
            }
        } else {
            let ids = self.archives.keys().copied().collect::<Vec<_>>();
            for id in ids {
                self.publish_archive(id, true)?;
            }
        }
        self.durable()
    }
    /// Graceful shutdown refuses live contexts instead of silently discarding
    /// delete-pending entries. Failure never becomes a successful flush/unmount.
    pub fn flush_for_shutdown(&mut self) -> Result<()> {
        self.healthy()?;
        if !self.handles.is_empty() || !self.pending_delete.is_empty() {
            if std::env::var_os("HFS_NATIVE_TRACE").is_some() {
                for (handle, context) in &self.handles {
                    eprintln!(
                        "Shutdown context {}: cnid={} named={:?} resource={} finder={} archive={:?} cleaned={}",
                        handle.0,
                        context.cnid,
                        context.named,
                        context.resource,
                        context.finder,
                        context.archive,
                        context.cleaned
                    );
                }
            }
            return Err(error(Status::Busy, "open contexts remain"));
        }
        self.durable()
    }
    /// Consume only after flush_for_shutdown succeeded. Native hosts must use
    /// the borrowing check first, so a busy mount retains its live contexts.
    pub fn shutdown(mut self) -> Result<D> {
        self.flush_for_shutdown()?;
        Ok(self.device)
    }
}
