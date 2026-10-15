//! Experimental engine adapter. Mutations target newly created image copies.
use crate::{
    Result,
    image::{Image, create_output, open_source},
    volume,
};
use fstool::block::BlockDevice;
use fstool::fs::Filesystem;
use fstool::fs::hfs_plus::{FormatOpts, HfsPlus};
use sha2::{Digest, Sha256};
use std::io::{self, Read};
use std::path::Path;

pub fn open_checked(device: &mut dyn BlockDevice) -> Result<HfsPlus> {
    volume::require_engine_access(&volume::inspect(device)?)?;
    let fs = HfsPlus::open(device)?;
    fs.require_classic_catalog_dates()?;
    Ok(fs)
}

/// Checked attributes. Every mutation targets a new image and verifies
/// the catalog, both regular-file forks and every unrelated attribute value.
pub fn edit_attribute(
    source: &Path,
    output: &Path,
    base: u64,
    length: Option<u64>,
    path: &str,
    name: &str,
    value_file: Option<&Path>,
) -> Result<()> {
    validate_hfs_path(path)?;
    let mut value = if let Some(path) = value_file {
        let mut file = open_source(path)?;
        if file.metadata()?.len() > 16 * 1024 * 1024 {
            return Err("attribute value exceeds 16 MiB limit".into());
        }
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        Some(bytes)
    } else {
        None
    };
    let mut original = Image::read_only(source, base, length)?;
    let mut fs = open_checked(&mut original)?;
    let before = fs.catalog_record(path)?;
    if name == "com.apple.FinderInfo"
        && let Some(bytes) = value.as_mut()
    {
        let finder: &[u8; 32] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| "FinderInfo must have 32 bytes")?;
        *bytes = fstool::fs::hfs_plus::attributes::public_finder_info(finder).to_vec();
    }
    let cnid = volume::be32(&before, 8);
    let forks = if volume::be16(&before, 0) == 2 {
        let data = sha256(&mut *FileFork::Data.reader(
            &fs,
            &mut original,
            path,
            volume::be64(&before, 88),
        )?)?;
        let resource = sha256(&mut *FileFork::Resource.reader(
            &fs,
            &mut original,
            path,
            volume::be64(&before, 168),
        )?)?;
        Some((data, resource))
    } else {
        None
    };
    let mut expected = inline_attributes(&fs, &mut original, cnid)?;
    expected.retain(|(key, _)| key != name);
    if let Some(value) = &value
        && (name != "com.apple.FinderInfo" || value.iter().any(|b| *b != 0))
    {
        expected.push((name.to_owned(), value.clone()));
    }
    expected.sort();
    // Prevalidate the whole plan on the read-only source before creating output.
    fs.set_inline_attribute(&mut original, cnid, name, value.as_deref())?;
    drop(fs);
    let mut device = Image::copy_new(source, output, base, length)?;
    let mut fs = open_checked(&mut device)?;
    fs.set_inline_attribute(&mut device, cnid, name, value.as_deref())?;
    fs.flush(&mut device)?;
    device.sync()?;
    drop(fs);
    drop(device);
    let mut reopened = Image::read_only(output, base, length)?;
    let fs = open_checked(&mut reopened)?;
    let mut expected_body = before;
    let flags = volume::be16(&expected_body, 2);
    expected_body[2..4].copy_from_slice(
        &((flags & !4)
            | if expected
                .iter()
                .any(|(name, _)| name != "com.apple.FinderInfo")
            {
                4
            } else {
                0
            })
        .to_be_bytes(),
    );
    if name == "com.apple.FinderInfo" {
        let finder = value.as_deref().unwrap_or(&[0; 32]);
        expected_body[48..64].copy_from_slice(&finder[..16]);
        expected_body[72..76].copy_from_slice(&finder[24..28]);
    }
    if fs.catalog_record(path)? != expected_body
        || inline_attributes(&fs, &mut reopened, cnid)? != expected
    {
        return Err("attribute edit changed catalog metadata or unrelated attribute values".into());
    }
    if let Some((data, resource)) = forks
        && (sha256(&mut *FileFork::Data.reader(
            &fs,
            &mut reopened,
            path,
            volume::be64(&expected_body, 88),
        )?)? != data
            || sha256(&mut *FileFork::Resource.reader(
                &fs,
                &mut reopened,
                path,
                volume::be64(&expected_body, 168),
            )?)? != resource)
    {
        return Err("attribute edit changed a data or resource fork".into());
    }
    Ok(())
}
fn inline_attributes(
    fs: &HfsPlus,
    device: &mut dyn BlockDevice,
    cnid: u32,
) -> Result<Vec<(String, Vec<u8>)>> {
    let mut values = Vec::new();
    for name in fs.attribute_names(device, cnid)? {
        let value = fs
            .inline_attribute(device, cnid, &name)?
            .ok_or("listed attribute has no value")?;
        values.push((name, value));
    }
    values.sort();
    Ok(values)
}
pub fn extract_attribute(
    image: &Path,
    base: u64,
    length: Option<u64>,
    path: &str,
    name: &str,
    output: &Path,
) -> Result<()> {
    validate_hfs_path(path)?;
    let mut device = Image::read_only(image, base, length)?;
    let fs = open_checked(&mut device)?;
    let cnid = volume::be32(&fs.catalog_record(path)?, 8);
    let value = fs
        .inline_attribute(&mut device, cnid, name)?
        .ok_or("attribute does not exist")?;
    let mut file = create_output(output)?;
    use std::io::Write;
    file.write_all(&value)?;
    file.sync_all()?;
    Ok(())
}
pub fn sha256(reader: &mut dyn Read) -> Result<String> {
    let mut digest = Sha256::new();
    let mut buffer = [0u8; 65536];
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    Ok(format!("{:x}", digest.finalize()))
}
/// Read-only, complete hashes for a regular file and specifically named Mac
/// attributes. Catalog hash includes ownership, flags, all dates and both forks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileSnapshot {
    pub cnid: u32,
    pub uid: u32,
    pub gid: u32,
    pub mode: u16,
    pub catalog_sha256: String,
    pub data_sha256: String,
    pub resource_sha256: Option<String>,
    pub attributes: Vec<(String, Option<String>)>,
}
pub fn snapshot_device(
    device: &mut dyn BlockDevice,
    path: &str,
    attribute_names: &[&str],
) -> Result<FileSnapshot> {
    validate_hfs_path(path)?;
    if attribute_names.len() > 64
        || attribute_names
            .iter()
            .any(|name| name.is_empty() || name.contains('\0') || name.encode_utf16().count() > 127)
    {
        return Err("snapshot requires at most 64 valid native attribute names".into());
    }
    let fs = open_checked(device)?;
    let body = fs.catalog_record(path)?;
    if body.len() != 248 || volume::be16(&body, 0) != 2 {
        return Err("snapshot requires a regular catalog file".into());
    }
    let cnid = volume::be32(&body, 8);
    let data_sha256 = sha256(&mut fs.open_file_reader(device, path)?)?;
    let resource_sha256 = if fs.resource_fork_size(device, path)?.is_some() {
        Some(sha256(&mut fs.open_resource_fork_reader(device, path)?)?)
    } else {
        None
    };
    let mut attributes = Vec::new();
    for &name in attribute_names {
        let digest = match fs.inline_attribute(device, cnid, name)? {
            Some(data) => Some(sha256(&mut &data[..])?),
            None => None,
        };
        attributes.push((name.into(), digest));
    }
    Ok(FileSnapshot {
        cnid,
        uid: volume::be32(&body, 32),
        gid: volume::be32(&body, 36),
        mode: volume::be16(&body, 42),
        catalog_sha256: sha256(&mut &body[..])?,
        data_sha256,
        resource_sha256,
        attributes,
    })
}
pub fn snapshot(
    image: &Path,
    path: &str,
    attributes: &[&str],
    offset: u64,
    length: Option<u64>,
) -> Result<FileSnapshot> {
    snapshot_device(
        &mut Image::read_only(image, offset, length)?,
        path,
        attributes,
    )
}
pub fn validate_hfs_path(path: &str) -> Result<()> {
    if !path.starts_with('/')
        || path == "/"
        || path.contains('\0')
        || path[1..].split('/').any(|part| {
            part.is_empty()
                || part == "."
                || part == ".."
                || fstool::fs::hfs_plus::catalog::UniStr::from_path_component_checked(part).is_err()
        })
    {
        return Err("filesystem path must be absolute, with ordinary non-empty components of at most 255 UTF-16 units".into());
    }
    Ok(())
}
pub fn fixture(output: &Path, journaled: bool) -> Result<()> {
    let mut device = Image::create(output, 32 * 1024 * 1024)?;
    let options = FormatOpts {
        volume_name: "HFS Bridge Fixture".into(),
        journaled,
        ..Default::default()
    };
    let mut fs = HfsPlus::format(&mut device, &options)?;
    fs.create_dir(&mut device, "/Transfer", 0o755, 0, 0, 1_700_000_000)?;
    let payload = b"HFS Bridge: persistent Windows-to-Mac filesystem development fixture.\n";
    fs.create_file(
        &mut device,
        "/Transfer/hello.txt",
        &mut &payload[..],
        payload.len() as u64,
        0o644,
        0,
        0,
        1_700_000_000,
    )?;
    fs.flush(&mut device)?;
    device.sync()?;
    drop(fs);
    drop(device);
    let mut reader = Image::read_only(output, 0, None)?;
    let mut fs = open_checked(&mut reader)?;
    let mut file = Filesystem::read_file(&mut fs, &mut reader, Path::new("/Transfer/hello.txt"))?;
    let mut expected = &payload[..];
    if sha256(&mut *file)? != sha256(&mut expected)? {
        return Err("fixture failed reopened payload verification".into());
    }
    Ok(())
}
#[derive(Clone, Copy)]
pub enum Mutation<'a> {
    Put {
        source: &'a Path,
        destination: &'a str,
    },
    Mkdir(&'a str),
    Delete(&'a str),
    Rename {
        source: &'a str,
        destination: &'a str,
    },
}

#[derive(Clone, Copy)]
pub enum FileEdit<'a> {
    Overwrite(&'a Path),
    Patch { source: &'a Path, offset: u64 },
    Truncate(u64),
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum FileFork {
    Data,
    Resource,
}
impl FileFork {
    fn offset(self) -> usize {
        match self {
            Self::Data => 88,
            Self::Resource => 168,
        }
    }
    fn reader<'a>(
        self,
        fs: &HfsPlus,
        dev: &'a mut dyn BlockDevice,
        path: &str,
        size: u64,
    ) -> Result<Box<dyn Read + 'a>> {
        Ok(match self {
            Self::Data => Box::new(fs.open_file_reader(dev, path)?),
            Self::Resource if size == 0 => Box::new(io::empty()),
            Self::Resource => Box::new(fs.open_resource_fork_reader(dev, path)?),
        })
    }
}
fn hash_bytes(reader: &mut dyn Read, mut len: u64, digest: &mut Sha256) -> Result<()> {
    let mut buffer = [0; 65536];
    while len > 0 {
        let want = len.min(buffer.len() as u64) as usize;
        let count = reader.read(&mut buffer[..want])?;
        if count == 0 {
            return Err("file ended before its declared size".into());
        }
        digest.update(&buffer[..count]);
        len -= count as u64;
    }
    Ok(())
}
fn hash_zeros(mut len: u64, digest: &mut Sha256) {
    let zeros = [0; 65536];
    while len > 0 {
        let count = len.min(zeros.len() as u64) as usize;
        digest.update(&zeros[..count]);
        len -= count as u64;
    }
}

enum EditSegment {
    Original(u64),
    Skip(u64),
    Zeros(u64),
    Input(u64),
}

/// Streams an edit from a separate read-only image. Neither a sparse gap nor
/// the decoded original content is materialized as a whole-file buffer.
struct EditedReader<'a> {
    original: Box<dyn Read + 'a>,
    input: Option<&'a mut std::fs::File>,
    segments: std::collections::VecDeque<EditSegment>,
}
impl<'a> EditedReader<'a> {
    fn new(
        original: Box<dyn Read + 'a>,
        input: Option<&'a mut std::fs::File>,
        edit: FileEdit<'_>,
        old_len: u64,
        input_len: u64,
    ) -> Self {
        use EditSegment::*;
        let segments = match edit {
            FileEdit::Overwrite(_) => vec![Input(input_len)],
            FileEdit::Truncate(size) => {
                vec![
                    Original(old_len.min(size)),
                    Zeros(size.saturating_sub(old_len)),
                ]
            }
            FileEdit::Patch { offset, .. } if input_len != 0 => {
                let end = offset + input_len; // Checked by the caller.
                vec![
                    Original(offset.min(old_len)),
                    Zeros(offset.saturating_sub(old_len)),
                    Input(input_len),
                    Skip(end.min(old_len) - offset.min(old_len)),
                    Original(old_len.saturating_sub(end)),
                ]
            }
            FileEdit::Patch { .. } => vec![Original(old_len)],
        };
        Self {
            original,
            input,
            segments: segments.into(),
        }
    }
}
impl Read for EditedReader<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        loop {
            let Some(segment) = self.segments.front_mut() else {
                if let Some(input) = self.input.as_mut()
                    && input.read(&mut [0; 1])? != 0
                {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "edit input grew after preflight",
                    ));
                }
                return Ok(0);
            };
            if let EditSegment::Skip(length) = segment {
                let wanted = *length;
                if io::copy(&mut self.original.by_ref().take(wanted), &mut io::sink())? != wanted {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "original ended in replaced range",
                    ));
                }
                self.segments.pop_front();
                continue;
            }
            let length = match segment {
                EditSegment::Original(n) | EditSegment::Zeros(n) | EditSegment::Input(n) => *n,
                EditSegment::Skip(_) => unreachable!(),
            };
            if length == 0 {
                self.segments.pop_front();
                continue;
            }
            let want = length.min(buffer.len() as u64) as usize;
            let count = match segment {
                EditSegment::Original(_) => self.original.read(&mut buffer[..want])?,
                EditSegment::Input(_) => self.input.as_mut().unwrap().read(&mut buffer[..want])?,
                EditSegment::Zeros(_) => {
                    buffer[..want].fill(0);
                    want
                }
                EditSegment::Skip(_) => unreachable!(),
            };
            if count == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "edit source ended before its declared size",
                ));
            }
            match segment {
                EditSegment::Original(n) | EditSegment::Zeros(n) | EditSegment::Input(n) => {
                    *n -= count as u64
                }
                EditSegment::Skip(_) => unreachable!(),
            }
            return Ok(count);
        }
    }
}

fn user_attribute_hashes(
    fs: &HfsPlus,
    device: &mut dyn BlockDevice,
    cnid: u32,
) -> Result<Vec<(String, usize, String)>> {
    let mut hashes = Vec::new();
    for name in fs.attribute_names(device, cnid)? {
        if name == "com.apple.decmpfs" {
            continue;
        }
        let value = fs
            .inline_attribute(device, cnid, &name)?
            .ok_or("listed user attribute has no value")?;
        hashes.push((name, value.len(), sha256(&mut value.as_slice())?));
    }
    hashes.sort();
    Ok(hashes)
}

/// Edit an existing file only in a newly created image copy. Expected bytes
/// are hashed from original streams before the mutation, with bounded memory.
pub fn edit_file(
    source_image: &Path,
    output: &Path,
    base: u64,
    length: Option<u64>,
    path: &str,
    edit: FileEdit<'_>,
) -> Result<()> {
    edit_fork(
        source_image,
        output,
        base,
        length,
        path,
        edit,
        FileFork::Data,
    )
}

/// Edit a selected fork in a new copy, then verify both its complete payload
/// and the untouched sibling payload and catalog metadata after reopening.
pub fn edit_fork(
    source_image: &Path,
    output: &Path,
    base: u64,
    length: Option<u64>,
    path: &str,
    edit: FileEdit<'_>,
    fork: FileFork,
) -> Result<()> {
    use std::io::{Seek, SeekFrom};
    validate_hfs_path(path)?;
    let mut original = Image::read_only(source_image, base, length)?;
    let fs = open_checked(&mut original)?;
    let record = fs.catalog_record(path)?;
    if record.len() < 248 || volume::be16(&record, 0) != 2 {
        return Err("edit target must be an existing regular file".into());
    }
    let cnid = volume::be32(&record, 8);
    let compression = fs.compressed_info(&mut original, cnid)?;
    if compression.is_some() && fork == FileFork::Resource {
        return Err("compressed resource editing requires ordinary-data conversion first".into());
    }
    let fork_offset = fork.offset();
    let old_len = compression.map_or_else(|| volume::be64(&record, fork_offset), |(size, _)| size);
    let sibling = if fork == FileFork::Data {
        FileFork::Resource
    } else {
        FileFork::Data
    };
    let sibling_len = if compression.is_some_and(|(_, internal)| internal) {
        0
    } else {
        volume::be64(&record, sibling.offset())
    };
    let sibling_hash = sha256(&mut *sibling.reader(&fs, &mut original, path, sibling_len)?)?;
    let user_attributes = if compression.is_some() {
        Some(user_attribute_hashes(&fs, &mut original, cnid)?)
    } else {
        None
    };
    let mut host = match edit {
        FileEdit::Overwrite(source) | FileEdit::Patch { source, .. } => Some(open_source(source)?),
        _ => None,
    };
    let host_len = host
        .as_ref()
        .map(|file| file.metadata().map(|m| m.len()))
        .transpose()?
        .unwrap_or(0);
    let new_len = match edit {
        FileEdit::Overwrite(_) => host_len,
        FileEdit::Truncate(size) => size,
        FileEdit::Patch { offset, .. } if host_len != 0 => old_len.max(
            offset
                .checked_add(host_len)
                .ok_or("patch offset overflow")?,
        ),
        FileEdit::Patch { .. } => old_len,
    };
    if new_len > fs.total_bytes() {
        return Err("edited file exceeds volume capacity".into());
    }
    let convert = compression.is_some()
        && !(matches!(edit, FileEdit::Patch { .. }) && host_len == 0
            || matches!(edit, FileEdit::Truncate(size) if size == old_len));
    if convert {
        fs.validate_compressed_replacement(&mut original, cnid, new_len)?;
    }
    let mut digest = Sha256::new();
    let mut old = fork.reader(&fs, &mut original, path, old_len)?;
    match edit {
        FileEdit::Overwrite(_) => hash_bytes(host.as_mut().unwrap(), host_len, &mut digest)?,
        FileEdit::Truncate(size) => {
            hash_bytes(&mut old, old_len.min(size), &mut digest)?;
            hash_zeros(size.saturating_sub(old_len), &mut digest);
        }
        FileEdit::Patch { offset, .. } if host_len != 0 => {
            let end = offset + host_len; // overflow checked above
            hash_bytes(&mut old, offset.min(old_len), &mut digest)?;
            hash_zeros(offset.saturating_sub(old_len), &mut digest);
            hash_bytes(host.as_mut().unwrap(), host_len, &mut digest)?;
            let skip = end.min(old_len) - offset.min(old_len);
            if io::copy(&mut old.by_ref().take(skip), &mut io::sink())? != skip {
                return Err("original file ended within patched range".into());
            }
            hash_bytes(&mut old, old_len.saturating_sub(end), &mut digest)?;
        }
        FileEdit::Patch { .. } => hash_bytes(&mut old, old_len, &mut digest)?,
    }
    let expected = format!("{:x}", digest.finalize());
    drop(old);
    if let Some(host) = host.as_mut() {
        host.seek(SeekFrom::Start(0))?;
    }
    let original_fs = fs;
    let mut device = Image::copy_new(source_image, output, base, length)?;
    let mut fs = open_checked(&mut device)?;
    if convert {
        let mut input = EditedReader::new(
            fork.reader(&original_fs, &mut original, path, old_len)?,
            host.as_mut(),
            edit,
            old_len,
            host_len,
        );
        fs.replace_compressed_data(&mut device, Path::new(path), &mut input, new_len)?;
    } else if compression.is_none() {
        let mut handle = match fork {
            FileFork::Data => {
                fs.open_file_rw(&mut device, Path::new(path), Default::default(), None)?
            }
            FileFork::Resource => fs.open_resource_fork_rw(&mut device, Path::new(path))?,
        };
        match edit {
            FileEdit::Overwrite(_) => {
                handle.set_len(0)?;
                io::copy(host.as_mut().unwrap(), &mut handle)?;
            }
            FileEdit::Patch { offset, .. } => {
                handle.seek(SeekFrom::Start(offset))?;
                io::copy(host.as_mut().unwrap(), &mut handle)?;
            }
            FileEdit::Truncate(size) => handle.set_len(size)?,
        }
        handle.sync()?;
    }
    device.sync()?;
    drop(fs);
    drop(device);
    let mut reopened = Image::read_only(output, base, length)?;
    let fs = open_checked(&mut reopened)?;
    let after = fs.catalog_record(path)?;
    let mut expected_body = record.clone();
    if convert {
        expected_body[41] &= !0x20;
        let flags = volume::be16(&expected_body, 2);
        let tree_attributes_remain = user_attributes
            .as_ref()
            .unwrap()
            .iter()
            .any(|(name, _, _)| name != "com.apple.FinderInfo");
        expected_body[2..4].copy_from_slice(
            &((flags & !4) | if tree_attributes_remain { 4 } else { 0 }).to_be_bytes(),
        );
        if compression.is_some_and(|(_, internal)| internal) {
            expected_body[168..248].fill(0);
        }
        if fs
            .inline_attribute(&mut reopened, cnid, "com.apple.decmpfs")?
            .is_some()
            || user_attribute_hashes(&fs, &mut reopened, cnid)?
                != *user_attributes.as_ref().unwrap()
        {
            return Err(
                "conversion changed user attributes or retained compression metadata".into(),
            );
        }
    }
    if after[..fork_offset] != expected_body[..fork_offset]
        || after[fork_offset + 80..] != expected_body[fork_offset + 80..]
        || after[fork_offset + 8..fork_offset + 12]
            != expected_body[fork_offset + 8..fork_offset + 12]
    {
        return Err(
            "fork edit changed identity, Mac metadata, clump size or sibling-fork descriptor"
                .into(),
        );
    }
    let after_len = fs
        .compressed_info(&mut reopened, cnid)?
        .map_or_else(|| volume::be64(&after, fork_offset), |(size, _)| size);
    if after_len != new_len
        || sha256(&mut *fork.reader(&fs, &mut reopened, path, new_len)?)? != expected
        || sha256(&mut *sibling.reader(&fs, &mut reopened, path, sibling_len)?)? != sibling_hash
    {
        return Err("reopened edited file does not match expected size and SHA256".into());
    }
    Ok(())
}
pub fn extract_resource(
    image: &Path,
    path: &str,
    output: &Path,
    base: u64,
    length: Option<u64>,
) -> Result<String> {
    validate_hfs_path(path)?;
    let mut device = Image::read_only(image, base, length)?;
    let fs = open_checked(&mut device)?;
    // An absent fork has no named resource stream to extract.
    let mut reader = fs.open_resource_fork_reader(&mut device, path)?;
    let mut host = create_output(output)?;
    io::copy(&mut reader, &mut host)?;
    host.sync_all()?;
    drop(host);
    sha256(&mut open_source(output)?)
}
pub fn mutate(
    source_image: &Path,
    output: &Path,
    base: u64,
    length: Option<u64>,
    operation: Mutation<'_>,
) -> Result<()> {
    let path = match operation {
        Mutation::Put { destination, .. }
        | Mutation::Rename { destination, .. }
        | Mutation::Mkdir(destination)
        | Mutation::Delete(destination) => destination,
    };
    validate_hfs_path(path)?;
    if let Mutation::Rename { source, .. } = operation {
        validate_hfs_path(source)?;
    }
    let mut original = Image::read_only(source_image, base, length)?;
    volume::require_engine_access(&volume::inspect(&mut original)?)?;
    let mut host_source = match operation {
        Mutation::Put { source, .. } => Some(open_source(source)?),
        _ => None,
    };
    // Failed outputs are incomplete; existing files are never overwritten.
    let mut device = Image::copy_new(source_image, output, base, length)?;
    let mut fs = open_checked(&mut device)?;
    let mut original_record = None;
    let expected = match operation {
        Mutation::Put { destination, .. } => {
            let source = host_source.as_mut().unwrap();
            let len = source.metadata()?.len();
            let digest = sha256(source)?;
            use std::io::{Seek, SeekFrom};
            source.seek(SeekFrom::Start(0))?;
            fs.create_file(
                &mut device,
                destination,
                source,
                len,
                0o644,
                0,
                0,
                1_700_000_000,
            )?;
            Some(digest)
        }
        Mutation::Mkdir(destination) => {
            fs.create_dir(&mut device, destination, 0o755, 0, 0, 1_700_000_000)?;
            None
        }
        Mutation::Delete(destination) => {
            fs.remove(&mut device, destination)?;
            None
        }
        Mutation::Rename {
            source,
            destination,
        } => {
            original_record = Some(fs.catalog_record(source)?);
            fs.rename(&mut device, source, destination)?;
            None
        }
    };
    fs.flush(&mut device)?;
    device.sync()?;
    drop(fs);
    drop(device);
    let mut reopened = Image::read_only(output, base, length)?;
    let mut fs = open_checked(&mut reopened)?;
    if let Some(expected) = expected {
        let mut reader = Filesystem::read_file(&mut fs, &mut reopened, Path::new(path))?;
        if sha256(&mut *reader)? != expected {
            return Err("reopened destination payload hash does not match source".into());
        }
    } else if let Mutation::Rename {
        source,
        destination,
    } = operation
    {
        if fs.catalog_record(destination)? != original_record.unwrap() {
            return Err("renamed catalog identity, metadata or fork descriptors changed".into());
        }
        let (parent, name) = destination.rsplit_once('/').unwrap();
        let parent = if parent.is_empty() { "/" } else { parent };
        let canonical_name =
            fstool::fs::hfs_plus::catalog::UniStr::from_path_component_checked(name)?
                .to_display_name();
        if !fs
            .list(&mut reopened, Path::new(parent))?
            .iter()
            .any(|entry| entry.name == canonical_name)
        {
            return Err("destination spelling did not persist after rename".into());
        }
        // A case-only alias can still resolve to the same identity on HFS+.
        if source != destination
            && let Ok(record) = fs.catalog_record(source)
            && record != fs.catalog_record(destination)?
        {
            return Err("source path resolves to a different entry after rename".into());
        }
    } else if matches!(operation, Mutation::Mkdir(_)) {
        fs.list(&mut reopened, Path::new(path))?;
    } else {
        let (parent, name) = path.rsplit_once('/').unwrap();
        let parent = if parent.is_empty() { "/" } else { parent };
        let canonical_name =
            fstool::fs::hfs_plus::catalog::UniStr::from_path_component_checked(name)?
                .to_display_name();
        if fs
            .list(&mut reopened, Path::new(parent))?
            .iter()
            .any(|entry| entry.name == canonical_name)
        {
            return Err("deleted entry is still present after reopen".into());
        }
    }
    Ok(())
}
pub fn extract(
    image: &Path,
    path: &str,
    output: &Path,
    base: u64,
    length: Option<u64>,
) -> Result<String> {
    validate_hfs_path(path)?;
    let mut device = Image::read_only(image, base, length)?;
    let mut fs = open_checked(&mut device)?;
    let mut reader = Filesystem::read_file(&mut fs, &mut device, Path::new(path))?;
    let mut output_file = create_output(output)?;
    io::copy(&mut reader, &mut output_file)?;
    output_file.sync_all()?;
    use std::io::{Seek, SeekFrom};
    output_file.seek(SeekFrom::Start(0))?;
    sha256(&mut output_file)
}
pub fn list(
    image: &Path,
    path: &str,
    base: u64,
    length: Option<u64>,
) -> Result<Vec<fstool::fs::DirEntry>> {
    if path != "/" {
        validate_hfs_path(path)?;
    }
    let mut device = Image::read_only(image, base, length)?;
    let mut fs = open_checked(&mut device)?;
    Ok(fs.list(&mut device, Path::new(path))?)
}

/// Read-only Windows-safe directory view. No catalog names are rewritten.
pub fn windows_names(
    image: &Path,
    directory: &str,
    base: u64,
    length: Option<u64>,
) -> Result<crate::names::DirectoryNames> {
    if directory != "/" {
        validate_hfs_path(directory)?;
    }
    let mut device = Image::read_only(image, base, length)?;
    let fs = open_checked(&mut device)?;
    let entries = fs.list_path(&mut device, directory)?;
    for entry in &entries {
        let path = format!("{}/{}", directory.trim_end_matches('/'), entry.name);
        let record = fs.catalog_record(&path)?;
        if volume::be32(&record, 8) != entry.inode {
            return Err("catalog name cannot round-trip to its original identity".into());
        }
    }
    crate::names::DirectoryNames::build(entries.into_iter().map(|entry| (entry.inode, entry.name)))
}

pub fn extract_windows(
    image: &Path,
    directory: &str,
    name: &str,
    output: &Path,
    base: u64,
    length: Option<u64>,
) -> Result<String> {
    // Hold a read-only input handle while resolving and extracting so another
    // Windows process cannot mutate the input between these reads.
    let _input = Image::read_only(image, base, length)?;
    let view = windows_names(image, directory, base, length)?;
    let entry = view.resolve(name)?;
    let path = format!(
        "{}/{}",
        directory.trim_end_matches('/'),
        entry.hfs_component
    );
    extract(image, &path, output, base, length)
}
