//! Exclusive whole-file transfers. Payload is streamed into private free blocks;
//! one existing journal publication makes the complete file visible. No overwrite.
use crate::{Result, engine, image, volume};
use fstool::block::BlockDevice;
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{self, Read},
    path::Path,
};

#[derive(Debug, PartialEq, Eq)]
pub struct Receipt {
    pub bytes: u64,
    pub sha256: String,
}

pub fn validate_destination(destination: &str) -> Result<(&str, &str)> {
    engine::validate_hfs_path(destination)?;
    let (folder, name) = destination
        .rsplit_once('/')
        .ok_or("missing transfer folder")?;
    if folder.is_empty()
        || folder[1..].contains('/')
        || !crate::names::windows_component(&folder[1..])
        || !crate::names::windows_component(name)
    {
        return Err("choose a new root folder and an ordinary filename for this transfer".into());
    }
    Ok((folder, name))
}

struct Meter<'a, R, F> {
    input: &'a mut R,
    digest: Sha256,
    bytes: u64,
    total: u64,
    report: &'a mut F,
    phase: &'static str,
    reported: u64,
}
impl<R: Read, F: FnMut(&str, u64, u64)> Read for Meter<'_, R, F> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let count = self.input.read(buffer)?;
        self.digest.update(&buffer[..count]);
        self.bytes += count as u64;
        if self.bytes.saturating_sub(self.reported) >= 1024 * 1024 || self.bytes == self.total {
            (self.report)(self.phase, self.bytes, self.total);
            self.reported = self.bytes;
        }
        Ok(count)
    }
}

/// Errors abandon the writer rather than flushing an incomplete plan. Callers
/// must retain exclusive ownership and never retry a failed writer in place.
pub fn copy_file<R: Read, F: FnMut(&str, u64, u64)>(
    device: &mut dyn BlockDevice,
    input: &mut R,
    length: u64,
    destination: &str,
    modified: u32,
    mut report: F,
) -> Result<Receipt> {
    let (folder, _) = validate_destination(destination)?;
    let mut fs = engine::open_checked(device)?;
    // Checks the case-folded HFS name without editing an existing folder.
    fs.creation_cnid(folder)?;
    let inspection = volume::inspect(device)?;
    let header = &inspection.header;
    if length.div_ceil(u64::from(header.block_size)) > u64::from(header.free_blocks) {
        return Err("not enough space for this file".into());
    }
    fs.create_dir(device, folder, 0o755, 0, 0, modified)?;
    fs.flush(device)?;
    device.sync()?;
    let mut meter = Meter {
        input,
        digest: Sha256::new(),
        bytes: 0,
        total: length,
        report: &mut report,
        phase: "copy",
        reported: 0,
    };
    fs.create_file(
        device,
        destination,
        &mut meter,
        length,
        0o644,
        0,
        0,
        modified,
    )?;
    if meter.bytes != length || meter.read(&mut [0; 1])? != 0 {
        return Err("source length changed; file was not published".into());
    }
    let expected = format!("{:X}", meter.digest.finalize());
    report("committing", length, length);
    fs.flush(device)?;
    device.sync()?;
    drop(fs);
    // Reopen the catalog and read every saved byte; copying progress alone is
    // never treated as a verified transfer.
    let fs = engine::open_checked(device)?;
    let record = fs.catalog_record(destination)?;
    if volume::be64(&record, 88) != length {
        return Err("saved file length differs".into());
    }
    let mut reader = fs.open_file_reader(device, destination)?;
    let mut verified = Meter {
        input: &mut reader,
        digest: Sha256::new(),
        bytes: 0,
        total: length,
        report: &mut report,
        phase: "verify",
        reported: 0,
    };
    io::copy(&mut verified, &mut io::sink())?;
    if verified.bytes != length || format!("{:X}", verified.digest.finalize()) != expected {
        return Err("saved copy failed SHA256 verification".into());
    }
    drop(reader);
    drop(fs);
    device.sync()?;
    volume::require_engine_access(&volume::inspect(device)?)?;
    Ok(Receipt {
        bytes: length,
        sha256: expected,
    })
}

pub fn source(path: &Path) -> Result<(File, u64, u32)> {
    let file = image::open_source(path)?;
    let metadata = file.metadata()?;
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & 0x400 != 0 {
            return Err("choose a regular file, not a reparse point".into());
        }
    }
    let seconds = metadata
        .modified()?
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    let modified = u32::try_from(seconds).map_err(|_| "source date is unsupported")?;
    Ok((file, metadata.len(), modified))
}

pub fn copy_image(
    source_image: &Path,
    output: &Path,
    host: &Path,
    destination: &str,
    base: u64,
    length: Option<u64>,
    report: impl FnMut(&str, u64, u64),
) -> Result<Receipt> {
    validate_destination(destination)?;
    let (mut input, size, modified) = source(host)?;
    let mut device = image::Image::copy_new(source_image, output, base, length)?;
    copy_file(&mut device, &mut input, size, destination, modified, report)
}
