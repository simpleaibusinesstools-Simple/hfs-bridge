//! Read-only filesystem operations for the bounded raw-device view.
use crate::{Result, engine, image, volume};
use fstool::{block::BlockDevice, fs::Filesystem};
use std::io::{self, Seek, SeekFrom};
use std::path::Path;

pub fn inspect(device: &mut dyn BlockDevice) -> Result<String> {
    Ok(volume::inspection_json(&volume::inspect(device)?))
}
pub fn list(device: &mut dyn BlockDevice, path: &str) -> Result<Vec<fstool::fs::DirEntry>> {
    if path != "/" {
        engine::validate_hfs_path(path)?;
    }
    let mut fs = engine::open_checked(device)?;
    Ok(fs.list(device, Path::new(path))?)
}
pub fn list_json(device: &mut dyn BlockDevice, path: &str) -> Result<String> {
    let rows = list(device, path)?
        .into_iter()
        .map(|entry| {
            format!(
                "{{\"name\":{},\"inode\":{},\"kind\":{},\"size\":{}}}",
                super::json_string(&entry.name),
                entry.inode,
                super::json_string(&format!("{:?}", entry.kind)),
                entry.size
            )
        })
        .collect::<Vec<_>>();
    Ok(format!(
        "{{\"schema\":1,\"path\":{},\"entries\":[{}],\"physicalWrites\":false}}",
        super::json_string(path),
        rows.join(",")
    ))
}
pub fn hash(device: &mut dyn BlockDevice, path: &str) -> Result<String> {
    engine::validate_hfs_path(path)?;
    let fs = engine::open_checked(device)?;
    engine::sha256(&mut fs.open_file_reader(device, path)?)
}
/// Copies a data fork to a new regular host file. No source metadata changes or
/// journal replay are permitted by the raw read-only device.
pub fn extract(device: &mut dyn BlockDevice, path: &str, output: &Path) -> Result<String> {
    engine::validate_hfs_path(path)?;
    let mut fs = engine::open_checked(device)?;
    let mut reader = fs.read_file(device, Path::new(path))?;
    let mut output_file = image::create_output(output)?;
    io::copy(&mut reader, &mut output_file)?;
    output_file.sync_all()?;
    output_file.seek(SeekFrom::Start(0))?;
    engine::sha256(&mut output_file)
}
