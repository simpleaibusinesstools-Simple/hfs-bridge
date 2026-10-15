//! Resolve the held source handle, then reject any volume extent on the target.
//! This check runs before READY and the source handle remains open throughout.
use super::*;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetFinalPathNameByHandleW(
        handle: *mut std::ffi::c_void,
        path: *mut u16,
        count: u32,
        flags: u32,
    ) -> u32;
    fn GetVolumePathNameW(path: *const u16, volume: *mut u16, count: u32) -> i32;
    fn GetVolumeNameForVolumeMountPointW(mount: *const u16, volume: *mut u16, count: u32) -> i32;
}
pub fn require_other_disk(source: &File, target: u32) -> io::Result<()> {
    let mut path = vec![0u16; 32768];
    let count = unsafe {
        GetFinalPathNameByHandleW(
            source.as_raw_handle(),
            path.as_mut_ptr(),
            path.len() as u32,
            0,
        )
    };
    if count == 0 {
        return Err(io::Error::last_os_error());
    }
    if count as usize >= path.len() {
        return Err(invalid("source path is too long"));
    }
    let name = String::from_utf16(&path[..count as usize]).map_err(io::Error::other)?;
    if !name.starts_with(r"\\?\")
        || !name.as_bytes().get(4).is_some_and(u8::is_ascii_alphabetic)
        || name.as_bytes().get(5..7) != Some(b":\\")
    {
        return Err(invalid("choose a file on a local Windows volume"));
    }
    let mut mount = vec![0u16; 32768];
    if unsafe { GetVolumePathNameW(path.as_ptr(), mount.as_mut_ptr(), mount.len() as u32) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let mut guid = [0u16; 64];
    if unsafe {
        GetVolumeNameForVolumeMountPointW(mount.as_ptr(), guid.as_mut_ptr(), guid.len() as u32)
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let end = guid
        .iter()
        .position(|c| *c == 0)
        .ok_or_else(|| invalid("invalid source volume"))?;
    let name = std::ffi::OsString::from_wide(&guid[..end]);
    let mut wide: Vec<u16> = name.encode_wide().collect();
    if wide.last() == Some(&92) {
        wide.pop();
    }
    let volume = std::ffi::OsString::from_wide(&wide);
    let file = OpenOptions::new().read(true).share_mode(7).open(volume)?;
    let extents = query(&file, 0x0056_0000, &[], 65536)?;
    validate_extents(&extents, target)
}
fn validate_extents(extents: &[u8], target: u32) -> io::Result<()> {
    let count = u32_at(extents, 0)? as usize;
    if count == 0 || count > 2048 || extents.len() != 8 + count * 24 {
        return Err(invalid("cannot establish source disk identity"));
    }
    for index in 0..count {
        if u32_at(extents, 8 + index * 24)? == target {
            return Err(invalid(
                "source is on the destination disk; choose a Windows file on another disk",
            ));
        }
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn source_extent_identity_refuses_same_disk_anywhere_and_truncated_reports() {
        let mut bytes = vec![0; 56];
        bytes[..4].copy_from_slice(&2u32.to_le_bytes());
        bytes[8..12].copy_from_slice(&0u32.to_le_bytes());
        bytes[32..36].copy_from_slice(&3u32.to_le_bytes());
        assert!(validate_extents(&bytes, 0).is_err());
        assert!(validate_extents(&bytes, 3).is_err());
        assert!(validate_extents(&bytes, 4).is_ok());
        for cut in 0..bytes.len() {
            assert!(validate_extents(&bytes[..cut], 4).is_err());
        }
        bytes[..4].copy_from_slice(&0u32.to_le_bytes());
        assert!(validate_extents(&bytes, 4).is_err());
    }
}
