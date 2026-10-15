//! Test-only capability for a newly created 64 MiB VHDX. Never opens an
//! existing image and never accepts a physical disk number or path.
use super as windows_disk;
use std::os::windows::fs::OpenOptionsExt;
use std::{ffi::c_void, fs::OpenOptions, io, path::Path};
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Guid {
    a: u32,
    b: u16,
    c: u16,
    d: [u8; 8],
}
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Storage {
    device: u32,
    vendor: Guid,
}
#[repr(C)]
#[derive(Default)]
struct Version2 {
    id: Guid,
    maximum: u64,
    block: u32,
    logical: u32,
    physical: u32,
    parent: *const u16,
    source: *const u16,
    flags: u32,
    parent_storage: Storage,
    source_storage: Storage,
    resilience: Guid,
}
#[repr(C)]
struct Create {
    version: u32,
    v2: Version2,
}
#[repr(C)]
struct Attach {
    version: u32,
    reserved: u32,
}
#[link(name = "virtdisk")]
unsafe extern "system" {
    fn CreateVirtualDisk(
        storage: *const Storage,
        path: *const u16,
        access: u32,
        security: *const c_void,
        flags: u32,
        provider: u32,
        params: *const Create,
        overlapped: *mut c_void,
        handle: *mut *mut c_void,
    ) -> u32;
    fn AttachVirtualDisk(
        handle: *mut c_void,
        security: *const c_void,
        flags: u32,
        provider: u32,
        params: *const Attach,
        overlapped: *mut c_void,
    ) -> u32;
    fn GetVirtualDiskPhysicalPath(handle: *mut c_void, size: *mut u32, path: *mut u16) -> u32;
    fn DetachVirtualDisk(handle: *mut c_void, flags: u32, provider: u32) -> u32;
}
#[link(name = "kernel32")]
unsafe extern "system" {
    fn CloseHandle(handle: *mut c_void) -> i32;
    fn DeviceIoControl(
        handle: *mut c_void,
        code: u32,
        input: *const c_void,
        input_size: u32,
        output: *mut c_void,
        output_size: u32,
        returned: *mut u32,
        overlapped: *mut c_void,
    ) -> i32;
}
fn code(result: u32) -> io::Result<()> {
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(result as i32))
    }
}
pub struct OwnedVhd {
    handle: *mut c_void,
    attached: bool,
    logical: u32,
    physical_sector: u32,
}
impl OwnedVhd {
    fn new(path: &Path, logical: u32, physical: u32) -> io::Result<Self> {
        if path.exists() || path.extension().is_none_or(|e| e != "vhdx") {
            return Err(io::Error::other("VHDX output must be new"));
        }
        use std::os::windows::ffi::OsStrExt;
        let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
        let storage = Storage {
            device: 3,
            vendor: Guid {
                a: 0xec984aec,
                b: 0xa0f9,
                c: 0x47e9,
                d: [0x90, 0x1f, 0x71, 0x41, 0x5a, 0x66, 0x34, 0x5b],
            },
        };
        let params = Create {
            version: 2,
            v2: Version2 {
                maximum: 64 * 1024 * 1024,
                logical,
                physical,
                ..Default::default()
            },
        };
        let mut handle = std::ptr::null_mut();
        code(unsafe {
            CreateVirtualDisk(
                &storage,
                wide.as_ptr(),
                0,
                std::ptr::null(),
                0,
                0,
                &params,
                std::ptr::null_mut(),
                &mut handle,
            )
        })?;
        if handle.is_null() {
            return Err(io::Error::other("virtual disk returned no handle"));
        }
        Ok(Self {
            handle,
            attached: false,
            logical,
            physical_sector: physical,
        })
    }
    fn attach(&mut self) -> io::Result<()> {
        let params = Attach {
            version: 1,
            reserved: 0,
        };
        // No drive letter, no permanent lifetime. Closing the owning handle
        // also ends attachment; an explicit detach is checked on success.
        code(unsafe {
            AttachVirtualDisk(
                self.handle,
                std::ptr::null(),
                2,
                0,
                &params,
                std::ptr::null_mut(),
            )
        })?;
        self.attached = true;
        Ok(())
    }
    fn physical(&self) -> io::Result<String> {
        let mut path = [0u16; 128];
        let mut size = (path.len() * 2) as u32;
        code(unsafe { GetVirtualDiskPhysicalPath(self.handle, &mut size, path.as_mut_ptr()) })?;
        if size as usize > path.len() * 2 {
            return Err(io::Error::other("oversized virtual device path"));
        }
        let end = path
            .iter()
            .position(|n| *n == 0)
            .ok_or_else(|| io::Error::other("unterminated device path"))?;
        String::from_utf16(&path[..end]).map_err(io::Error::other)
    }
    pub fn detach(&mut self) -> io::Result<()> {
        code(unsafe { DetachVirtualDisk(self.handle, 0, 0) })?;
        self.attached = false;
        Ok(())
    }
}

impl Drop for OwnedVhd {
    fn drop(&mut self) {
        if self.attached {
            unsafe { DetachVirtualDisk(self.handle, 0, 0) };
        }
        unsafe { CloseHandle(self.handle) };
    }
}
fn number(path: &str) -> io::Result<u32> {
    let suffix = path
        .strip_prefix(r"\\.\PhysicalDrive")
        .ok_or_else(|| io::Error::other("unexpected virtual device path"))?;
    if suffix.is_empty() || !suffix.bytes().all(|n| n.is_ascii_digit()) {
        return Err(io::Error::other("invalid virtual device number"));
    }
    let n = suffix.parse::<u32>().map_err(io::Error::other)?;
    if n > 4095 {
        return Err(io::Error::other("virtual device number out of range"));
    }
    Ok(n)
}
fn offline_owned(disk: &OwnedVhd, expected: &str) -> io::Result<()> {
    if disk.physical()? != expected {
        return Err(io::Error::other("owned virtual disk path changed"));
    }
    let number = number(expected)?;
    let identity = windows_disk::inspect(number)?;
    if identity.length != 64 * 1024 * 1024 {
        return Err(io::Error::other("owned virtual disk geometry mismatch"));
    }
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .share_mode(3)
        .open(expected)?;
    // Only this harness can alter attributes, only on the device belonging to
    // its still-attached freshly-created VHD handle. Production factory cannot.
    use std::os::windows::io::AsRawHandle;
    let mut reply = [0u8; 12];
    let mut returned = 0;
    let success = unsafe {
        DeviceIoControl(
            file.as_raw_handle(),
            0x002d1080,
            std::ptr::null(),
            0,
            reply.as_mut_ptr().cast(),
            12,
            &mut returned,
            std::ptr::null_mut(),
        )
    };
    if success == 0 {
        return Err(io::Error::last_os_error());
    }
    if returned != 12
        || u32::from_le_bytes(reply[..4].try_into().unwrap()) != 7
        || u32::from_le_bytes(reply[4..8].try_into().unwrap()) != number
        || reply[8..] != [0; 4]
        || disk.physical()? != expected
    {
        return Err(io::Error::other(
            "offline handle does not match owned virtual disk",
        ));
    }
    let mut request = [0u8; 40];
    request[..4].copy_from_slice(&40u32.to_le_bytes());
    request[8..16].copy_from_slice(&1u64.to_le_bytes()); // offline
    request[16..24].copy_from_slice(&1u64.to_le_bytes()); // mask: offline only
    let success = unsafe {
        DeviceIoControl(
            file.as_raw_handle(),
            0x0007c0f4,
            request.as_ptr().cast(),
            40,
            std::ptr::null_mut(),
            0,
            &mut returned,
            std::ptr::null_mut(),
        )
    };
    if success == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

impl OwnedVhd {
    pub fn create(path: &Path, logical: u32, physical: u32) -> io::Result<Self> {
        if ![(512, 512), (512, 4096), (4096, 4096)].contains(&(logical, physical)) {
            return Err(io::Error::other("unsupported owned-test geometry"));
        }
        let mut owner = Self::new(path, logical, physical)?;
        owner.attach()?;
        offline_owned(&owner, &owner.physical()?)?;
        Ok(owner)
    }
    pub fn inspect(&self) -> io::Result<super::Inspection> {
        super::inspect_layout(number(&self.physical()?)?)
    }
    pub fn open(&self) -> io::Result<super::OfflineDisk> {
        if !self.attached {
            return Err(io::Error::other("owned disk detached"));
        }
        let path = self.physical()?;
        let expected = super::inspect(number(&path)?)?;
        if expected.length != 64 * 1024 * 1024
            || expected.logical_sector != self.logical
            || expected.physical_sector != self.physical_sector
        {
            return Err(io::Error::other("owned disk identity mismatch"));
        }
        let disk = super::OfflineDisk::open_checked(&expected)?;
        if self.physical()? != path {
            return Err(io::Error::other("owned disk changed"));
        }
        Ok(disk)
    }
    /// Exercises the production read-only handle on this newly owned VHD only.
    pub fn open_read(&self) -> io::Result<super::ReadOnlyDisk> {
        if !self.attached {
            return Err(io::Error::other("owned disk detached"));
        }
        let path = self.physical()?;
        let expected = super::inspect(number(&path)?)?;
        if expected.length != 64 * 1024 * 1024
            || expected.logical_sector != self.logical
            || expected.physical_sector != self.physical_sector
        {
            return Err(io::Error::other("owned disk identity mismatch"));
        }
        let disk = super::ReadOnlyDisk::open_checked(&expected)?;
        if self.physical()? != path {
            return Err(io::Error::other("owned disk changed"));
        }
        Ok(disk)
    }
    /// Formatting and layout construction are restricted to the new held VHD.
    pub fn preparation_slice(
        &self,
        offset: u64,
        length: u64,
    ) -> io::Result<crate::sector_device::SectorSlice<std::fs::File>> {
        self.open()?.slice(offset, length)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sdk_layout_and_owned_device_path_are_exact() {
        assert_eq!(std::mem::size_of::<Storage>(), 20);
        assert_eq!(std::mem::offset_of!(Create, v2), 8);
        assert_eq!(std::mem::offset_of!(Version2, maximum), 16);
        assert_eq!(std::mem::offset_of!(Version2, physical), 32);
        assert_eq!(std::mem::size_of::<Create>(), 128);
        assert_eq!(number(r"\\.\PhysicalDrive3").unwrap(), 3);
        for path in [
            r"\\.\PhysicalDrive",
            r"\\.\PhysicalDrive-1",
            r"\\.\PhysicalDrive4096",
            "C:",
        ] {
            assert!(number(path).is_err());
        }
    }
}
