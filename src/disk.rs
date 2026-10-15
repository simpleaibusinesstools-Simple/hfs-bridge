//! Windows physical-disk identity and guarded offline partition access.
//! No method changes disk attributes, formats disks, or brings a disk offline.
use crate::partitions::{self, Layout};
use crate::sector_device::SectorSlice;
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io;
use std::io::{Read, Seek, SeekFrom};
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::AsRawHandle;

// CTL_CODE values checked against the installed Windows SDK winioctl.h.
const GEOMETRY: u32 = 0x0007_00a0;
const LENGTH: u32 = 0x0007_405c;
const ATTRIBUTES: u32 = 0x0007_00f0;
const NUMBER: u32 = 0x002d_1080;
const PROPERTY: u32 = 0x002d_1400;
#[link(name = "kernel32")]
unsafe extern "system" {
    fn DeviceIoControl(
        device: *mut std::ffi::c_void,
        code: u32,
        input: *const std::ffi::c_void,
        input_size: u32,
        output: *mut std::ffi::c_void,
        output_size: u32,
        returned: *mut u32,
        overlapped: *mut std::ffi::c_void,
    ) -> i32;
}
fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
fn u32_at(bytes: &[u8], at: usize) -> io::Result<u32> {
    Ok(u32::from_le_bytes(
        bytes
            .get(at..at + 4)
            .ok_or_else(|| invalid("truncated disk reply"))?
            .try_into()
            .unwrap(),
    ))
}
fn u64_at(bytes: &[u8], at: usize) -> io::Result<u64> {
    Ok(u64::from_le_bytes(
        bytes
            .get(at..at + 8)
            .ok_or_else(|| invalid("truncated disk reply"))?
            .try_into()
            .unwrap(),
    ))
}
fn query(file: &File, code: u32, input: &[u8], capacity: usize) -> io::Result<Vec<u8>> {
    let mut bytes = vec![0; capacity];
    let mut returned = 0;
    // The file owns a synchronous handle; buffers and returned stay alive
    // throughout this METHOD_BUFFERED request. No asynchronous completion.
    let success = unsafe {
        DeviceIoControl(
            file.as_raw_handle(),
            code,
            input.as_ptr().cast(),
            input.len() as u32,
            bytes.as_mut_ptr().cast(),
            bytes.len() as u32,
            &mut returned,
            std::ptr::null_mut(),
        )
    };
    if success == 0 {
        return Err(io::Error::last_os_error());
    }
    if returned as usize > capacity {
        return Err(invalid("oversized disk reply"));
    }
    bytes.truncate(returned as usize);
    Ok(bytes)
}
fn property(file: &File, id: u32) -> io::Result<Vec<u8>> {
    let mut request = [0; 12];
    request[..4].copy_from_slice(&id.to_le_bytes());
    let header = query(file, PROPERTY, &request, 8)?;
    let size = u32_at(&header, 4)? as usize;
    if !(8..=65536).contains(&size) {
        return Err(invalid("invalid disk descriptor size"));
    }
    let bytes = query(file, PROPERTY, &request, size)?;
    if u32_at(&bytes, 4)? as usize != size || bytes.len() < size {
        return Err(invalid("changing or truncated disk descriptor"));
    }
    Ok(bytes)
}
fn serial(bytes: &[u8]) -> io::Result<String> {
    if bytes.len() < 36 || u32_at(bytes, 4)? as usize != bytes.len() {
        return Err(invalid("invalid device descriptor"));
    }
    let offset = u32_at(bytes, 24)? as usize;
    if offset == 0 {
        return Ok(String::new());
    }
    if offset < 36 || offset >= bytes.len() {
        return Err(invalid("invalid serial offset"));
    }
    let tail = &bytes[offset..];
    let end = tail
        .iter()
        .position(|b| *b == 0)
        .ok_or_else(|| invalid("unterminated serial"))?;
    if end > 256
        || tail[..end]
            .iter()
            .any(|b| !b.is_ascii_graphic() && *b != b' ')
    {
        return Err(invalid("invalid serial bytes"));
    }
    Ok(std::str::from_utf8(&tail[..end])
        .map_err(|_| invalid("non-ASCII serial"))?
        .trim()
        .to_owned())
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Identity {
    pub number: u32,
    pub length: u64,
    pub logical_sector: u32,
    /// Zero means the device does not implement the alignment query. Such
    /// devices may be inspected/read but cannot pass the physical-write gate.
    pub physical_sector: u32,
    pub serial: String,
    pub bus_type: u32,
    pub removable_media: bool,
    pub descriptor_hash: [u8; 32],
}
fn decode_identity(
    number: u32,
    device: &[u8],
    geometry: &[u8],
    length: &[u8],
    alignment: Option<&[u8]>,
    descriptor: &[u8],
) -> io::Result<Identity> {
    if u32_at(device, 0)? != 7 || u32_at(device, 4)? != number || u32_at(device, 8)? != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "handle is not the selected whole disk: type={}, number={}, partition={}",
                u32_at(device, 0)?,
                u32_at(device, 4)?,
                u32_at(device, 8)?
            ),
        ));
    }
    let length = u64_at(length, 0)?;
    let logical_sector = u32_at(geometry, 20)?;
    if ![512, 4096].contains(&logical_sector)
        || length == 0
        || length > i64::MAX as u64
        || !length.is_multiple_of(u64::from(logical_sector))
        || u64_at(geometry, 24)? != length
    {
        return Err(invalid("inconsistent or unsupported disk geometry"));
    }
    let physical_sector = if let Some(alignment) = alignment {
        let physical = u32_at(alignment, 20)?;
        if u32_at(alignment, 4)? != 28
            || alignment.len() < 28
            || u32_at(alignment, 16)? != logical_sector
            || ![512, 4096].contains(&physical)
            || physical < logical_sector
            || u32_at(alignment, 24)? != 0
            || !length.is_multiple_of(u64::from(physical))
        {
            return Err(invalid("inconsistent or unsupported disk alignment"));
        }
        physical
    } else {
        0
    };
    if descriptor.get(10).is_none_or(|flag| *flag > 1) {
        return Err(invalid("invalid removable-media flag"));
    }
    Ok(Identity {
        number,
        length,
        logical_sector,
        physical_sector,
        serial: serial(descriptor)?,
        bus_type: u32_at(descriptor, 28)?,
        removable_media: descriptor[10] != 0,
        descriptor_hash: Sha256::digest(descriptor).into(),
    })
}
fn optional_alignment(reply: io::Result<Vec<u8>>) -> io::Result<Option<Vec<u8>>> {
    match reply {
        Ok(bytes) => Ok(Some(bytes)),
        // ERROR_INVALID_FUNCTION / ERROR_NOT_SUPPORTED mean the device stack
        // lacks this query. Do not suppress access, media, malformed-reply or
        // transient I/O failures, and never invent a physical sector size.
        Err(error) if matches!(error.raw_os_error(), Some(1 | 50)) => Ok(None),
        Err(error) => Err(error),
    }
}
fn identify(file: &File, number: u32) -> io::Result<Identity> {
    let alignment = optional_alignment(property(file, 6))?;
    decode_identity(
        number,
        &query(file, NUMBER, &[], 12)?,
        &query(file, GEOMETRY, &[], 256)?,
        &query(file, LENGTH, &[], 8)?,
        alignment.as_deref(),
        &property(file, 0)?,
    )
}
fn require_offline_writable(bytes: &[u8]) -> io::Result<()> {
    if u32_at(bytes, 0)? != 16 || bytes.len() != 16 {
        return Err(invalid("invalid disk attributes"));
    }
    let attributes = u64_at(bytes, 8)?;
    if attributes & 1 == 0 || attributes & 2 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "disk must already be offline and writable",
        ));
    }
    Ok(())
}
fn disk_path(number: u32) -> io::Result<String> {
    if number > 4095 {
        return Err(invalid("disk number out of range"));
    }
    Ok(format!(r"\\.\PhysicalDrive{number}"))
}
pub fn inspect(number: u32) -> io::Result<Identity> {
    let file = OpenOptions::new()
        .read(true)
        .share_mode(3)
        .open(disk_path(number)?)?;
    identify(&file, number)
}

/// A read-only snapshot, not a mount or a promise of filesystem health.
#[derive(Debug)]
pub struct Inspection {
    pub identity: Identity,
    pub layout: Layout,
    pub offline: bool,
    pub read_only: bool,
    layout_hash: [u8; 32],
}
impl Inspection {
    /// Versioned, bounded JSON for the desktop controller. No paths or commands
    /// are accepted from this output; the native factory revalidates selection.
    pub fn json(&self) -> io::Result<String> {
        let i = &self.identity;
        let mut rows = Vec::new();
        for partition in &self.layout.partitions {
            let token = if partition.hfs_candidate {
                self.token(partition.number)?
            } else {
                String::new()
            };
            rows.push(format!("{{\"number\":{},\"name\":{},\"offset\":{},\"length\":{},\"hfsCandidate\":{},\"writable\":{},\"token\":{}}}",
                partition.number, json_string(&partition.name), partition.offset, partition.length,
                partition.hfs_candidate, partition.writable, json_string(&token)));
        }
        Ok(format!(
            "{{\"schema\":1,\"number\":{},\"length\":{},\"logicalSector\":{},\"physicalSector\":{},\"busType\":{},\"serial\":{},\"offline\":{},\"readOnly\":{},\"physicalWriteSupported\":{},\"removableMedia\":{},\"volumeLockSupported\":{},\"partitions\":[{}]}}",
            i.number,
            i.length,
            i.logical_sector,
            i.physical_sector,
            i.bus_type,
            json_string(&i.serial),
            self.offline,
            self.read_only,
            require_usb_native512(i).is_ok(),
            i.removable_media,
            require_removable_buffered(i).is_ok(),
            rows.join(",")
        ))
    }
    /// Binds selection to device identity and the exact partition metadata read.
    /// This is a stale-selection check, not authentication or write permission.
    pub fn token(&self, partition: u32) -> io::Result<String> {
        let selected = self.layout.select(partition, false)?;
        let mut hash = Sha256::new();
        hash.update(b"HFS Bridge disk selection v1\0");
        hash.update(self.identity.number.to_le_bytes());
        hash.update(self.identity.length.to_le_bytes());
        hash.update(self.identity.logical_sector.to_le_bytes());
        hash.update(self.identity.physical_sector.to_le_bytes());
        hash.update(self.identity.descriptor_hash);
        hash.update(self.layout_hash);
        hash.update(selected.number.to_le_bytes());
        hash.update(selected.offset.to_le_bytes());
        hash.update(selected.length.to_le_bytes());
        Ok(format!("{:X}", hash.finalize()))
    }
}
fn json_string(value: &str) -> String {
    let mut out = String::from("\"");
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if c < '\u{20}' => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}
struct LayoutReader<R> {
    inner: R,
    digest: Sha256,
    cursor: u64,
}
impl<R: Read> Read for LayoutReader<R> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        let count = self.inner.read(bytes)?;
        self.digest.update(self.cursor.to_le_bytes());
        self.digest.update((count as u64).to_le_bytes());
        self.digest.update(&bytes[..count]);
        self.cursor += count as u64;
        Ok(count)
    }
}
impl<R: Seek> Seek for LayoutReader<R> {
    fn seek(&mut self, at: SeekFrom) -> io::Result<u64> {
        self.cursor = self.inner.seek(at)?;
        Ok(self.cursor)
    }
}
fn read_layout<R: Read + Seek>(reader: R, identity: &Identity) -> io::Result<(Layout, [u8; 32])> {
    let mut reader = LayoutReader {
        inner: reader,
        digest: Sha256::new(),
        cursor: 0,
    };
    let layout = partitions::discover(&mut reader, identity.length, identity.logical_sector)?;
    Ok((layout, reader.digest.finalize().into()))
}
fn inspect_handle(file: &mut File, number: u32) -> io::Result<Inspection> {
    let identity = identify(file, number)?;
    let attrs = query(file, ATTRIBUTES, &[], 16)?;
    if attrs.len() != 16 || u32_at(&attrs, 0)? != 16 {
        return Err(invalid("invalid disk attributes"));
    }
    let attributes = u64_at(&attrs, 8)?;
    let mut reader = SectorSlice::new(
        &mut *file,
        identity.length,
        0,
        identity.length,
        identity.logical_sector as usize,
        false,
    )?;
    let (layout, layout_hash) = read_layout(&mut reader, &identity)?;
    // Detect a swapped device during snapshot collection; the mount also checks
    // everything again on its single exclusive, already-offline handle.
    if identify(file, number)? != identity {
        return Err(invalid("disk changed during inspection"));
    }
    Ok(Inspection {
        identity,
        layout,
        layout_hash,
        offline: attributes & 1 != 0,
        read_only: attributes & 2 != 0,
    })
}
pub fn inspect_layout(number: u32) -> io::Result<Inspection> {
    let mut file = OpenOptions::new()
        .read(true)
        .share_mode(3)
        .open(disk_path(number)?)?;
    inspect_handle(&mut file, number)
}
fn require_usb_native512(identity: &Identity) -> io::Result<()> {
    if identity.serial.is_empty()
        || identity.bus_type != 7
        || identity.logical_sector != 512
        || identity.physical_sector != 512
    {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "direct writes require a USB disk with a stable serial and native 512-byte sectors",
        ));
    }
    Ok(())
}
fn require_removable_buffered(identity: &Identity) -> io::Result<()> {
    if !identity.removable_media
        || identity.bus_type != 7
        || identity.serial.is_empty()
        || identity.logical_sector != 512
        || ![0, 512].contains(&identity.physical_sector)
    {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "volume locking requires removable USB media with 512-byte logical sectors and a stable serial",
        ));
    }
    Ok(())
}
fn validate_token(token: &str) -> io::Result<()> {
    if token.len() != 64 || !token.bytes().all(|c| c.is_ascii_hexdigit()) {
        return Err(invalid(
            "expected the 64-digit selection token from disk-inspect",
        ));
    }
    Ok(())
}
fn verify_selection(
    snapshot: &Inspection,
    number: u32,
    token: &str,
) -> io::Result<partitions::Partition> {
    verify_selection_access(snapshot, number, token, true)
}
fn verify_selection_access(
    snapshot: &Inspection,
    number: u32,
    token: &str,
    writable: bool,
) -> io::Result<partitions::Partition> {
    validate_token(token)?;
    if !snapshot.token(number)?.eq_ignore_ascii_case(token) {
        return Err(invalid("disk or partition changed; inspect again"));
    }
    let selected = snapshot.layout.select(number, writable)?;
    if !selected
        .offset
        .is_multiple_of(u64::from(snapshot.identity.logical_sector))
        || !selected
            .length
            .is_multiple_of(u64::from(snapshot.identity.logical_sector))
    {
        return Err(invalid("partition is not aligned to this device"));
    }
    Ok(selected.clone())
}
/// Holds one exclusive handle to a disk that was already offline. No method
/// changes attributes, takes a physical disk offline, or formats it.
pub struct OfflineDisk {
    file: File,
    identity: Identity,
    adapter: Vec<u8>,
    transfer_limit: usize,
}
impl OfflineDisk {
    fn open_checked(expected: &Identity) -> io::Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .share_mode(0)
            .custom_flags(0x8000_0000)
            .open(disk_path(expected.number)?)?;
        let identity = identify(&file, expected.number)?;
        if &identity != expected {
            return Err(invalid("disk identity changed; inspect again"));
        }
        require_offline_writable(&query(&file, ATTRIBUTES, &[], 16)?)?;
        let adapter = property(&file, 1)?;
        let transfer_limit =
            locked_volume::transfer_limit(&adapter, identity.logical_sector as usize)?;
        Ok(Self {
            file,
            identity,
            adapter,
            transfer_limit,
        })
    }
    fn slice(self, offset: u64, length: u64) -> io::Result<SectorSlice<File>> {
        require_offline_writable(&query(&self.file, ATTRIBUTES, &[], 16)?)?;
        if property(&self.file, 1)? != self.adapter {
            return Err(invalid(
                "storage adapter changed while acquiring disk ownership",
            ));
        }
        SectorSlice::new(
            self.file,
            self.identity.length,
            offset,
            length,
            self.identity.logical_sector as usize,
            true,
        )?
        .with_transfer_limit(self.transfer_limit)
    }
    pub fn select(mut self, number: u32, token: &str) -> io::Result<SectorSlice<File>> {
        let snapshot = inspect_handle(&mut self.file, self.identity.number)?;
        if snapshot.identity != self.identity {
            return Err(invalid("held disk identity changed"));
        }
        let selected = verify_selection(&snapshot, number, token)?;
        self.slice(selected.offset, selected.length)
    }
}
/// Refuses unsupported disks before acquiring a write handle. Selection is
/// revalidated after exclusive acquisition, before exposing any write method.
pub fn open_partition(number: u32, partition: u32, token: &str) -> io::Result<SectorSlice<File>> {
    validate_token(token)?;
    let expected = inspect(number)?;
    require_usb_native512(&expected)?;
    OfflineDisk::open_checked(&expected)?.select(partition, token)
}
/// One read-only OS handle. FILE_SHARE_READ denies concurrent write/delete
/// opens; the bounded slice also rejects all writes and never syncs storage.
pub struct ReadOnlyDisk {
    file: File,
    identity: Identity,
}
impl ReadOnlyDisk {
    fn open_checked(expected: &Identity) -> io::Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .share_mode(1)
            .custom_flags(0x8000_0000)
            .open(disk_path(expected.number)?)?;
        let identity = identify(&file, expected.number)?;
        if &identity != expected {
            return Err(invalid("disk identity changed; inspect again"));
        }
        Ok(Self { file, identity })
    }
    pub fn select(mut self, partition: u32, token: &str) -> io::Result<SectorSlice<File>> {
        let snapshot = inspect_handle(&mut self.file, self.identity.number)?;
        if snapshot.identity != self.identity {
            return Err(invalid("held read-only disk identity changed"));
        }
        let selected = verify_selection_access(&snapshot, partition, token, false)?;
        SectorSlice::new(
            self.file,
            self.identity.length,
            selected.offset,
            selected.length,
            self.identity.logical_sector as usize,
            false,
        )
    }
}
/// Allows online or write-protected USB media, but only reads it. This is
/// separate from the unchanged offline/native512 physical-write factory.
pub fn open_read_partition(
    number: u32,
    partition: u32,
    token: &str,
) -> io::Result<SectorSlice<File>> {
    validate_token(token)?;
    let expected = inspect(number)?;
    if expected.bus_type != 7 || expected.serial.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "direct reads require a USB disk with a stable serial",
        ));
    }
    ReadOnlyDisk::open_checked(&expected)?.select(partition, token)
}
pub mod locked_volume;
#[cfg(feature = "owned-vhd-test")]
pub mod owned;
pub mod read;
pub mod source;
#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    #[test]
    fn desktop_protocol_preserves_unicode_and_escapes_control_data() {
        assert_eq!(
            json_string("Mac Ω\"\\\n\0"),
            "\"Mac Ω\\\"\\\\\\u000a\\u0000\""
        );
        let mut fixture = snapshot(mbr());
        fixture.identity.bus_type = 7;
        fixture.layout.partitions[0].name = "Mac Ω\"\\\n".into();
        let value = fixture.json().unwrap();
        assert!(value.starts_with("{\"schema\":1,\"number\":3,"));
        assert!(value.contains("\"offset\":1024,\"length\":4096,"));
        assert!(value.contains(&format!("\"token\":\"{}\"", fixture.token(1).unwrap())));
        println!("DESKTOP_PROTOCOL_JSON={value}");
    }
    pub(super) fn snapshot(bytes: Vec<u8>) -> Inspection {
        let (d, g, l, a, s) = replies();
        let mut identity = decode_identity(3, &d, &g, &l, Some(&a), &s).unwrap();
        identity.length = bytes.len() as u64;
        let (layout, layout_hash) = read_layout(Cursor::new(bytes), &identity).unwrap();
        Inspection {
            identity,
            layout,
            layout_hash,
            offline: true,
            read_only: false,
        }
    }
    pub(super) fn mbr() -> Vec<u8> {
        let mut bytes = vec![0; 8192];
        bytes[510..512].copy_from_slice(&[0x55, 0xaa]);
        bytes[450] = 0xaf;
        bytes[454..458].copy_from_slice(&2u32.to_le_bytes());
        bytes[458..462].copy_from_slice(&8u32.to_le_bytes());
        bytes
    }
    #[test]
    fn stale_disk_and_partition_selections_are_refused() {
        let original = snapshot(mbr());
        let token = original.token(1).unwrap();
        assert_eq!(verify_selection(&original, 1, &token).unwrap().offset, 1024);
        for field in 0..6 {
            let mut changed = snapshot(mbr());
            match field {
                0 => changed.identity.number += 1,
                1 => changed.identity.length += 512,
                2 => changed.identity.logical_sector = 4096,
                3 => changed.identity.physical_sector = 4096,
                4 => changed.identity.descriptor_hash[0] ^= 1,
                _ => changed.layout_hash[0] ^= 1,
            }
            assert!(verify_selection(&changed, 1, &token).is_err());
        }
        // Even a disk-signature change that leaves decoded partitions identical
        // must invalidate selection. Do not hash only the displayed layout.
        let mut changed = mbr();
        changed[440] = 99;
        assert!(verify_selection(&snapshot(changed), 1, &token).is_err());
        assert!(verify_selection(&original, 2, &token).is_err());
        let mut readonly = snapshot(mbr());
        readonly.layout.partitions[0].writable = false;
        assert!(verify_selection(&readonly, 1, &token).is_err());
        let mut nonhfs = snapshot(mbr());
        nonhfs.layout.partitions[0].hfs_candidate = false;
        assert!(verify_selection(&nonhfs, 1, &token).is_err());
    }
    #[test]
    fn read_selection_accepts_protected_media_without_relaxing_writes() {
        let mut protected = snapshot(mbr());
        protected.offline = false;
        protected.read_only = true;
        protected.layout.partitions[0].writable = false;
        let token = protected.token(1).unwrap();
        assert!(verify_selection_access(&protected, 1, &token, false).is_ok());
        assert!(verify_selection(&protected, 1, &token).is_err());
        assert!(verify_selection_access(&protected, 1, &"0".repeat(64), false).is_err());
        assert!(verify_selection_access(&protected, 2, &token, false).is_err());
        protected.layout.partitions[0].hfs_candidate = false;
        assert!(verify_selection_access(&protected, 1, &token, false).is_err());
    }
    #[test]
    fn malformed_tokens_cannot_open_any_disk() {
        for token in [
            "",
            "yes",
            "123",
            &"g".repeat(64),
            &"0".repeat(63),
            &"0".repeat(65),
        ] {
            assert!(
                matches!(open_partition(0, 1, token), Err(error) if error.kind() == io::ErrorKind::InvalidData)
            );
        }
    }
    #[test]
    fn physical_write_gate_rejects_non_usb_buses() {
        let (d, g, l, a, s) = replies();
        let mut identity = decode_identity(3, &d, &g, &l, Some(&a), &s).unwrap();
        for bus in 0..24 {
            identity.bus_type = bus;
            assert_eq!(require_usb_native512(&identity).is_ok(), bus == 7);
        }
    }
    type Replies = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);
    fn replies() -> Replies {
        let mut device = vec![0; 12];
        device[..4].copy_from_slice(&7u32.to_le_bytes());
        device[4..8].copy_from_slice(&3u32.to_le_bytes());
        let mut geometry = vec![0; 32];
        geometry[20..24].copy_from_slice(&512u32.to_le_bytes());
        geometry[24..].copy_from_slice(&8192u64.to_le_bytes());
        let length = 8192u64.to_le_bytes().to_vec();
        let mut alignment = vec![0; 28];
        alignment[..4].copy_from_slice(&28u32.to_le_bytes());
        alignment[4..8].copy_from_slice(&28u32.to_le_bytes());
        alignment[16..20].copy_from_slice(&512u32.to_le_bytes());
        alignment[20..24].copy_from_slice(&512u32.to_le_bytes());
        let mut descriptor = vec![0; 41];
        descriptor[4..8].copy_from_slice(&41u32.to_le_bytes());
        descriptor[24..28].copy_from_slice(&36u32.to_le_bytes());
        descriptor[36..].copy_from_slice(b"AB12\0");
        (device, geometry, length, alignment, descriptor)
    }
    #[test]
    fn production_gate_refuses_missing_serial_before_opening_any_device() {
        let expected = Identity {
            number: 0,
            length: 8192,
            logical_sector: 512,
            physical_sector: 512,
            serial: String::new(),
            bus_type: 7,
            removable_media: false,
            descriptor_hash: [0; 32],
        };
        assert!(
            matches!(require_usb_native512(&expected),Err(error) if error.kind()==io::ErrorKind::Unsupported)
        );
        // Owned geometry features must never widen the production factory.
        for (logical, physical) in [(512, 4096), (4096, 4096)] {
            let mut changed = expected.clone();
            changed.serial = "real-device-serial".into();
            changed.logical_sector = logical;
            changed.physical_sector = physical;
            assert!(
                matches!(require_usb_native512(&changed),Err(error) if error.kind()==io::ErrorKind::Unsupported)
            );
        }
    }
    #[test]
    fn validates_whole_disk_identity_and_every_reply_boundary() {
        let (d, g, l, a, s) = replies();
        let expected = decode_identity(3, &d, &g, &l, Some(&a), &s).unwrap();
        assert_eq!(expected.serial, "AB12");
        assert_eq!(expected.length, 8192);
        for cut in 0..12 {
            assert!(decode_identity(3, &d[..cut], &g, &l, Some(&a), &s).is_err());
        }
        for cut in 0..32 {
            assert!(decode_identity(3, &d, &g[..cut], &l, Some(&a), &s).is_err());
        }
        for cut in 0..8 {
            assert!(decode_identity(3, &d, &g, &l[..cut], Some(&a), &s).is_err());
        }
        for cut in 0..28 {
            assert!(decode_identity(3, &d, &g, &l, Some(&a[..cut]), &s).is_err());
        }
        assert!(decode_identity(4, &d, &g, &l, Some(&a), &s).is_err());
        let mut partition = d.clone();
        partition[8..12].copy_from_slice(&1u32.to_le_bytes());
        assert!(decode_identity(3, &partition, &g, &l, Some(&a), &s).is_err());
        partition[8..].fill(255);
        assert!(decode_identity(3, &partition, &g, &l, Some(&a), &s).is_err());
        let mut size = l.clone();
        size[0] = 1;
        assert!(decode_identity(3, &d, &g, &size, Some(&a), &s).is_err());
    }
    #[test]
    fn missing_alignment_allows_reads_but_never_authorizes_writes() {
        let (d, g, l, _, s) = replies();
        let identity = decode_identity(3, &d, &g, &l, None, &s).unwrap();
        assert_eq!(identity.logical_sector, 512);
        assert_eq!(identity.physical_sector, 0);
        assert!(require_usb_native512(&identity).is_err());
        let mut inspection = snapshot(mbr());
        let original_token = inspection.token(1).unwrap();
        inspection.identity.physical_sector = 0;
        let token = inspection.token(1).unwrap();
        assert_ne!(original_token, token);
        assert!(verify_selection_access(&inspection, 1, &token, false).is_ok());
        let json = inspection.json().unwrap();
        assert!(json.contains("\"physicalSector\":0"));
        assert!(json.contains("\"physicalWriteSupported\":false"));
        let mut wrong_length = l.clone();
        wrong_length[0] = 1;
        assert!(decode_identity(3, &d, &g, &wrong_length, None, &s).is_err());
        assert!(decode_identity(4, &d, &g, &l, None, &s).is_err());
    }
    #[test]
    fn buffered_volume_gate_requires_removable_usb_and_retains_offline_gate() {
        let mut fixture = snapshot(mbr());
        fixture.identity.bus_type = 7;
        assert!(require_removable_buffered(&fixture.identity).is_err());
        fixture.identity.removable_media = true;
        for physical in [0, 512] {
            fixture.identity.physical_sector = physical;
            require_removable_buffered(&fixture.identity).unwrap();
            assert_eq!(
                require_usb_native512(&fixture.identity).is_ok(),
                physical == 512
            );
        }
        fixture.identity.physical_sector = 4096;
        assert!(require_removable_buffered(&fixture.identity).is_err());
        fixture.identity.physical_sector = 0;
        fixture.identity.logical_sector = 4096;
        assert!(require_removable_buffered(&fixture.identity).is_err());
        fixture.identity.logical_sector = 512;
        fixture.identity.bus_type = 17;
        assert!(require_removable_buffered(&fixture.identity).is_err());
        fixture.identity.bus_type = 7;
        fixture.identity.serial.clear();
        assert!(require_removable_buffered(&fixture.identity).is_err());
    }
    #[test]
    fn only_explicitly_unsupported_alignment_errors_are_optional() {
        for code in [1, 50] {
            assert!(
                optional_alignment(Err(io::Error::from_raw_os_error(code)))
                    .unwrap()
                    .is_none()
            );
        }
        for code in [5, 21, 23, 87, 1117, 1167] {
            assert_eq!(
                optional_alignment(Err(io::Error::from_raw_os_error(code)))
                    .unwrap_err()
                    .raw_os_error(),
                Some(code)
            );
        }
        let (d, g, l, _, s) = replies();
        // A successful but empty/truncated reply is corruption, not absence.
        let empty = optional_alignment(Ok(vec![])).unwrap();
        assert!(decode_identity(3, &d, &g, &l, empty.as_deref(), &s).is_err());
        assert!(optional_alignment(Err(invalid("malformed reply"))).is_err());
    }
    #[test]
    fn rejects_online_readonly_and_malformed_disk_attributes() {
        let mut attrs = vec![0; 16];
        attrs[..4].copy_from_slice(&16u32.to_le_bytes());
        assert!(require_offline_writable(&attrs).is_err());
        attrs[8] = 1;
        require_offline_writable(&attrs).unwrap();
        attrs[8] = 3;
        assert!(require_offline_writable(&attrs).is_err());
        for n in 0..16 {
            assert!(require_offline_writable(&attrs[..n]).is_err());
        }
        assert!(disk_path(4096).is_err());
        assert_eq!(disk_path(3).unwrap(), r"\\.\PhysicalDrive3");
    }
    #[test]
    fn rejects_forged_serial_offsets_unterminated_and_non_ascii_values() {
        let (_, _, _, _, s) = replies();
        for n in 0..36 {
            assert!(serial(&s[..n]).is_err());
        }
        for offset in [1u32, 35, 41, u32::MAX] {
            let mut bad = s.clone();
            bad[24..28].copy_from_slice(&offset.to_le_bytes());
            assert!(serial(&bad).is_err());
        }
        let mut bad = s.clone();
        bad[40] = 1;
        assert!(serial(&bad).is_err());
        bad[40] = 0;
        bad[36] = 255;
        assert!(serial(&bad).is_err());
        bad[24..28].fill(0);
        assert_eq!(serial(&bad).unwrap(), "");
    }
}
