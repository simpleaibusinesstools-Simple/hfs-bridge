//! Buffered, write-through access to one locked removable USB partition.
//! The volume lock and a whole-disk read handle denying raw writers live for
//! the entire device lifetime. No disk attributes or partition maps are changed.
use super::*;
use crate::sector_device::DurableIo;
use std::io::Write;

const EXTENTS: u32 = 0x0056_0000;
const LOCK: u32 = 0x0009_0018;
const DISMOUNT: u32 = 0x0009_0020;

pub(super) fn transfer_limit(descriptor: &[u8], sector: usize) -> io::Result<usize> {
    if descriptor.len() < 32
        || u32_at(descriptor, 0)? < 32
        || u32_at(descriptor, 0)? as usize > descriptor.len()
        || u32_at(descriptor, 4)? as usize != descriptor.len()
        || ![512, 4096].contains(&sector)
    {
        return Err(invalid("invalid storage adapter descriptor"));
    }
    let bytes = u64::from(u32_at(descriptor, 8)?);
    let pages = u32_at(descriptor, 12)?;
    let mask = u32_at(descriptor, 16)?;
    if pages == 0 || mask > 4095 || !(mask + 1).is_power_of_two() {
        return Err(invalid("unsupported adapter pages or buffer alignment"));
    }
    // Each SectorSlice bounce buffer starts on a 4KiB boundary. Reserve one
    // page for adapters with multiple pages, conservatively using the minimum
    // Windows page size. A single-page 4KiB transfer remains aligned.
    let page_bytes = u64::from(pages.saturating_sub(1).max(1)) * 4096;
    let limit = bytes.min(page_bytes).min(1024 * 1024) as usize / sector * sector;
    if limit < sector {
        return Err(invalid("adapter cannot transfer one logical sector"));
    }
    Ok(limit)
}

fn partition_path(number: u32, partition: u32) -> io::Result<String> {
    if number > 4095 || !(1..=4095).contains(&partition) {
        return Err(invalid("invalid disk or partition number"));
    }
    Ok(format!(
        r"\\?\GLOBALROOT\Device\Harddisk{number}\Partition{partition}"
    ))
}

fn removable_transfer_limit(descriptor: &[u8], identity: &Identity) -> io::Result<usize> {
    require_removable_buffered(identity)?;
    let adapter_limit = transfer_limit(descriptor, identity.logical_sector as usize)?;
    // Readers that cannot report physical geometry use one aligned 4KiB page
    // per request. This conservative policy also respects smaller adapter caps;
    // it neither assumes physical geometry nor retries uncertain I/O.
    Ok(if identity.physical_sector == 0 {
        adapter_limit.min(4096)
    } else {
        adapter_limit
    })
}

fn validate_volume(
    disk: u32,
    selected: &partitions::Partition,
    device: &[u8],
    length: &[u8],
    extents: &[u8],
) -> io::Result<()> {
    if device.len() != 12
        || u32_at(device, 0)? != 7
        || u32_at(device, 4)? != disk
        || u32_at(device, 8)? != selected.number
        || length.len() != 8
        || u64_at(length, 0)? != selected.length
        || extents.len() != 32
        || u32_at(extents, 0)? != 1
        || u32_at(extents, 8)? != disk
        || u64_at(extents, 16)? != selected.offset
        || u64_at(extents, 24)? != selected.length
    {
        return Err(invalid(
            "volume does not match the selected single disk partition",
        ));
    }
    Ok(())
}

fn check_volume(file: &File, disk: u32, selected: &partitions::Partition) -> io::Result<()> {
    validate_volume(
        disk,
        selected,
        &query(file, NUMBER, &[], 12)?,
        &query(file, LENGTH, &[], 8)?,
        &query(file, EXTENTS, &[], 32)?,
    )
}

pub struct LockedVolume {
    // Closing the volume handle releases FSCTL_LOCK_VOLUME. Keep it before
    // disk_guard so the read-only whole-disk protection is released last.
    file: File,
    _disk_guard: File,
}
impl Read for LockedVolume {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        self.file.read(out)
    }
}
impl Write for LockedVolume {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.file.write(bytes)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}
impl Seek for LockedVolume {
    fn seek(&mut self, at: SeekFrom) -> io::Result<u64> {
        self.file.seek(at)
    }
}
impl DurableIo for LockedVolume {
    fn sync_all(&mut self) -> io::Result<()> {
        self.file.sync_all()
    }
}

pub fn open(number: u32, partition: u32, token: &str) -> io::Result<SectorSlice<LockedVolume>> {
    validate_token(token)?;
    // Deny competing whole-disk writers while allowing a distinct partition
    // device to be locked below. Failure never falls back to shared raw writes.
    let mut disk_guard = OpenOptions::new()
        .read(true)
        .share_mode(1)
        .open(disk_path(number)?)?;
    let before = inspect_handle(&mut disk_guard, number)?;
    require_removable_buffered(&before.identity)?;
    if before.offline || before.read_only {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "volume locking requires an online writable USB",
        ));
    }
    let selected = verify_selection(&before, partition, token)?;
    let adapter = property(&disk_guard, 1)?;
    let max_transfer = removable_transfer_limit(&adapter, &before.identity)?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .share_mode(3)
        .custom_flags(0x8000_0000) // FILE_FLAG_WRITE_THROUGH; keep buffered I/O.
        .open(partition_path(number, partition)?)?;
    check_volume(&file, number, &selected)?;
    // Only a successful lock permits dismount. The lock stays on this exact
    // handle through the adapter's final durable flush and device destruction.
    query(&file, LOCK, &[], 0)?;
    query(&file, DISMOUNT, &[], 0)?;
    check_volume(&file, number, &selected)?;
    let after = inspect_handle(&mut disk_guard, number)?;
    if after.identity != before.identity
        || after.offline
        || after.read_only
        || after.token(partition)? != before.token(partition)?
        || property(&disk_guard, 1)? != adapter
    {
        return Err(invalid(
            "disk selection changed while acquiring the volume lock",
        ));
    }
    // Bounds are relative to the partition handle, never to the physical disk.
    eprintln!("USB transfer limit: {max_transfer} bytes; buffered write-through, locked partition");
    SectorSlice::new(
        LockedVolume {
            file,
            _disk_guard: disk_guard,
        },
        selected.length,
        0,
        selected.length,
        before.identity.logical_sector as usize,
        true,
    )?
    .with_transfer_limit(max_transfer)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unknown_reader_geometry_uses_small_requests_without_weakening_admission() {
        let mut descriptor = [0u8; 32];
        for (at, value) in [(0, 32u32), (4, 32), (8, 65536), (12, 17)] {
            descriptor[at..at + 4].copy_from_slice(&value.to_le_bytes());
        }
        let mut identity = super::super::tests::snapshot(super::super::tests::mbr()).identity;
        identity.bus_type = 7;
        identity.removable_media = true;
        identity.physical_sector = 0;
        assert_eq!(
            removable_transfer_limit(&descriptor, &identity).unwrap(),
            4096
        );
        identity.physical_sector = 512;
        assert_eq!(
            removable_transfer_limit(&descriptor, &identity).unwrap(),
            65536
        );
        identity.physical_sector = 0;
        descriptor[8..12].copy_from_slice(&1024u32.to_le_bytes());
        assert_eq!(
            removable_transfer_limit(&descriptor, &identity).unwrap(),
            1024
        );
        descriptor[8..12].fill(0);
        assert!(removable_transfer_limit(&descriptor, &identity).is_err());
        descriptor[8..12].copy_from_slice(&65536u32.to_le_bytes());
        identity.physical_sector = 4096;
        assert!(removable_transfer_limit(&descriptor, &identity).is_err());
        identity.physical_sector = 0;
        identity.removable_media = false;
        assert!(removable_transfer_limit(&descriptor, &identity).is_err());
    }
    #[test]
    fn adapter_limits_reject_malformed_and_bound_both_bytes_and_pages() {
        let mut data = [0u8; 32];
        for (at, value) in [(0, 32u32), (4, 32), (8, 65536), (12, 17)] {
            data[at..at + 4].copy_from_slice(&value.to_le_bytes());
        }
        assert_eq!(transfer_limit(&data, 512).unwrap(), 65536);
        for cut in 0..32 {
            assert!(transfer_limit(&data[..cut], 512).is_err());
        }
        for at in [0, 4, 8, 12] {
            let mut bad = data;
            bad[at..at + 4].fill(0);
            assert!(transfer_limit(&bad, 512).is_err());
        }
        for mask in [2, 4096, u32::MAX] {
            let mut bad = data;
            bad[16..20].copy_from_slice(&mask.to_le_bytes());
            assert!(transfer_limit(&bad, 512).is_err());
        }
        data[12..16].copy_from_slice(&2u32.to_le_bytes());
        assert_eq!(transfer_limit(&data, 512).unwrap(), 4096);
        data[12..16].copy_from_slice(&1u32.to_le_bytes());
        assert_eq!(transfer_limit(&data, 512).unwrap(), 4096);
        data[12..16].copy_from_slice(&u32::MAX.to_le_bytes());
        data[8..12].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(transfer_limit(&data, 4096).unwrap(), 1024 * 1024);
        data[8..12].copy_from_slice(&4095u32.to_le_bytes());
        assert_eq!(transfer_limit(&data, 512).unwrap(), 3584);
        assert!(transfer_limit(&data, 4096).is_err());
    }
    #[test]
    fn selected_partition_checks_every_extent_boundary_and_identity() {
        let fixture = super::super::tests::snapshot(super::super::tests::mbr());
        let selected = fixture.layout.select(1, true).unwrap();
        let mut number = [0; 12];
        number[..4].copy_from_slice(&7u32.to_le_bytes());
        number[4..8].copy_from_slice(&3u32.to_le_bytes());
        number[8..].copy_from_slice(&1u32.to_le_bytes());
        let length = selected.length.to_le_bytes();
        let mut extent = [0; 32];
        extent[..4].copy_from_slice(&1u32.to_le_bytes());
        extent[8..12].copy_from_slice(&3u32.to_le_bytes());
        extent[16..24].copy_from_slice(&selected.offset.to_le_bytes());
        extent[24..].copy_from_slice(&selected.length.to_le_bytes());
        validate_volume(3, selected, &number, &length, &extent).unwrap();
        for cut in 0..32 {
            assert!(validate_volume(3, selected, &number, &length, &extent[..cut]).is_err());
        }
        for cut in 0..12 {
            assert!(validate_volume(3, selected, &number[..cut], &length, &extent).is_err());
        }
        for cut in 0..8 {
            assert!(validate_volume(3, selected, &number, &length[..cut], &extent).is_err());
        }
        for field in [0, 8, 16, 24] {
            let mut bad = extent;
            bad[field] ^= 1;
            assert!(validate_volume(3, selected, &number, &length, &bad).is_err());
        }
        assert!(validate_volume(4, selected, &number, &length, &extent).is_err());
        assert!(partition_path(0, 0).is_err());
        assert!(partition_path(4096, 1).is_err());
        assert!(partition_path(1, 4096).is_err());
        assert_eq!(
            partition_path(3, 2).unwrap(),
            r"\\?\GLOBALROOT\Device\Harddisk3\Partition2"
        );
    }
}
