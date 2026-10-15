//! Bounded sector I/O. Raw-device construction lives in the Windows disk factory.
use std::io::{self, Read, Seek, SeekFrom, Write};
pub trait DurableIo: Read + Write + Seek {
    fn sync_all(&mut self) -> io::Result<()>;
}
impl DurableIo for std::fs::File {
    fn sync_all(&mut self) -> io::Result<()> {
        std::fs::File::sync_all(self)
    }
}
impl<T: DurableIo + ?Sized> DurableIo for &mut T {
    fn sync_all(&mut self) -> io::Result<()> {
        (**self).sync_all()
    }
}
// Raw storage handles can require aligned addresses as well as sector-sized
// transfers. This bounded bounce buffer uses only safe slices of one Vec.
struct AlignedBuffer {
    storage: Vec<u8>,
    begin: usize,
    length: usize,
}
impl AlignedBuffer {
    fn new(length: usize) -> io::Result<Self> {
        if length == 0 || length > 1024 * 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid transfer size",
            ));
        }
        let mut storage = Vec::new();
        storage
            .try_reserve_exact(length + 4095)
            .map_err(io::Error::other)?;
        storage.resize(length + 4095, 0);
        let begin = (4096 - storage.as_ptr() as usize % 4096) % 4096;
        Ok(Self {
            storage,
            begin,
            length,
        })
    }
    fn bytes(&mut self) -> &mut [u8] {
        &mut self.storage[self.begin..self.begin + self.length]
    }
}
pub struct SectorSlice<D> {
    device: D,
    base: u64,
    length: u64,
    cursor: u64,
    sector: usize,
    transfer_limit: usize,
    writable: bool,
    failed: bool,
}
impl<D: Read + Write + Seek> SectorSlice<D> {
    pub fn new(
        device: D,
        device_length: u64,
        base: u64,
        length: u64,
        sector: usize,
        writable: bool,
    ) -> io::Result<Self> {
        if ![512, 4096].contains(&sector)
            || !base.is_multiple_of(sector as u64)
            || !length.is_multiple_of(sector as u64)
            || length == 0
            || base
                .checked_add(length)
                .is_none_or(|end| end > device_length)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid sector-aligned partition bounds",
            ));
        }
        Ok(Self {
            device,
            base,
            length,
            cursor: 0,
            sector,
            transfer_limit: 1024 * 1024,
            writable,
            failed: false,
        })
    }
    /// Bound individual device calls without changing partition bounds, flush
    /// barriers, or the fail-stop behavior after an uncertain partial write.
    pub fn with_transfer_limit(mut self, bytes: usize) -> io::Result<Self> {
        if bytes < self.sector || bytes > 1024 * 1024 || !bytes.is_multiple_of(self.sector) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid sector transfer limit",
            ));
        }
        self.transfer_limit = bytes;
        Ok(self)
    }
    fn checked_write(&mut self, offset: u64, bytes: &[u8]) -> io::Result<()> {
        let result = (|| {
            let mut aligned = AlignedBuffer::new(bytes.len())?;
            aligned.bytes().copy_from_slice(bytes);
            self.device.seek(SeekFrom::Start(offset))?;
            // A short device write is an uncertain mutation. Never retry it.
            let count = self.device.write(aligned.bytes())?;
            if count != bytes.len() {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "short sector write; reopen device",
                ));
            }
            Ok(())
        })();
        if result.is_err() {
            self.failed = true;
        }
        if let Err(error) = &result {
            eprintln!(
                "SECTOR_DIAGNOSTIC write: offset={offset} bytes={} error={error}",
                bytes.len()
            );
        }
        result
    }
    fn checked_read(
        &mut self,
        offset: u64,
        bytes: &mut [u8],
        before_write: bool,
    ) -> io::Result<()> {
        let result = (|| {
            self.device.seek(SeekFrom::Start(offset))?;
            // One request only. Preserve the original OS error and let the
            // caller fail-stop; diagnostics must never introduce retries.
            if self.device.read(bytes)? != bytes.len() {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    if before_write {
                        "short sector read before write"
                    } else {
                        "short sector read"
                    },
                ));
            }
            Ok(())
        })();
        if let Err(error) = &result {
            let operation = if before_write {
                "read before write"
            } else {
                "read"
            };
            eprintln!(
                "SECTOR_DIAGNOSTIC {operation}: offset={offset} bytes={} error={error}",
                bytes.len()
            );
        }
        result
    }
}
impl<D: Read + Write + Seek> Read for SectorSlice<D> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.failed {
            return Err(io::Error::other("failed device; read refused"));
        }
        let count = (out.len() as u64).min(self.length - self.cursor) as usize;
        let result = self.read_sectors(&mut out[..count]);
        if result.is_err() {
            self.failed = true;
        }
        result
    }
}
impl<D: Read + Write + Seek> SectorSlice<D> {
    fn read_sectors(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let count = out.len();
        let mut done = 0;
        let mut aligned_scratch = AlignedBuffer::new(self.sector)?;
        let scratch = aligned_scratch.bytes();
        while done < count {
            let at = self.cursor + done as u64;
            let sector_start = at / self.sector as u64 * self.sector as u64;
            let within = (at - sector_start) as usize;
            if within == 0 && count - done >= self.sector {
                let n = ((count - done).min(self.transfer_limit) / self.sector) * self.sector;
                let mut transfer = AlignedBuffer::new(n)?;
                self.checked_read(self.base + sector_start, transfer.bytes(), false)?;
                out[done..done + n].copy_from_slice(transfer.bytes());
                done += n;
                continue;
            }
            let n = (count - done).min(self.sector - within);
            self.checked_read(self.base + sector_start, scratch, false)?;
            out[done..done + n].copy_from_slice(&scratch[within..within + n]);
            done += n;
        }
        self.cursor += count as u64;
        Ok(count)
    }
}
impl<D: DurableIo> Write for SectorSlice<D> {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        if !self.writable || self.failed {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "read-only or failed device",
            ));
        }
        if self
            .cursor
            .checked_add(input.len() as u64)
            .is_none_or(|end| end > self.length)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "write outside partition",
            ));
        }
        let result = (|| {
            let mut done = 0;
            let mut aligned_scratch = AlignedBuffer::new(self.sector)?;
            let scratch = aligned_scratch.bytes();
            while done < input.len() {
                let at = self.cursor + done as u64;
                let sector_start = at / self.sector as u64 * self.sector as u64;
                let within = (at - sector_start) as usize;
                if within == 0 && input.len() - done >= self.sector {
                    let n =
                        ((input.len() - done).min(self.transfer_limit) / self.sector) * self.sector;
                    self.checked_write(self.base + sector_start, &input[done..done + n])?;
                    done += n;
                    continue;
                }
                let n = (input.len() - done).min(self.sector - within);
                if within != 0 || n != self.sector {
                    self.checked_read(self.base + sector_start, scratch, true)?;
                }
                scratch[within..within + n].copy_from_slice(&input[done..done + n]);
                self.checked_write(self.base + sector_start, scratch)?;
                done += n;
            }
            Ok(input.len())
        })();
        if result.is_err() {
            self.failed = true;
        } else {
            self.cursor += input.len() as u64;
        }
        result
    }
    fn flush(&mut self) -> io::Result<()> {
        if self.failed {
            return Err(io::Error::other("failed device; flush refused"));
        }
        if !self.writable {
            return Ok(());
        }
        let result = self.device.sync_all();
        if let Err(error) = &result {
            eprintln!("SECTOR_DIAGNOSTIC sync: error={error}");
        }
        if result.is_err() {
            self.failed = true;
        }
        result
    }
}
impl<D> Seek for SectorSlice<D> {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        let next = match position {
            SeekFrom::Start(n) => i128::from(n),
            SeekFrom::End(n) => i128::from(self.length) + i128::from(n),
            SeekFrom::Current(n) => i128::from(self.cursor) + i128::from(n),
        };
        if next < 0 || next > i128::from(self.length) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "seek outside partition",
            ));
        }
        self.cursor = next as u64;
        Ok(self.cursor)
    }
}
impl<D: DurableIo + Send> fstool::block::BlockDevice for SectorSlice<D> {
    fn block_size(&self) -> u32 {
        self.sector as u32
    }
    fn total_size(&self) -> u64 {
        self.length
    }
    fn sync(&mut self) -> fstool::Result<()> {
        Ok(self.flush()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    struct TransferDevice {
        bytes: Cursor<Vec<u8>>,
        limit: usize,
        reads: Vec<usize>,
        writes: Vec<usize>,
        fail_second: Option<bool>,
        syncs: usize,
    }
    impl Read for TransferDevice {
        fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
            assert!(b.len() <= self.limit);
            assert_eq!(b.as_ptr() as usize % 4096, 0);
            self.reads.push(b.len());
            self.bytes.read(b)
        }
    }
    impl Write for TransferDevice {
        fn write(&mut self, b: &[u8]) -> io::Result<usize> {
            assert!(b.len() <= self.limit);
            assert_eq!(b.as_ptr() as usize % 4096, 0);
            self.writes.push(b.len());
            if self.writes.len() == 2
                && let Some(short) = self.fail_second
            {
                self.bytes.write_all(&b[..512])?;
                return if short {
                    Ok(512)
                } else {
                    Err(io::Error::other("uncertain second transfer"))
                };
            }
            self.bytes.write(b)
        }
        fn flush(&mut self) -> io::Result<()> {
            panic!("device sync_all is required")
        }
    }
    impl Seek for TransferDevice {
        fn seek(&mut self, p: SeekFrom) -> io::Result<u64> {
            self.bytes.seek(p)
        }
    }
    impl DurableIo for TransferDevice {
        fn sync_all(&mut self) -> io::Result<()> {
            self.syncs += 1;
            Ok(())
        }
    }
    #[test]
    fn adapter_bounded_transfers_preserve_payload_neighbors_and_flush() {
        for sector in [512, 4096] {
            for limit in [sector, 65536] {
                let size = 256 * 1024;
                let initial = vec![0xa5; size + 2 * sector];
                let mut expected = initial.clone();
                let payload: Vec<_> = (0..131101).map(|i| (i % 251) as u8).collect();
                expected[sector + 13..sector + 13 + payload.len()].copy_from_slice(&payload);
                let mut slice = SectorSlice::new(
                    TransferDevice {
                        bytes: Cursor::new(initial),
                        limit,
                        reads: vec![],
                        writes: vec![],
                        fail_second: None,
                        syncs: 0,
                    },
                    (size + 2 * sector) as u64,
                    sector as u64,
                    size as u64,
                    sector,
                    true,
                )
                .unwrap()
                .with_transfer_limit(limit)
                .unwrap();
                slice.seek(SeekFrom::Start(13)).unwrap();
                slice.write_all(&payload).unwrap();
                slice.flush().unwrap();
                slice.seek(SeekFrom::Start(13)).unwrap();
                let mut actual = vec![0; payload.len()];
                slice.read_exact(&mut actual).unwrap();
                assert_eq!(actual, payload);
                assert_eq!(slice.device.bytes.get_ref(), &expected);
                assert_eq!(slice.device.syncs, 1);
                assert!(slice.device.writes.len() > 2);
            }
        }
        for limit in [0, 511, 513, 1024 * 1024 + 512] {
            assert!(
                SectorSlice::new(Cursor::new(vec![0; 1024]), 1024, 0, 1024, 512, true)
                    .unwrap()
                    .with_transfer_limit(limit)
                    .is_err()
            );
        }
    }
    #[test]
    fn second_transfer_error_or_short_write_is_not_retried_or_flushed() {
        for short in [false, true] {
            let mut slice = SectorSlice::new(
                TransferDevice {
                    bytes: Cursor::new(vec![0; 131072]),
                    limit: 65536,
                    reads: vec![],
                    writes: vec![],
                    fail_second: Some(short),
                    syncs: 0,
                },
                131072,
                0,
                131072,
                512,
                true,
            )
            .unwrap()
            .with_transfer_limit(65536)
            .unwrap();
            assert!(slice.write_all(&vec![0x73; 102400]).is_err());
            assert_eq!(slice.device.writes, [65536, 36864]);
            assert!(
                slice.device.bytes.get_ref()[..65536 + 512]
                    .iter()
                    .all(|b| *b == 0x73)
            );
            assert!(
                slice.device.bytes.get_ref()[65536 + 512..]
                    .iter()
                    .all(|b| *b == 0)
            );
            assert!(slice.write(&[0; 512]).is_err());
            assert!(slice.read(&mut [0; 512]).is_err());
            assert!(slice.flush().is_err());
            assert_eq!(slice.device.writes.len(), 2);
            assert!(slice.device.reads.is_empty());
            assert_eq!(slice.device.syncs, 0);
        }
    }
    #[test]
    fn multi_megabyte_reads_and_writes_stay_within_the_slice() {
        for sector in [512, 4096] {
            let size = 3 * 1024 * 1024;
            let initial = vec![0xa5; size + 2 * sector];
            let mut slice = SectorSlice::new(
                Cursor::new(initial),
                (size + 2 * sector) as u64,
                sector as u64,
                size as u64,
                sector,
                true,
            )
            .unwrap();
            let payload: Vec<_> = (0..size - 19).map(|i| (i % 251) as u8).collect();
            slice.seek(SeekFrom::Start(9)).unwrap();
            slice.write_all(&payload).unwrap();
            slice.flush().unwrap();
            slice.seek(SeekFrom::Start(9)).unwrap();
            let mut actual = vec![0; payload.len()];
            slice.read_exact(&mut actual).unwrap();
            assert_eq!(actual, payload);
            assert!(
                slice.device.get_ref()[..sector + 9]
                    .iter()
                    .all(|b| *b == 0xa5)
            );
            assert!(
                slice.device.get_ref()[sector + size - 10..]
                    .iter()
                    .all(|b| *b == 0xa5)
            );
        }
    }
    #[test]
    fn read_faults_preserve_os_errors_and_never_retry_or_write() {
        struct Fault {
            mode: u8,
            seeks: usize,
            reads: usize,
            writes: usize,
            syncs: usize,
        }
        impl Seek for Fault {
            fn seek(&mut self, _: SeekFrom) -> io::Result<u64> {
                self.seeks += 1;
                if self.mode == 0 {
                    Err(io::Error::from_raw_os_error(23))
                } else {
                    Ok(0)
                }
            }
        }
        impl Read for Fault {
            fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
                self.reads += 1;
                if self.mode == 1 {
                    Err(io::Error::from_raw_os_error(23))
                } else {
                    b[0] = 0x39;
                    Ok(1)
                }
            }
        }
        impl Write for Fault {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                self.writes += 1;
                panic!("must stop before any write after a failed read")
            }
            fn flush(&mut self) -> io::Result<()> {
                panic!("use durable sync")
            }
        }
        impl DurableIo for Fault {
            fn sync_all(&mut self) -> io::Result<()> {
                self.syncs += 1;
                panic!("must not flush after a failed read")
            }
        }
        for path in 0..3 {
            for mode in 0..3 {
                let device = Fault {
                    mode,
                    seeks: 0,
                    reads: 0,
                    writes: 0,
                    syncs: 0,
                };
                let mut slice = SectorSlice::new(device, 8192, 512, 4096, 512, true).unwrap();
                if path != 0 {
                    slice.seek(SeekFrom::Start(13)).unwrap();
                }
                let mut output = [0x55; 4096];
                let error = match path {
                    0 => slice.read(&mut output),
                    1 => slice.read(&mut output[..19]),
                    _ => slice.write(&[0x73; 19]),
                }
                .unwrap_err();
                if mode == 2 {
                    assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
                } else {
                    assert_eq!(error.raw_os_error(), Some(23));
                }
                assert!(output.iter().all(|b| *b == 0x55));
                assert!(slice.read(&mut [0; 512]).is_err());
                assert!(slice.write(&[0; 512]).is_err());
                assert!(slice.flush().is_err());
                assert_eq!(slice.device.seeks, 1);
                assert_eq!(slice.device.reads, usize::from(mode != 0));
                assert_eq!((slice.device.writes, slice.device.syncs), (0, 0));
            }
        }
    }
    #[test]
    fn failed_reads_and_syncs_prevent_any_later_io() {
        struct Fault {
            bytes: Cursor<Vec<u8>>,
            short: bool,
            reads: usize,
            writes: usize,
            syncs: usize,
        }
        impl Read for Fault {
            fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
                self.reads += 1;
                let n = if self.short { b.len() / 2 } else { b.len() };
                self.bytes.read(&mut b[..n])
            }
        }
        impl Seek for Fault {
            fn seek(&mut self, p: SeekFrom) -> io::Result<u64> {
                self.bytes.seek(p)
            }
        }
        impl Write for Fault {
            fn write(&mut self, b: &[u8]) -> io::Result<usize> {
                self.writes += 1;
                self.bytes.write(b)
            }
            fn flush(&mut self) -> io::Result<()> {
                panic!("use durable sync")
            }
        }
        impl DurableIo for Fault {
            fn sync_all(&mut self) -> io::Result<()> {
                self.syncs += 1;
                Err(io::Error::other("sync failure"))
            }
        }
        for short in [false, true] {
            let mut slice = SectorSlice::new(
                Fault {
                    bytes: Cursor::new(vec![0; 1536]),
                    short,
                    reads: 0,
                    writes: 0,
                    syncs: 0,
                },
                1536,
                512,
                512,
                512,
                true,
            )
            .unwrap();
            if short {
                assert!(slice.read(&mut [0; 512]).is_err());
            } else {
                slice.write_all(&[9; 512]).unwrap();
                assert!(slice.flush().is_err());
            }
            let before = (slice.device.reads, slice.device.writes, slice.device.syncs);
            assert!(slice.write(&[2]).is_err());
            assert!(slice.flush().is_err());
            assert!(slice.read(&mut [0; 1]).is_err());
            assert_eq!(
                before,
                (slice.device.reads, slice.device.writes, slice.device.syncs)
            );
        }
    }
    struct AlignmentRequired(Cursor<Vec<u8>>);
    impl Read for AlignmentRequired {
        fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
            if !(bytes.as_ptr() as usize).is_multiple_of(4096) || !bytes.len().is_multiple_of(512) {
                return Err(io::Error::from_raw_os_error(87));
            }
            self.0.read(bytes)
        }
    }
    impl Write for AlignmentRequired {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if !(bytes.as_ptr() as usize).is_multiple_of(4096) || !bytes.len().is_multiple_of(512) {
                return Err(io::Error::from_raw_os_error(87));
            }
            self.0.write(bytes)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    impl Seek for AlignmentRequired {
        fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
            self.0.seek(position)
        }
    }
    impl DurableIo for AlignmentRequired {
        fn sync_all(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    #[test]
    fn caller_alignment_does_not_reach_raw_device_buffers() {
        for sector in [512, 4096] {
            let device = AlignmentRequired(Cursor::new(vec![0x35; 2 * 1024 * 1024]));
            let mut slice =
                SectorSlice::new(device, 2 * 1024 * 1024, 0, 2 * 1024 * 1024, sector, true)
                    .unwrap();
            let storage = vec![0x7a; 1024 * 1024 + 37];
            let input = &storage[1..];
            slice.seek(SeekFrom::Start(13)).unwrap();
            slice.write_all(input).unwrap();
            slice.flush().unwrap();
            let mut output = vec![0; input.len() + 29];
            slice.seek(SeekFrom::Start(0)).unwrap();
            slice.read_exact(&mut output).unwrap();
            assert_eq!(&output[..13], &[0x35; 13]);
            assert_eq!(&output[13..13 + input.len()], input);
            assert!(output[13 + input.len()..].iter().all(|b| *b == 0x35));
        }
    }
    impl DurableIo for Cursor<Vec<u8>> {
        fn sync_all(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    #[test]
    fn sub_sector_edits_preserve_neighbor_bytes_and_partition_boundaries() {
        for sector in [512, 4096] {
            let initial = (0..sector * 5).map(|n| (n % 251) as u8).collect::<Vec<_>>();
            let mut slice = SectorSlice::new(
                Cursor::new(initial.clone()),
                initial.len() as u64,
                sector as u64,
                (sector * 3) as u64,
                sector,
                true,
            )
            .unwrap();
            slice.seek(SeekFrom::Start((sector - 3) as u64)).unwrap();
            slice.write_all(&[17; 9]).unwrap();
            slice.flush().unwrap();
            let mut expected = initial;
            expected[sector * 2 - 3..sector * 2 + 6].fill(17);
            assert_eq!(slice.device.get_ref(), &expected);
            slice.seek(SeekFrom::Start((sector - 3) as u64)).unwrap();
            let mut out = [0; 9];
            slice.read_exact(&mut out).unwrap();
            assert_eq!(out, [17; 9]);
            let before = slice.device.get_ref().clone();
            slice.seek(SeekFrom::End(-1)).unwrap();
            assert!(slice.write(&[0; 2]).is_err());
            assert_eq!(slice.device.get_ref(), &before);
            assert!(slice.seek(SeekFrom::End(1)).is_err());
            assert!(slice.seek(SeekFrom::Current(i64::MIN)).is_err());
        }
    }
    struct Short {
        bytes: Cursor<Vec<u8>>,
        writes: usize,
    }
    impl Read for Short {
        fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
            self.bytes.read(b)
        }
    }
    impl Seek for Short {
        fn seek(&mut self, p: SeekFrom) -> io::Result<u64> {
            self.bytes.seek(p)
        }
    }
    impl Write for Short {
        fn write(&mut self, b: &[u8]) -> io::Result<usize> {
            self.writes += 1;
            self.bytes.write(&b[..b.len() / 2])
        }
        fn flush(&mut self) -> io::Result<()> {
            panic!("failed write retried via flush")
        }
    }
    impl DurableIo for Short {
        fn sync_all(&mut self) -> io::Result<()> {
            panic!("failed write retried via sync")
        }
    }
    #[test]
    fn read_failure_after_a_written_sector_poisoned_the_remaining_operation() {
        struct FailRead {
            bytes: Cursor<Vec<u8>>,
            reads: usize,
            writes: usize,
        }
        impl Read for FailRead {
            fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
                self.reads += 1;
                if self.reads == 2 {
                    Err(io::Error::other("read fault"))
                } else {
                    self.bytes.read(b)
                }
            }
        }
        impl Seek for FailRead {
            fn seek(&mut self, p: SeekFrom) -> io::Result<u64> {
                self.bytes.seek(p)
            }
        }
        impl Write for FailRead {
            fn write(&mut self, b: &[u8]) -> io::Result<usize> {
                self.writes += 1;
                self.bytes.write(b)
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        impl DurableIo for FailRead {
            fn sync_all(&mut self) -> io::Result<()> {
                panic!("partial mutation retried via sync")
            }
        }
        let mut slice = SectorSlice::new(
            FailRead {
                bytes: Cursor::new(vec![0; 2048]),
                reads: 0,
                writes: 0,
            },
            2048,
            512,
            1024,
            512,
            true,
        )
        .unwrap();
        slice.seek(SeekFrom::Start(510)).unwrap();
        assert!(slice.write(&[1; 8]).is_err());
        assert_eq!(slice.device.writes, 1);
        assert!(slice.write(&[2; 8]).is_err());
        assert!(slice.flush().is_err());
        assert_eq!(slice.device.writes, 1);
    }
    #[test]
    fn readonly_and_short_device_writes_never_retry() {
        let mut slice = SectorSlice::new(
            Short {
                bytes: Cursor::new(vec![0; 1536]),
                writes: 0,
            },
            1536,
            512,
            512,
            512,
            true,
        )
        .unwrap();
        assert!(slice.write(&[1; 4]).is_err());
        assert_eq!(slice.device.writes, 1);
        assert!(slice.write(&[1; 4]).is_err());
        assert!(slice.flush().is_err());
        assert_eq!(slice.device.writes, 1);
        let mut readonly =
            SectorSlice::new(Cursor::new(vec![0; 1024]), 1024, 0, 1024, 512, false).unwrap();
        assert!(readonly.write(&[1]).is_err());
        readonly.flush().unwrap();
        assert!(readonly.device.get_ref().iter().all(|n| *n == 0));
        assert!(SectorSlice::new(Cursor::new(vec![0; 1024]), 1024, 1, 512, 512, true).is_err());
    }
}
