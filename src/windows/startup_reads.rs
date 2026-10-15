//! Bounded read-ahead used only while opening a read-only filesystem.
//! Sixteen windows retain at most 1 MiB; the source handle denies concurrent writers. Volume headers
//! always bypass the window; the window is dropped before mounting begins.
use fstool::block::BlockDevice;
use std::collections::VecDeque;
use std::io::{self, Read, Seek, SeekFrom, Write};

const WINDOW: usize = 64 * 1024;
const WINDOWS: usize = 16;
pub(super) struct StartupReads<'a, D> {
    inner: &'a mut D,
    position: u64,
    windows: VecDeque<(u64, Vec<u8>)>,
}
impl<'a, D: BlockDevice> StartupReads<'a, D> {
    pub(super) fn new(inner: &'a mut D) -> io::Result<Self> {
        let position = inner.stream_position()?;
        Ok(Self {
            inner,
            position,
            windows: VecDeque::new(),
        })
    }
}
impl<D: BlockDevice> Read for StartupReads<'_, D> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let total = self.inner.total_size();
        let wanted = output
            .len()
            .min(total.saturating_sub(self.position).min(usize::MAX as u64) as usize);
        if wanted == 0 {
            return Ok(0);
        }
        let end = self.position + wanted as u64;
        let header = (self.position < 1536 && end > 1024)
            || (self.position < total.saturating_sub(512) && end > total.saturating_sub(1024));
        if wanted >= WINDOW || header {
            self.inner.seek(SeekFrom::Start(self.position))?;
            let count = self.inner.read(&mut output[..wanted])?;
            self.position += count as u64;
            return Ok(count);
        }
        let hit = self.windows.iter().position(|(start, bytes)| {
            self.position >= *start && self.position < *start + bytes.len() as u64
        });
        if let Some(hit) = hit {
            let window = self.windows.remove(hit).unwrap();
            self.windows.push_back(window);
        } else {
            let start = self.position / WINDOW as u64 * WINDOW as u64;
            let length = (total - start).min(WINDOW as u64) as usize;
            let mut bytes = vec![0; length];
            if let Err(error) = self
                .inner
                .seek(SeekFrom::Start(start))
                .and_then(|_| self.inner.read_exact(&mut bytes))
            {
                // No saved window may conceal an unsuccessful refill.
                self.windows.clear();
                return Err(error);
            }
            if self.windows.len() == WINDOWS {
                self.windows.pop_front();
            }
            self.windows.push_back((start, bytes));
        }
        let (start, bytes) = self.windows.back().unwrap();
        let offset = (self.position - start) as usize;
        let count = wanted.min(bytes.len() - offset);
        output[..count].copy_from_slice(&bytes[offset..offset + count]);
        self.position += count as u64;
        Ok(count)
    }
}
impl<D: BlockDevice> Seek for StartupReads<'_, D> {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        let next = match position {
            SeekFrom::Start(at) => Some(at),
            SeekFrom::Current(delta) => self.position.checked_add_signed(delta),
            SeekFrom::End(delta) => self.inner.total_size().checked_add_signed(delta),
        }
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid startup read seek"))?;
        self.position = next;
        Ok(next)
    }
}
impl<D> Write for StartupReads<'_, D> {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "read-only startup",
        ))
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
impl<D: BlockDevice> BlockDevice for StartupReads<'_, D> {
    fn block_size(&self) -> u32 {
        self.inner.block_size()
    }
    fn total_size(&self) -> u64 {
        self.inner.total_size()
    }
    fn sync(&mut self) -> fstool::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    struct Device {
        bytes: Cursor<Vec<u8>>,
        reads: usize,
        fail: bool,
    }
    impl Device {
        fn new() -> Self {
            Self {
                bytes: Cursor::new((0..3 * WINDOW + 4096).map(|i| (i % 251) as u8).collect()),
                reads: 0,
                fail: false,
            }
        }
    }
    impl Read for Device {
        fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
            self.reads += 1;
            if self.fail {
                return Err(io::Error::other("injected startup read failure"));
            }
            self.bytes.read(out)
        }
    }
    impl Seek for Device {
        fn seek(&mut self, p: SeekFrom) -> io::Result<u64> {
            self.bytes.seek(p)
        }
    }
    impl Write for Device {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            panic!("source write");
        }
        fn flush(&mut self) -> io::Result<()> {
            panic!("source flush");
        }
    }
    impl BlockDevice for Device {
        fn block_size(&self) -> u32 {
            512
        }
        fn total_size(&self) -> u64 {
            self.bytes.get_ref().len() as u64
        }
        fn sync(&mut self) -> fstool::Result<()> {
            panic!("source sync");
        }
    }
    #[test]
    fn coalesces_metadata_reads_and_keeps_exact_cross_window_and_eof_bytes() {
        let mut disk = Device::new();
        let expected = disk.bytes.get_ref().clone();
        let mut cached = StartupReads::new(&mut disk).unwrap();
        for offset in (WINDOW..WINDOW + 8192).step_by(512) {
            let mut data = [0; 512];
            cached.read_at(offset as u64, &mut data).unwrap();
            assert_eq!(&data[..], &expected[offset..offset + 512]);
        }
        assert_eq!(cached.inner.reads, 1);
        let mut crossing = [0; 1024];
        cached
            .read_at((2 * WINDOW - 128) as u64, &mut crossing)
            .unwrap();
        assert_eq!(&crossing[..], &expected[2 * WINDOW - 128..2 * WINDOW + 896]);
        cached.seek(SeekFrom::End(-37)).unwrap();
        let mut tail = [0; 80];
        assert_eq!(cached.read(&mut tail).unwrap(), 37);
        assert_eq!(&tail[..37], &expected[expected.len() - 37..]);
        assert_eq!(cached.read(&mut tail).unwrap(), 0);
        assert!(cached.seek(SeekFrom::Start(0)).is_ok());
        assert!(cached.seek(SeekFrom::Current(-1)).is_err());
        assert!(cached.write_all(b"no").is_err());
        cached.flush().unwrap();
        cached.sync().unwrap();
    }
    #[test]
    fn alternating_tree_pages_reuse_a_bounded_least_recently_used_set() {
        let mut disk = Device::new();
        disk.bytes.get_mut().resize((WINDOWS + 3) * WINDOW, 0x44);
        let expected = disk.bytes.get_ref().clone();
        let mut cached = StartupReads::new(&mut disk).unwrap();
        let mut data = [0; 512];
        for page in (1..=WINDOWS).chain(1..=WINDOWS).chain([1]) {
            let offset = page * WINDOW + 512;
            cached.read_at(offset as u64, &mut data).unwrap();
            assert_eq!(&data[..], &expected[offset..offset + data.len()]);
        }
        assert_eq!(cached.inner.reads, WINDOWS);
        cached
            .read_at(((WINDOWS + 1) * WINDOW) as u64, &mut data)
            .unwrap();
        assert_eq!(cached.windows.len(), WINDOWS);
        let calls = cached.inner.reads;
        cached.read_at(WINDOW as u64, &mut data).unwrap();
        assert_eq!(cached.inner.reads, calls, "recent page retained");
        cached.read_at((2 * WINDOW) as u64, &mut data).unwrap();
        assert_eq!(cached.inner.reads, calls + 1, "oldest page evicted");
    }
    #[test]
    fn headers_bypass_cached_pages_and_failed_refills_do_not_reuse_old_data() {
        let mut disk = Device::new();
        let mut cached = StartupReads::new(&mut disk).unwrap();
        let mut data = [0; 16];
        cached.read_at(4096, &mut data).unwrap();
        cached.inner.bytes.get_mut()[1024..1040].fill(0x5a);
        cached.read_at(1024, &mut data).unwrap();
        assert_eq!(data, [0x5a; 16]);
        let alternate = cached.total_size() - 1024;
        cached.read_at(alternate - 512, &mut data).unwrap();
        cached.inner.bytes.get_mut()[alternate as usize..alternate as usize + 16].fill(0x42);
        cached.read_at(alternate, &mut data).unwrap();
        assert_eq!(data, [0x42; 16]);
        cached.inner.fail = true;
        let calls = cached.inner.reads;
        assert!(cached.read_at(WINDOW as u64, &mut data).is_err());
        assert_eq!(
            cached.inner.reads,
            calls + 1,
            "failed I/O must not be retried"
        );
        assert!(cached.read_at(alternate - 512, &mut data).is_err());
    }
}
