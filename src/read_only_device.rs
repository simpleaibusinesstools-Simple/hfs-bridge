//! A capability boundary for browsing: no write, flush or sync reaches the source.
use fstool::block::BlockDevice;
use std::io::{self, Read, Seek, SeekFrom, Write};

pub struct ReadOnlyDevice<D> {
    inner: D,
}
impl<D> ReadOnlyDevice<D> {
    pub(crate) fn new(inner: D) -> Self {
        Self { inner }
    }
}
impl<D: Read> Read for ReadOnlyDevice<D> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.inner.read(bytes)
    }
}
impl<D: Seek> Seek for ReadOnlyDevice<D> {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        self.inner.seek(position)
    }
}
impl<D> Write for ReadOnlyDevice<D> {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "read-only source",
        ))
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
impl<D: BlockDevice> BlockDevice for ReadOnlyDevice<D> {
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
