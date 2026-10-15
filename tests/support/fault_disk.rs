//! Independent sector persistence simulator shared with fork-attribute tests.
use fstool::block::BlockDevice;
use std::{
    io::{self, Cursor, Read, Seek, SeekFrom, Write},
    sync::{Arc, Mutex},
};
pub(crate) struct State {
    visible: Cursor<Vec<u8>>,
    pub(crate) durable: Vec<u8>,
    pending: Vec<(usize, usize)>,
    pub(crate) calls: usize,
    fail: Option<usize>,
    dead: bool,
}
#[derive(Clone)]
pub(crate) struct Disk(pub(crate) Arc<Mutex<State>>);
impl Disk {
    pub(crate) fn new(bytes: &[u8]) -> Self {
        Self(Arc::new(Mutex::new(State {
            visible: Cursor::new(bytes.to_vec()),
            durable: bytes.to_vec(),
            pending: Vec::new(),
            calls: 0,
            fail: None,
            dead: false,
        })))
    }
    pub(crate) fn arm(&self, fail: Option<usize>) {
        let mut state = self.0.lock().unwrap();
        state.calls = 0;
        state.fail = fail;
        state.dead = false;
        state.pending.clear();
    }
    fn boundary(state: &mut State) -> io::Result<()> {
        if state.dead || state.fail == Some(state.calls) {
            state.dead = true;
            return Err(io::Error::other("simulated power loss"));
        }
        state.calls += 1;
        Ok(())
    }
    pub(crate) fn snapshot(&self, policy: usize, journal: usize) -> Vec<u8> {
        let state = self.0.lock().unwrap();
        let mut bytes = state.durable.clone();
        let range = match policy {
            0 => None,
            1 => return state.visible.get_ref().clone(),
            2 => state.pending.last().copied(),
            3 => state.pending.first().map(|(off, _)| (off / 512 * 512, 512)),
            4 => state
                .pending
                .last()
                .map(|(off, len)| ((off + len - 1) / 512 * 512, 512)),
            5 => state
                .pending
                .iter()
                .rev()
                .find(|(off, _)| *off == journal)
                .copied(),
            _ => unreachable!(),
        };
        if let Some((off, len)) = range {
            bytes[off..off + len].copy_from_slice(&state.visible.get_ref()[off..off + len]);
        }
        bytes
    }
}
impl Read for Disk {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.0.lock().unwrap().visible.read(bytes)
    }
}
impl Seek for Disk {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        self.0.lock().unwrap().visible.seek(position)
    }
}
impl Write for Disk {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let mut state = self.0.lock().unwrap();
        Self::boundary(&mut state)?;
        let off = state.visible.position() as usize;
        if off
            .checked_add(bytes.len())
            .is_none_or(|end| end > state.durable.len())
        {
            return Err(io::Error::other("out of bounds"));
        }
        let count = state.visible.write(bytes)?;
        if count > 0 {
            state.pending.push((off, count));
        }
        Ok(count)
    }
    fn flush(&mut self) -> io::Result<()> {
        let mut state = self.0.lock().unwrap();
        Self::boundary(&mut state)?;
        let bytes = state.visible.get_ref().clone();
        state.durable.copy_from_slice(&bytes);
        state.pending.clear();
        Ok(())
    }
}
impl BlockDevice for Disk {
    fn block_size(&self) -> u32 {
        512
    }
    fn total_size(&self) -> u64 {
        self.0.lock().unwrap().durable.len() as u64
    }
    fn sync(&mut self) -> fstool::Result<()> {
        Ok(self.flush()?)
    }
}
