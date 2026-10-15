//! Attribute publication fault model copied from the independent deferred-delete
//! sector simulator. Honest sync and atomic 512-byte sectors only.
use fstool::{
    block::{BlockDevice, MemoryBackend},
    fs::hfs_plus::{FormatOpts, HfsPlus},
};
use hfs_bridge::{engine, volume, windows::Adapter};
use std::{
    io::{self, Cursor, Read, Seek, SeekFrom, Write},
    sync::{Arc, Mutex},
};
#[path = "support/attribute_wire.rs"]
mod wire;
const POLICIES: [&str; 6] = [
    "lost-cache",
    "all-cache",
    "last-write",
    "first-sector",
    "last-sector",
    "header-first",
];
struct State {
    visible: Cursor<Vec<u8>>,
    durable: Vec<u8>,
    pending: Vec<(usize, usize)>,
    calls: usize,
    fail: Option<usize>,
    dead: bool,
}
#[derive(Clone)]
struct Disk(Arc<Mutex<State>>);
impl Disk {
    fn new(bytes: &[u8]) -> Self {
        Self(Arc::new(Mutex::new(State {
            visible: Cursor::new(bytes.to_vec()),
            durable: bytes.to_vec(),
            pending: Vec::new(),
            calls: 0,
            fail: None,
            dead: false,
        })))
    }
    fn arm(&self, fail: Option<usize>) {
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
    fn snapshot(&self, policy: usize, journal: usize) -> Vec<u8> {
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
fn journal_offset(bytes: &[u8]) -> usize {
    let info = volume::be32(bytes, 1036) as usize * volume::be32(bytes, 1064) as usize;
    volume::be64(bytes, info + 36) as usize
}

const PATH: &str = "/file";
const NAME: &str = "com.example.edited";
const OLD: &[u8] = b"old attribute\0\xff";
const NEW: &[u8] = b"replacement attribute\0\x80\xff";
fn finder_value() -> [u8; 32] {
    let mut bytes = [0; 32];
    bytes[..8].copy_from_slice(b"TEXTttxt");
    bytes[26] = 17;
    bytes
}
fn fixture(little: bool, wrap: bool, sensitive: bool, initial: bool) -> Vec<u8> {
    let mut disk = MemoryBackend::new(8 * 1024 * 1024);
    let mut fs = HfsPlus::format(
        &mut disk,
        &FormatOpts {
            journaled: true,
            ..Default::default()
        },
    )
    .unwrap();
    for (path, payload) in [
        (PATH, &b"unchanged main payload"[..]),
        ("/survivor", &b"survivor payload"[..]),
    ] {
        fs.create_file(
            &mut disk,
            path,
            &mut &payload[..],
            payload.len() as u64,
            0o640,
            501,
            20,
            1_700_000_000,
        )
        .unwrap();
    }
    {
        let mut resource = fs
            .open_resource_fork_rw(&mut disk, std::path::Path::new(PATH))
            .unwrap();
        resource
            .write_all(b"unchanged resource payload\0\xff")
            .unwrap();
        resource.sync().unwrap();
    }
    fs.flush(&mut disk).unwrap();
    let cnid = volume::be32(&fs.catalog_record(PATH).unwrap(), 8);
    let survivor = volume::be32(&fs.catalog_record("/survivor").unwrap(), 8);
    drop(fs);
    let mut bytes = disk.into_bytes();
    if !initial {
        wire::install(
            &mut bytes,
            vec![
                wire::record(cnid, NAME, OLD),
                wire::record(survivor, "com.example.survivor", b"unchanged attr"),
            ],
            16,
            2,
            false,
        );
        let cat = volume::be32(&bytes, 1312) as usize * 4096;
        let size = wire::u16be(&bytes, cat + 32) as usize;
        let mut leaf = volume::be32(&bytes, cat + 24);
        while leaf != 0 {
            let node = cat + leaf as usize * size;
            for i in 0..wire::u16be(&bytes, node + 10) as usize {
                let key = node + wire::u16be(&bytes, node + size - 2 * (i + 1)) as usize;
                let body = key + 2 + wire::u16be(&bytes, key) as usize;
                if wire::u16be(&bytes, body) == 2
                    && [cnid, survivor].contains(&volume::be32(&bytes, body + 8))
                {
                    bytes[body + 3] |= 4;
                }
            }
            leaf = volume::be32(&bytes, node);
        }
    }
    if sensitive {
        bytes[1024..1026].copy_from_slice(b"HX");
        wire::p16(&mut bytes, 1026, 5);
        let cat = volume::be32(&bytes, 1312) as usize * 4096;
        bytes[cat + 51] = 0xbc;
    }
    let alt = bytes.len() - 1024;
    let header = bytes[1024..1536].to_vec();
    bytes[alt..alt + 512].copy_from_slice(&header);
    let j = journal_offset(&bytes);
    let size = volume::be64(&bytes, j + 24);
    let cursor = if wrap { size - 512 } else { 512 };
    if little {
        for (offset, width) in [
            (0, 4),
            (4, 4),
            (8, 8),
            (16, 8),
            (24, 8),
            (32, 4),
            (36, 4),
            (40, 4),
            (44, 4),
        ] {
            bytes[j + offset..j + offset + width].reverse();
        }
    }
    for offset in [8, 16] {
        bytes[j + offset..j + offset + 8].copy_from_slice(&if little {
            cursor.to_le_bytes()
        } else {
            cursor.to_be_bytes()
        });
    }
    bytes[j + 36..j + 40].fill(0);
    let checksum = volume::journal_checksum(&bytes[j..j + 44]);
    bytes[j + 36..j + 40].copy_from_slice(&if little {
        checksum.to_le_bytes()
    } else {
        checksum.to_be_bytes()
    });
    bytes
}
fn attempt(input: &[u8], operation: usize, stop: Option<usize>) -> (bool, Disk) {
    let mut disk = Disk::new(input);
    let mut fs = engine::open_checked(&mut disk).unwrap();
    let cnid = volume::be32(&fs.catalog_record(PATH).unwrap(), 8);
    disk.arm(stop);
    if operation == 3 {
        fs.set_inline_attributes(
            &mut disk,
            cnid,
            &[
                (NAME, Some(NEW)),
                ("com.example.CASE", Some(b"UPPER")),
                ("com.example.case", Some(b"lower")),
                ("com.apple.FinderInfo", Some(&finder_value())),
            ],
        )
        .unwrap();
    } else {
        fs.set_inline_attribute(
            &mut disk,
            cnid,
            NAME,
            if operation == 2 { None } else { Some(NEW) },
        )
        .unwrap();
    }
    let success = fs.flush(&mut disk).is_ok();
    if !success {
        let calls = disk.0.lock().unwrap().calls;
        assert!(fs.flush(&mut disk).is_err(), "failed writer retried");
        assert_eq!(disk.0.lock().unwrap().calls, calls);
    }
    drop(fs);
    (success, disk)
}
fn verify(
    disk: &mut Disk,
    before: &engine::FileSnapshot,
    survivor: &engine::FileSnapshot,
    operation: usize,
    original_free: u32,
) {
    // Explicit test-only replay; production still refuses pending journals.
    let fs = HfsPlus::open(disk).unwrap();
    let body = fs.catalog_record(PATH).unwrap();
    let cnid = volume::be32(&body, 8);
    let value = fs.inline_attribute(disk, cnid, NAME).unwrap();
    let old = if operation == 0 {
        None
    } else {
        Some(OLD.to_vec())
    };
    let new = if operation == 2 {
        None
    } else {
        Some(NEW.to_vec())
    };
    let batch_new = operation == 3 && value == Some(NEW.to_vec());
    assert_eq!(
        &body[48..80],
        if batch_new { finder_value() } else { [0; 32] }.as_slice(),
        "FinderInfo and attribute batch partially published"
    );
    for (name, data) in [
        ("com.example.CASE", &b"UPPER"[..]),
        ("com.example.case", &b"lower"[..]),
    ] {
        assert_eq!(
            fs.inline_attribute(disk, cnid, name).unwrap(),
            if batch_new { Some(data.to_vec()) } else { None },
            "attribute batch partially published"
        );
    }
    assert!(
        value == old || value == new,
        "attribute is neither complete old nor complete new value"
    );
    assert_eq!(
        volume::be16(&body, 2) & 4,
        if value.is_some() { 4 } else { 0 },
        "catalog flag and tree publication disagree"
    );
    let mut actual = engine::snapshot_device(disk, PATH, &[]).unwrap();
    // Only the HasAttributes bit may differ from the baseline catalog body.
    let mut expected_body = body.clone();
    expected_body[48..80].fill(0);
    expected_body[2..4].copy_from_slice(
        &((volume::be16(&body, 2) & !4)
            | if before.attributes[0].1.is_some() {
                4
            } else {
                0
            })
        .to_be_bytes(),
    );
    actual.catalog_sha256 = engine::sha256(&mut &expected_body[..]).unwrap();
    actual.attributes = before.attributes.clone();
    assert_eq!(
        &actual, before,
        "fork payload or ownership/metadata changed"
    );
    assert_eq!(
        &engine::snapshot_device(disk, "/survivor", &["com.example.survivor"]).unwrap(),
        survivor
    );
    let fs = HfsPlus::open(disk).unwrap();
    let bytes = disk.0.lock().unwrap().durable.clone();
    let header = volume::be32(&bytes, 1388);
    let initialized = operation == 0 && value.is_some();
    assert_eq!(
        volume::be32(&bytes, 1072),
        original_free - if initialized { 8 } else { 0 },
        "interruption leaked allocation blocks"
    );
    assert_eq!(
        header,
        if operation == 0 {
            if initialized { 8 } else { 0 }
        } else {
            16
        },
        "attributes fork descriptor disagrees with committed tree"
    );
    let allocation = volume::be32(&bytes, 1152) as usize * 4096;
    assert!(
        bytes[allocation + 256..allocation + 512]
            .iter()
            .all(|&byte| byte == 0),
        "small-volume bitmap sector padding changed"
    );
    if header != 0 {
        let raw = if operation == 0 {
            wire::audit_initialized(&bytes)
        } else {
            wire::audit(&bytes)
        };
        let actual_records = raw.iter().filter(|r| volume::be32(r, 4) == cnid).count();
        let expected_records = usize::from(value.is_some()) + if batch_new { 2 } else { 0 };
        assert_eq!(actual_records, expected_records);
        // The entire attributes reservation must be allocated exactly once.
        let bs = volume::be32(&bytes, 1064) as usize;
        let bitmap = volume::be32(&bytes, 1152) as usize * bs;
        let block = volume::be32(&bytes, 1392);
        for index in block..block + header {
            assert_ne!(
                bytes[bitmap + index as usize / 8] & (0x80 >> (index % 8)),
                0
            );
        }
        assert_eq!(
            fs.attribute_names(disk, cnid).unwrap().len(),
            expected_records + usize::from(batch_new)
        );
    } else {
        assert!(value.is_none());
    }
}
fn retain(bytes: &[u8], name: &str) {
    if let Some(path) = std::env::var_os("HFS_ATTRIBUTE_CRASH_ARTIFACT_DIR") {
        std::fs::create_dir_all(&path).unwrap();
        std::fs::write(std::path::PathBuf::from(path).join(name), bytes).unwrap();
    }
}
#[test]
fn attribute_tree_flag_and_first_allocation_survive_commit_and_replay_interruptions() {
    let mut checkpoints = 0;
    let mut replay_checkpoints = 0;
    for sensitive in [false, true] {
        for little in [false, true] {
            for wrap in [false, true] {
                for operation in 0..4 {
                    let base = fixture(little, wrap, sensitive, operation == 0);
                    let j = journal_offset(&base);
                    let original_free = volume::be32(&base, 1072);
                    let mut probe = Disk::new(&base);
                    let before = engine::snapshot_device(&mut probe, PATH, &[NAME]).unwrap();
                    let survivor =
                        engine::snapshot_device(&mut probe, "/survivor", &["com.example.survivor"])
                            .unwrap();
                    let (success, full) = attempt(&base, operation, None);
                    assert!(success);
                    let count = full.0.lock().unwrap().calls;
                    let committed = full.0.lock().unwrap().durable.clone();
                    verify(
                        &mut Disk::new(&committed),
                        &before,
                        &survivor,
                        operation,
                        original_free,
                    );
                    let label = format!("{sensitive}-{little}-{wrap}-{operation}");
                    retain(&committed, &format!("attribute-commit-{label}.img"));
                    let mut pending = None;
                    for stop in 0..count {
                        let (success, interrupted) = attempt(&base, operation, Some(stop));
                        assert!(!success);
                        for policy in 0..POLICIES.len() {
                            let bytes = interrupted.snapshot(policy, j);
                            let mut inspect = Disk::new(&bytes);
                            if matches!(
                                volume::inspect(&mut inspect).unwrap().journal,
                                volume::Journal::Pending { .. }
                            ) {
                                pending.get_or_insert_with(|| bytes.clone());
                                inspect.arm(Some(0));
                                assert!(Adapter::from_device(inspect.clone()).is_err());
                                assert_eq!(inspect.0.lock().unwrap().calls, 0);
                            }
                            verify(
                                &mut Disk::new(&bytes),
                                &before,
                                &survivor,
                                operation,
                                original_free,
                            );
                            checkpoints += 1;
                        }
                    }
                    let pending = pending.expect("pending attribute transaction never observed");
                    let mut replay = Disk::new(&pending);
                    HfsPlus::open(&mut replay).unwrap();
                    let count = replay.0.lock().unwrap().calls;
                    for stop in 0..count {
                        let mut interrupted = Disk::new(&pending);
                        interrupted.arm(Some(stop));
                        assert!(HfsPlus::open(&mut interrupted).is_err());
                        for policy in 0..POLICIES.len() {
                            verify(
                                &mut Disk::new(&interrupted.snapshot(policy, j)),
                                &before,
                                &survivor,
                                operation,
                                original_free,
                            );
                            replay_checkpoints += 1;
                        }
                    }
                }
            }
        }
    }
    println!(
        "ATTRIBUTE_MATRIX: {checkpoints} commit checkpoints + {replay_checkpoints} replay checkpoints passed; 32 scenarios"
    );
}
