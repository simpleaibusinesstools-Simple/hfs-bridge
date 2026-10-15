//! Independent sector-persistence model for the deferred-delete protocol.
//! Honest sync and atomic 512-byte sectors; no physical hardware claims.
use fstool::{
    block::{BlockDevice, MemoryBackend},
    fs::hfs_plus::{
        FormatOpts, HfsPlus, attributes::Attributes, btree::ForkReader,
        volume_header::read_volume_header,
    },
};
use hfs_bridge::{
    engine, volume,
    windows::{Access, Adapter, OpenRequest},
};
use std::{
    io::{self, Cursor, Read, Seek, SeekFrom, Write},
    sync::{Arc, Mutex},
};
#[path = "support/attribute_wire.rs"]
mod attribute_wire;
#[path = "support/catalog_wire.rs"]
mod catalog_wire;

const PATH: &str = "/Folder/victim.txt";
const STORE: &str = "/.hfs-bridge-orphans-v1";
const DATA: &[u8] = b"Deleted data survives until final close.";
const SURVIVOR: &[u8] = b"Unrelated file survives every interrupted deletion.";
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
fn resource_data() -> Vec<u8> {
    (0..8199)
        .map(|i| ((i * 37 + i / 251) & 255) as u8)
        .collect()
}
fn fixture_kind(little: bool, wrap: bool, sensitive: bool, resource: bool) -> Vec<u8> {
    let mut disk = MemoryBackend::new(16 * 1024 * 1024);
    let mut fs = HfsPlus::format(
        &mut disk,
        &FormatOpts {
            journaled: true,
            node_size: 2048,
            catalog_nodes: 4,
            ..Default::default()
        },
    )
    .unwrap();
    if sensitive {
        drop(fs);
        let mut bytes = disk.into_bytes();
        bytes[1024..1026].copy_from_slice(b"HX");
        bytes[1026..1028].copy_from_slice(&5u16.to_be_bytes());
        let catalog = volume::be32(&bytes, 1312) as usize * 4096;
        bytes[catalog + 51] = 0xbc;
        let header = bytes[1024..1536].to_vec();
        let alternate = bytes.len() - 1024;
        bytes[alternate..alternate + 512].copy_from_slice(&header);
        disk = MemoryBackend::from_bytes(bytes);
        fs = HfsPlus::open(&mut disk).unwrap();
    }
    fs.create_dir(&mut disk, "/Folder", 0o755, 0, 0, 0).unwrap();
    for (path, data) in [(PATH, DATA), ("/Folder/survivor.txt", SURVIVOR)] {
        fs.create_file(
            &mut disk,
            path,
            &mut &data[..],
            data.len() as u64,
            0o640,
            501,
            20,
            1_700_000_000,
        )
        .unwrap();
    }
    if resource {
        let mut fork = fs
            .open_resource_fork_rw(&mut disk, std::path::Path::new(PATH))
            .unwrap();
        fork.write_all(&resource_data()).unwrap();
        fork.sync().unwrap();
    }
    fs.flush(&mut disk).unwrap();
    let victim = fs.catalog_record(PATH).unwrap();
    let survivor = fs.catalog_record("/Folder/survivor.txt").unwrap();
    let cnid = volume::be32(&victim, 8);
    drop(fs);
    let mut bytes = disk.into_bytes();
    inject_inline_attribute(&mut bytes, &victim, &survivor, cnid);
    let j = journal_offset(&bytes);
    let size = volume::be64(&bytes, j + 24);
    let cursor = if wrap { size - 512 } else { 512 };
    for (off, width) in [
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
        if little {
            bytes[j + off..j + off + width].reverse();
        }
    }
    for off in [8, 16] {
        bytes[j + off..j + off + 8].copy_from_slice(&if little {
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

fn expected_attributes(victim: u32, survivor: u32, include_victim: bool) -> Vec<Vec<u8>> {
    let mut records = vec![
        attribute_wire::record(survivor, "com.example.CASE", &vec![0x42; 1801]),
        attribute_wire::record(survivor, "com.example.case", &vec![0x63; 1801]),
    ];
    if include_victim {
        records.extend([
            attribute_wire::record(victim, "com.example.hfsbridge", b"ATTR"),
            attribute_wire::record(victim, "com.example.large-a", &vec![0x11; 1801]),
            attribute_wire::record(victim, "com.example.large-b", &vec![0x22; 1801]),
        ]);
    }
    records.sort_by_key(|r| attribute_wire::order(r));
    records
}
fn inject_inline_attribute(bytes: &mut [u8], record: &[u8], survivor: &[u8], cnid: u32) {
    for record in [record, survivor] {
        let body = bytes
            .windows(record.len())
            .position(|chunk| chunk == record)
            .unwrap();
        bytes[body + 3] |= 4;
    }
    let survivor_id = volume::be32(survivor, 8);
    attribute_wire::install(
        bytes,
        expected_attributes(cnid, survivor_id, true),
        16,
        2,
        false,
    );
    attribute_wire::audit(bytes);
}
fn all() -> OpenRequest {
    OpenRequest {
        access: Access::ALL,
        ..Default::default()
    }
}

fn attempt_kind(
    base: &[u8],
    operation: usize,
    stop: Option<usize>,
    resource: bool,
) -> (bool, Disk) {
    let disk = Disk::new(base);
    let outcome;
    if operation == 2 {
        disk.arm(stop);
        outcome = Adapter::from_device(disk.clone()).is_ok();
    } else {
        let mut adapter = Adapter::from_device(disk.clone()).unwrap();
        let path = if resource {
            r"\Folder\victim.txt:AFP_Resource"
        } else {
            r"\Folder\victim.txt"
        };
        let handle = adapter.open(path, all()).unwrap();
        if operation == 1 {
            adapter.cleanup(handle, true).unwrap();
        }
        disk.arm(stop);
        outcome = if operation == 0 {
            adapter.cleanup(handle, true)
        } else {
            adapter.close(handle)
        }
        .is_ok();
        let calls = disk.0.lock().unwrap().calls;
        drop(adapter);
        assert_eq!(
            disk.0.lock().unwrap().calls,
            calls,
            "implicit retry on drop"
        );
    }
    (outcome, disk)
}
fn file(fs: &HfsPlus, disk: &mut Disk, path: &str) -> Vec<u8> {
    let mut data = Vec::new();
    fs.open_file_reader(disk, path)
        .unwrap()
        .read_to_end(&mut data)
        .unwrap();
    data
}
fn public_attributes(bytes: &[u8]) -> Vec<Vec<u8>> {
    use hfs_bridge::timestamps::{
        GENERATION_ATTRIBUTE, Generation, PrecisionRecord, TIMES_ATTRIBUTE, VolumeState,
    };
    let catalog = catalog_wire::fork(bytes);
    let size = attribute_wire::u16be(&catalog, 32) as usize;
    let mut identities = std::collections::BTreeMap::new();
    for node in catalog.chunks_exact(size).filter(|n| n[8] == 0xff) {
        for record in catalog_wire::records(node) {
            let body = &record[2 + attribute_wire::u16be(record, 0) as usize..];
            if matches!(attribute_wire::u16be(body, 0), 1 | 2) {
                assert!(identities.insert(volume::be32(body, 8), body).is_none());
            }
        }
    }
    let current = VolumeState {
        id: bytes[1128..1136].try_into().unwrap(),
        created: volume::be32(bytes, 1040),
        write_count: volume::be32(bytes, 1092),
    };
    let mut public = Vec::new();
    let mut generation = None;
    let mut epochs = Vec::new();
    for record in attribute_wire::audit(bytes) {
        let length = attribute_wire::u16be(&record, 12) as usize;
        let name = String::from_utf16(
            &record[14..14 + length * 2]
                .as_chunks::<2>()
                .0
                .iter()
                .map(|v| u16::from_be_bytes(*v))
                .collect::<Vec<_>>(),
        )
        .unwrap();
        if name != GENERATION_ATTRIBUTE && name != TIMES_ATTRIBUTE {
            public.push(record);
            continue;
        }
        let cnid = volume::be32(&record, 4);
        let body = &record[2 + attribute_wire::u16be(&record, 0) as usize..];
        assert_eq!(volume::be32(body, 0), 0x10);
        assert_eq!(&body[4..12], &[0; 8]);
        let value = &body[16..16 + volume::be32(body, 12) as usize];
        if name == GENERATION_ATTRIBUTE {
            assert_eq!(cnid, 2);
            assert!(Generation::decode(value).unwrap().matches(current));
            assert!(generation.replace(value[24..40].to_vec()).is_none());
        } else {
            assert!(PrecisionRecord::decode(value).is_some());
            assert_eq!(volume::be32(value, 20), cnid);
            assert_eq!(&value[8..16], &current.id);
            assert_eq!(volume::be32(value, 16), current.created);
            let catalog_body = identities
                .get(&cnid)
                .expect("precision on deleted identity");
            assert_eq!(value[40] as u16, attribute_wire::u16be(catalog_body, 0));
            for (i, offset) in [12, 24, 16, 20].into_iter().enumerate() {
                assert_eq!(
                    volume::be32(value, 48 + i * 4),
                    volume::be32(catalog_body, offset)
                );
            }
            epochs.push(value[24..40].to_vec());
        }
    }
    for epoch in epochs {
        assert_eq!(Some(epoch), generation);
    }
    public
}
fn verify(disk: &mut Disk, operation: usize, survivor: &[u8], cnid: u32) {
    // Explicit test-only journal replay. Production Adapter::from_device still
    // rejects a pending journal before it can issue recovery writes.
    let fs = HfsPlus::open(disk).unwrap();
    volume::require_engine_access(&volume::inspect(disk).unwrap()).unwrap();
    let source_exists = fs.catalog_record(PATH).is_ok();
    let store_exists = fs.catalog_record(STORE).is_ok();
    let vh = read_volume_header(disk).unwrap();
    let attrs = Attributes::open(
        disk,
        ForkReader::from_inline(&vh.attributes_file, vh.block_size, "replayed attributes").unwrap(),
        true,
    )
    .unwrap();
    assert_eq!(
        attrs
            .lookup(disk, cnid, "com.example.hfsbridge")
            .unwrap()
            .is_some(),
        source_exists || store_exists
    );
    if source_exists {
        assert_eq!(operation, 0);
        assert!(!store_exists, "partial original-name/store publication");
        assert_eq!(file(&fs, disk, PATH), DATA);
    }
    assert_eq!(fs.catalog_record("/Folder/survivor.txt").unwrap(), survivor);
    let survivor_id = volume::be32(survivor, 8);
    assert_eq!(
        public_attributes(&disk.0.lock().unwrap().durable),
        expected_attributes(cnid, survivor_id, source_exists || store_exists)
    );
    assert_eq!(file(&fs, disk, "/Folder/survivor.txt"), SURVIVOR);
    let audit = catalog_wire::audit(&disk.0.lock().unwrap().durable);
    assert!(audit.depth > 0 && audit.total > audit.free && audit.leaves > 0);
    let adapter = Adapter::from_device(disk.clone()).unwrap();
    let mut after = adapter.shutdown().unwrap();
    let fs = engine::open_checked(&mut after).unwrap();
    assert_eq!(fs.catalog_record(PATH).is_ok(), source_exists);
    assert!(fs.catalog_record(STORE).is_err());
    let vh = read_volume_header(&mut after).unwrap();
    let attrs = Attributes::open(
        &mut after,
        ForkReader::from_inline(&vh.attributes_file, vh.block_size, "recovered attributes")
            .unwrap(),
        true,
    )
    .unwrap();
    assert_eq!(
        attrs
            .lookup(&mut after, cnid, "com.example.hfsbridge")
            .unwrap()
            .is_some(),
        source_exists
    );
    let inspection = volume::inspect(&mut after).unwrap();
    // The journal and journal-info files are counted as regular files too.
    assert_eq!(inspection.header.files, if source_exists { 4 } else { 3 });
    assert_eq!(inspection.header.folders, 1);
    assert_eq!(file(&fs, &mut after, "/Folder/survivor.txt"), SURVIVOR);
    catalog_wire::audit(&after.0.lock().unwrap().durable);
    assert_eq!(
        public_attributes(&after.0.lock().unwrap().durable),
        expected_attributes(cnid, survivor_id, source_exists)
    );
}
fn retain(bytes: &[u8], name: &str) {
    if let Some(directory) = std::env::var_os("HFS_DEFERRED_ARTIFACT_DIR")
        .or_else(|| std::env::var_os("HFS_CRASH_ARTIFACT_DIR"))
    {
        let mut file =
            hfs_bridge::image::create_output(&std::path::Path::new(&directory).join(name)).unwrap();
        file.write_all(bytes).unwrap();
        file.sync_all().unwrap();
    }
}

fn fork_bitmap(bytes: &[u8], record: &[u8], offset: usize, allocated: bool) {
    let block_size = volume::be32(bytes, 1064) as usize;
    let bitmap_start = volume::be32(bytes, 1152) as usize * block_size;
    let mut blocks = 0;
    for extent in record[offset + 16..offset + 80].as_chunks::<8>().0 {
        let start = volume::be32(extent, 0);
        let count = volume::be32(extent, 4);
        for block in start..start + count {
            assert_eq!(
                bytes[bitmap_start + block as usize / 8] & (0x80 >> (block & 7)) != 0,
                allocated
            );
        }
        blocks += count;
    }
    assert_eq!(blocks, volume::be32(record, offset + 12));
}
fn verify_resource(disk: &mut Disk, operation: usize, survivor: &[u8], original: &[u8]) {
    let fs = HfsPlus::open(disk).unwrap(); // explicit test-only replay
    volume::require_engine_access(&volume::inspect(disk).unwrap()).unwrap();
    let current = fs.catalog_record(PATH).unwrap();
    assert_eq!(&current[..16], &original[..16]);
    assert_eq!(&current[24..168], &original[24..168]);
    assert_eq!(file(&fs, disk, PATH), DATA);
    let resource = fs.resource_fork_size(disk, PATH).unwrap().unwrap_or(0) != 0;
    let store = fs.catalog_record(STORE).is_ok();
    if resource {
        assert_eq!(operation, 0);
        assert!(!store, "partial source-resource/store publication");
        let mut observed = Vec::new();
        fs.open_resource_fork_reader(disk, PATH)
            .unwrap()
            .read_to_end(&mut observed)
            .unwrap();
        assert_eq!(observed, resource_data());
        assert_eq!(&current[168..248], &original[168..248]);
    } else {
        assert_eq!(volume::be32(&current, 180), 0);
        assert!(current[184..248].iter().all(|b| *b == 0));
        if store {
            let children = fs.list_path(disk, STORE).unwrap();
            assert_eq!(children.len(), 2);
            let orphan = children.iter().find(|e| e.name != "owner").unwrap();
            assert_eq!(orphan.name, format!("{:08X}", orphan.inode));
            assert_eq!(
                file(&fs, disk, &format!("{STORE}/{}", orphan.name)),
                resource_data()
            );
        }
    }
    assert_eq!(fs.catalog_record("/Folder/survivor.txt").unwrap(), survivor);
    assert_eq!(file(&fs, disk, "/Folder/survivor.txt"), SURVIVOR);
    let victim = volume::be32(original, 8);
    let survivor_id = volume::be32(survivor, 8);
    {
        let state = disk.0.lock().unwrap();
        assert_eq!(
            public_attributes(&state.durable),
            expected_attributes(victim, survivor_id, true)
        );
        catalog_wire::audit(&state.durable);
        fork_bitmap(&state.durable, original, 88, true);
        fork_bitmap(&state.durable, original, 168, resource || store);
    }
    let adapter = Adapter::from_device(disk.clone()).unwrap();
    let mut after = adapter.shutdown().unwrap();
    let fs = engine::open_checked(&mut after).unwrap();
    assert!(fs.catalog_record(STORE).is_err());
    assert_eq!(fs.catalog_record(PATH).unwrap(), current);
    assert_eq!(file(&fs, &mut after, PATH), DATA);
    let inspection = volume::inspect(&mut after).unwrap();
    assert_eq!(inspection.header.files, 4);
    assert_eq!(inspection.header.folders, 1);
    let state = after.0.lock().unwrap();
    assert_eq!(
        public_attributes(&state.durable),
        expected_attributes(victim, survivor_id, true)
    );
    catalog_wire::audit(&state.durable);
    fork_bitmap(&state.durable, original, 88, true);
    fork_bitmap(&state.durable, original, 168, resource);
}

#[test]
fn cleanup_close_and_recovery_survive_sector_persistence_and_replay_interruptions() {
    deletion_matrix(false);
}
#[test]
fn resource_unlink_close_and_recovery_survive_sector_persistence_and_replay_interruptions() {
    deletion_matrix(true);
}
fn deletion_matrix(resource: bool) {
    let mut checkpoints = 0;
    let mut replay_checkpoints = 0;
    for sensitive in [false, true] {
        for little in [false, true] {
            for wrap in [false, true] {
                let base = fixture_kind(little, wrap, sensitive, resource);
                let j = journal_offset(&base);
                let mut probe = Disk::new(&base);
                let fs = engine::open_checked(&mut probe).unwrap();
                let survivor = fs.catalog_record("/Folder/survivor.txt").unwrap();
                let original = fs.catalog_record(PATH).unwrap();
                let cnid = volume::be32(&original, 8);
                let run =
                    |input: &[u8], operation, stop| attempt_kind(input, operation, stop, resource);
                let check = |disk: &mut Disk, operation| {
                    if resource {
                        verify_resource(disk, operation, &survivor, &original);
                    } else {
                        verify(disk, operation, &survivor, cnid);
                    }
                };
                let (success, orphan) = run(&base, 0, None);
                assert!(success);
                let orphaned = orphan.0.lock().unwrap().durable.clone();
                let label = format!(
                    "{}-{}-{}",
                    if sensitive { "hfsx" } else { "hfsplus" },
                    if little { "le" } else { "be" },
                    if wrap { "wrap" } else { "straight" }
                );
                let prefix = if resource {
                    "resource-deferred"
                } else {
                    "deferred"
                };
                retain(&orphaned, &format!("{prefix}-store-{label}.img"));
                for operation in 0..3 {
                    let input = if operation == 2 { &orphaned } else { &base };
                    let (success, full) = run(input, operation, None);
                    assert!(success);
                    let count = full.0.lock().unwrap().calls;
                    let committed = full.0.lock().unwrap().durable.clone();
                    let mut committed_probe = Disk::new(&committed);
                    // Acknowledged cleanup must have removed the old name even
                    // before deferred reclamation is run.
                    let committed_fs = engine::open_checked(&mut committed_probe).unwrap();
                    if resource {
                        assert_eq!(
                            committed_fs
                                .resource_fork_size(&mut committed_probe, PATH)
                                .unwrap()
                                .unwrap_or(0),
                            0
                        );
                    } else {
                        assert!(committed_fs.catalog_record(PATH).is_err());
                    }
                    check(&mut committed_probe, operation);
                    retain(
                        &committed_probe.0.lock().unwrap().durable,
                        &format!("{prefix}-recovered-{operation}-{label}.img"),
                    );
                    let mut pending = None;
                    for stop in 0..count {
                        let (success, interrupted) = run(input, operation, Some(stop));
                        assert!(!success, "{label} operation {operation} stop {stop}");
                        for (policy, name) in POLICIES.iter().enumerate() {
                            let snapshot = interrupted.snapshot(policy, j);
                            let mut inspect = Disk::new(&snapshot);
                            if matches!(
                                volume::inspect(&mut inspect).unwrap().journal,
                                volume::Journal::Pending { .. }
                            ) {
                                pending.get_or_insert_with(|| snapshot.clone());
                                inspect.arm(Some(0));
                                assert!(Adapter::from_device(inspect.clone()).is_err());
                                assert_eq!(
                                    inspect.0.lock().unwrap().calls,
                                    0,
                                    "production open replayed a pending journal"
                                );
                            }
                            let mut recovered = Disk::new(&snapshot);
                            check(&mut recovered, operation);
                            checkpoints += 1;
                            let _ = name;
                        }
                    }
                    let pending = pending.expect("no pending transaction observed");
                    let mut replay = Disk::new(&pending);
                    HfsPlus::open(&mut replay).unwrap();
                    let replay_count = replay.0.lock().unwrap().calls;
                    for stop in 0..replay_count {
                        let mut interrupted = Disk::new(&pending);
                        interrupted.arm(Some(stop));
                        assert!(HfsPlus::open(&mut interrupted).is_err());
                        for policy in 0..POLICIES.len() {
                            let mut recovered = Disk::new(&interrupted.snapshot(policy, j));
                            check(&mut recovered, operation);
                            replay_checkpoints += 1;
                        }
                    }
                }
            }
        }
    }
    let name = if resource {
        "RESOURCE_DELETE_MATRIX"
    } else {
        "DEFERRED_MATRIX"
    };
    println!(
        "{name}: {checkpoints} commit checkpoints + {replay_checkpoints} replay checkpoints passed; 24 scenarios"
    );
}
