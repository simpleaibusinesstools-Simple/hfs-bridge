use fstool::block::{BlockDevice, MemoryBackend};
use fstool::fs::{
    Filesystem, OpenFlags,
    hfs_plus::{FormatOpts, HfsPlus},
};
use hfs_bridge::volume;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

fn bytes(len: usize) -> Vec<u8> {
    (0..len).map(|i| ((i * 31 + i / 251) % 256) as u8).collect()
}
fn fixture(journaled: bool) -> MemoryBackend {
    let mut disk = MemoryBackend::new(32 * 1024 * 1024);
    let mut fs = HfsPlus::format(
        &mut disk,
        &FormatOpts {
            journaled,
            ..Default::default()
        },
    )
    .unwrap();
    let data = bytes(200_003);
    fs.create_file(
        &mut disk,
        "/file.bin",
        &mut &data[..],
        data.len() as u64,
        0o640,
        501,
        20,
        1_700_000_000,
    )
    .unwrap();
    fs.create_file(
        &mut disk,
        "/other.bin",
        &mut &b"unrelated"[..],
        9,
        0o644,
        0,
        0,
        0,
    )
    .unwrap();
    fs.flush(&mut disk).unwrap();
    disk
}
fn read(fs: &mut HfsPlus, disk: &mut dyn BlockDevice, path: &str) -> Vec<u8> {
    let mut data = Vec::new();
    fs.open_file_reader(disk, path)
        .unwrap()
        .read_to_end(&mut data)
        .unwrap();
    data
}
fn sequence(journaled: bool) {
    let mut disk = fixture(journaled);
    let mut fs = HfsPlus::open(&mut disk).unwrap();
    let record = fs.catalog_record("/file.bin").unwrap();
    let mut expected = bytes(200_003);
    {
        let mut handle = fs
            .open_file_rw(
                &mut disk,
                std::path::Path::new("/FILE.bin"),
                OpenFlags::default(),
                None,
            )
            .unwrap();
        handle.seek(SeekFrom::Start(4093)).unwrap();
        handle.write_all(b"cross-block-patch").unwrap();
        expected[4093..4110].copy_from_slice(b"cross-block-patch");
        handle.seek(SeekFrom::Start(4088)).unwrap();
        let mut observed = [0; 24];
        handle.read_exact(&mut observed).unwrap();
        assert_eq!(&observed, &expected[4088..4112]);
        handle.sync().unwrap();
        handle.set_len(5).unwrap();
        handle.set_len(8193).unwrap();
        expected.truncate(5);
        expected.resize(8193, 0);
        handle.seek(SeekFrom::Start(8191)).unwrap();
        handle.write_all(b"end").unwrap();
        expected.resize(8194, 0);
        expected[8191..].copy_from_slice(b"end");
        handle.sync().unwrap();
        // Empty writes beyond EOF are a no-op; failed seeks change no cursor.
        handle.seek(SeekFrom::Start(u64::MAX)).unwrap();
        assert_eq!(handle.write(&[]).unwrap(), 0);
        assert!(handle.seek(SeekFrom::Current(1)).is_err());
        assert_eq!(handle.len(), expected.len() as u64);
    }
    let mut fs = HfsPlus::open(&mut disk).unwrap();
    assert_eq!(read(&mut fs, &mut disk, "/file.bin"), expected);
    assert_eq!(read(&mut fs, &mut disk, "/other.bin"), b"unrelated");
    let after = fs.catalog_record("/file.bin").unwrap();
    assert_eq!(&record[..88], &after[..88]);
    assert_eq!(&record[168..], &after[168..]);
    volume::require_engine_access(&volume::inspect(&mut disk).unwrap()).unwrap();
    // Reusing freed original blocks for another file must not change the edit.
    let other = bytes(200_003);
    fs.create_file(
        &mut disk,
        "/reuse.bin",
        &mut &other[..],
        other.len() as u64,
        0o644,
        0,
        0,
        0,
    )
    .unwrap();
    fs.flush(&mut disk).unwrap();
    assert_eq!(read(&mut fs, &mut disk, "/file.bin"), expected);
    assert_eq!(read(&mut fs, &mut disk, "/reuse.bin"), other);
    if let Some(directory) = std::env::var_os("HFS_CRASH_ARTIFACT_DIR") {
        let mut file = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(std::path::Path::new(&directory).join(format!(
                "editing-sequence-{}.img",
                if journaled { "journaled" } else { "plain" }
            )))
            .unwrap();
        file.write_all(disk.as_slice()).unwrap();
        file.sync_all().unwrap();
    }
}
#[test]
fn journaled_edit_sequence_preserves_contents_and_identity() {
    sequence(true);
}
#[test]
fn plain_edit_sequence_preserves_contents_and_identity() {
    sequence(false);
}

#[test]
fn zero_truncate_growth_and_append_flags_are_persistent() {
    let mut disk = fixture(true);
    let mut fs = HfsPlus::open(&mut disk).unwrap();
    {
        let mut handle = fs
            .open_file_rw(
                &mut disk,
                std::path::Path::new("/file.bin"),
                OpenFlags {
                    truncate: true,
                    ..Default::default()
                },
                None,
            )
            .unwrap();
        assert_eq!(handle.len(), 0);
        handle.sync().unwrap();
        handle.set_len(100_003).unwrap();
        handle.sync().unwrap();
    }
    let mut fs = HfsPlus::open(&mut disk).unwrap();
    assert_eq!(read(&mut fs, &mut disk, "/file.bin"), vec![0; 100_003]);
    {
        let mut handle = fs
            .open_file_rw(
                &mut disk,
                std::path::Path::new("/file.bin"),
                OpenFlags {
                    append: true,
                    ..Default::default()
                },
                None,
            )
            .unwrap();
        handle.write_all(b"append").unwrap();
        handle.sync().unwrap();
    }
    let mut fs = HfsPlus::open(&mut disk).unwrap();
    let mut expected = vec![0; 100_003];
    expected.extend_from_slice(b"append");
    assert_eq!(read(&mut fs, &mut disk, "/file.bin"), expected);
}

#[test]
fn impossible_growth_preserves_original_and_requires_reopen() {
    let mut disk = fixture(true);
    let before = disk.as_slice().to_vec();
    let mut fs = HfsPlus::open(&mut disk).unwrap();
    {
        let mut handle = fs
            .open_file_rw(
                &mut disk,
                std::path::Path::new("/file.bin"),
                OpenFlags::default(),
                None,
            )
            .unwrap();
        assert!(handle.set_len(32 * 1024 * 1024).is_err());
        assert!(handle.sync().is_err());
        assert!(handle.write(b"retry").is_err());
    }
    assert!(fs.flush(&mut disk).is_err());
    assert!(
        fs.create_dir(&mut disk, "/must-reopen", 0o755, 0, 0, 0)
            .is_err()
    );
    assert_eq!(disk.as_slice(), before);
    let mut fs = HfsPlus::open(&mut disk).unwrap();
    assert_eq!(read(&mut fs, &mut disk, "/file.bin"), bytes(200_003));
}

struct FailSync {
    disk: MemoryBackend,
    fail: bool,
    calls: Arc<AtomicUsize>,
}
impl Read for FailSync {
    fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
        self.disk.read(b)
    }
}
impl Seek for FailSync {
    fn seek(&mut self, p: SeekFrom) -> io::Result<u64> {
        self.disk.seek(p)
    }
}
impl Write for FailSync {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        self.disk.write(b)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        if self.fail {
            self.fail = false;
            Err(io::Error::other("single sync failure"))
        } else {
            Ok(())
        }
    }
}
impl BlockDevice for FailSync {
    fn block_size(&self) -> u32 {
        512
    }
    fn total_size(&self) -> u64 {
        self.disk.total_size()
    }
    fn sync(&mut self) -> fstool::Result<()> {
        Ok(self.flush()?)
    }
}
#[test]
fn failed_sync_is_sticky_and_close_does_not_retry_the_commit() {
    let calls = Arc::new(AtomicUsize::new(0));
    let mut disk = FailSync {
        disk: fixture(true),
        fail: false,
        calls: calls.clone(),
    };
    let mut fs = HfsPlus::open(&mut disk).unwrap();
    {
        let mut handle = fs
            .open_file_rw(
                &mut disk,
                std::path::Path::new("/file.bin"),
                OpenFlags::default(),
                None,
            )
            .unwrap();
        handle.seek(SeekFrom::Start(3)).unwrap();
        handle.write_all(b"edit").unwrap();
        handle.sync().unwrap();
    }
    disk.fail = true;
    let failed_counts;
    {
        let mut handle = fs
            .open_file_rw(
                &mut disk,
                std::path::Path::new("/file.bin"),
                OpenFlags::default(),
                None,
            )
            .unwrap();
        handle.write_all(b"pending").unwrap();
        assert!(
            handle
                .sync()
                .unwrap_err()
                .to_string()
                .contains("single sync failure")
        );
        failed_counts = calls.load(Ordering::Relaxed);
        assert!(handle.sync().is_err());
        assert_eq!(calls.load(Ordering::Relaxed), failed_counts);
    }
    assert_eq!(calls.load(Ordering::Relaxed), failed_counts);
    assert!(fs.flush(&mut disk).is_err());
    assert!(
        fs.open_file_rw(
            &mut disk,
            std::path::Path::new("/file.bin"),
            OpenFlags::default(),
            None
        )
        .is_err()
    );
    assert_eq!(calls.load(Ordering::Relaxed), failed_counts);
}

#[test]
fn fragmented_old_and_replacement_forks_keep_overflow_records_consistent() {
    fragmented_fork(false);
}
#[test]
fn fragmented_resource_forks_keep_their_own_overflow_records() {
    fragmented_fork(true);
}
fn fragmented_fork(resource: bool) {
    let mut disk = MemoryBackend::new(1024 * 1024);
    let mut fs = HfsPlus::format(&mut disk, &FormatOpts::default()).unwrap();
    let block = bytes(4096);
    for i in 0..9 {
        for kind in ["gap", "keep"] {
            fs.create_file(
                &mut disk,
                &format!("/{kind}{i}"),
                &mut &block[..],
                block.len() as u64,
                0o644,
                0,
                0,
                0,
            )
            .unwrap();
        }
    }
    fs.flush(&mut disk).unwrap();
    let remaining = u64::from(volume::inspect(&mut disk).unwrap().header.free_blocks) * 4096;
    fs.create_file(
        &mut disk,
        "/fill",
        &mut std::io::repeat(0),
        remaining,
        0o644,
        0,
        0,
        0,
    )
    .unwrap();
    fs.flush(&mut disk).unwrap();
    for i in 0..9 {
        fs.remove(&mut disk, &format!("/gap{i}")).unwrap();
    }
    fs.flush(&mut disk).unwrap();
    let mut expected = bytes(9 * 4096 - 3);
    fs.create_file(
        &mut disk,
        "/fragmented.bin",
        &mut &if resource { &[][..] } else { &expected[..] }[..],
        if resource { 0 } else { expected.len() as u64 },
        0o644,
        0,
        0,
        0,
    )
    .unwrap();
    if resource {
        let mut file = fs
            .open_resource_fork_rw(&mut disk, std::path::Path::new("/fragmented.bin"))
            .unwrap();
        file.write_all(&expected).unwrap();
        file.sync().unwrap();
    }
    fs.flush(&mut disk).unwrap();
    // The current handle must see the newly populated overflow tree without
    // reopening the volume (which would mask a stale B-tree header).
    let mut live = Vec::new();
    if resource {
        fs.open_resource_fork_reader(&mut disk, "/fragmented.bin")
            .unwrap()
            .read_to_end(&mut live)
            .unwrap();
    } else {
        live = read(&mut fs, &mut disk, "/fragmented.bin");
    }
    assert_eq!(live, expected);
    for i in 0..9 {
        fs.remove(&mut disk, &format!("/keep{i}")).unwrap();
    }
    fs.flush(&mut disk).unwrap();
    let mut fs = HfsPlus::open(&mut disk).unwrap();
    let original = fs.catalog_record("/fragmented.bin").unwrap();
    let fork_offset = if resource { 168 } else { 88 };
    assert_eq!(volume::be32(&original, fork_offset + 12), 9);
    assert!(
        original[fork_offset + 16..fork_offset + 80]
            .as_chunks::<8>()
            .0
            .iter()
            .all(|e| volume::be32(e, 4) == 1)
    );
    {
        let mut handle = if resource {
            fs.open_resource_fork_rw(&mut disk, std::path::Path::new("/fragmented.bin"))
                .unwrap()
        } else {
            fs.open_file_rw(
                &mut disk,
                std::path::Path::new("/fragmented.bin"),
                OpenFlags::default(),
                None,
            )
            .unwrap()
        };
        handle.seek(SeekFrom::Start(8191)).unwrap();
        handle.write_all(b"fragment").unwrap();
        handle.sync().unwrap();
    }
    expected[8191..8199].copy_from_slice(b"fragment");
    let mut live = Vec::new();
    if resource {
        fs.open_resource_fork_reader(&mut disk, "/fragmented.bin")
            .unwrap()
            .read_to_end(&mut live)
            .unwrap();
    } else {
        live = read(&mut fs, &mut disk, "/fragmented.bin");
    }
    assert_eq!(live, expected);
    let mut fs = HfsPlus::open(&mut disk).unwrap();
    if resource {
        let mut observed = Vec::new();
        fs.open_resource_fork_reader(&mut disk, "/fragmented.bin")
            .unwrap()
            .read_to_end(&mut observed)
            .unwrap();
        assert_eq!(observed, expected);
        assert_eq!(
            &fs.catalog_record("/fragmented.bin").unwrap()[..168],
            &original[..168]
        );
    } else {
        assert_eq!(read(&mut fs, &mut disk, "/fragmented.bin"), expected);
    }
    assert_eq!(
        volume::be32(&fs.catalog_record("/fragmented.bin").unwrap(), 8),
        volume::be32(&original, 8)
    );
    assert_eq!(volume::inspect(&mut disk).unwrap().header.free_blocks, 9);
    if let Some(directory) = std::env::var_os("HFS_CRASH_ARTIFACT_DIR") {
        let mut file = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(std::path::Path::new(&directory).join(if resource {
                "fragmented-resource-edited.img"
            } else {
                "fragmented-edited.img"
            }))
            .unwrap();
        file.write_all(disk.as_slice()).unwrap();
        file.sync_all().unwrap();
    }
    if resource {
        let before = fs.catalog_record("/fragmented.bin").unwrap();
        let target = fs
            .create_file(
                &mut disk,
                "/resource-orphan.bin",
                &mut &[][..],
                0,
                0o600,
                0,
                0,
                0,
            )
            .unwrap();
        fs.detach_resource_fork(&mut disk, volume::be32(&before, 8), target)
            .unwrap();
        fs.flush(&mut disk).unwrap();
        let mut reopened = HfsPlus::open(&mut disk).unwrap();
        assert_eq!(
            read(&mut reopened, &mut disk, "/resource-orphan.bin"),
            expected
        );
        let cleared = reopened.catalog_record("/fragmented.bin").unwrap();
        assert_eq!(&cleared[..168], &before[..168]);
        assert_eq!(volume::be64(&cleared, 168), 0);
        assert_eq!(volume::be32(&cleared, 180), 0);
        assert_eq!(
            &reopened.catalog_record("/resource-orphan.bin").unwrap()[88..168],
            &before[168..248]
        );
        // Recreating the source stream proves the old overflow key was removed
        // as well as retagged to the recovery file's data fork.
        {
            let mut fork = reopened
                .open_resource_fork_rw(&mut disk, std::path::Path::new("/fragmented.bin"))
                .unwrap();
            fork.write_all(b"fresh").unwrap();
            fork.sync().unwrap();
        }
        reopened.flush(&mut disk).unwrap();
        let mut reopened = HfsPlus::open(&mut disk).unwrap();
        assert_eq!(
            read(&mut reopened, &mut disk, "/resource-orphan.bin"),
            expected
        );
        if let Some(directory) = std::env::var_os("HFS_CRASH_ARTIFACT_DIR") {
            let mut file = hfs_bridge::image::create_output(
                &std::path::Path::new(&directory).join("fragmented-resource-detached.img"),
            )
            .unwrap();
            file.write_all(disk.as_slice()).unwrap();
            file.sync_all().unwrap();
        }
    }
    // Emptying the overflow tree must erase the former leaf as well as
    // clearing its allocation-map bit. Apple fsck_hfs rejects stale free nodes.
    if resource {
        fs.remove(&mut disk, "/resource-orphan.bin").unwrap();
    }
    fs.remove(&mut disk, "/fragmented.bin").unwrap();
    fs.flush(&mut disk).unwrap();
    let image = disk.as_slice();
    let extents_start = volume::be32(image, 1024 + 192 + 16) as usize * 4096;
    let node_size = volume::be16(image, extents_start + 14 + 18) as usize;
    assert_eq!(volume::be32(image, extents_start + 14 + 2), 0);
    assert!(
        image[extents_start + node_size..extents_start + 2 * node_size]
            .iter()
            .all(|byte| *byte == 0),
        "Unused extents node 1 must be erased after the final overflow record is removed"
    );
}
