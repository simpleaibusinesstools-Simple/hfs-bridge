//! Cache correctness, including a changed volume header and live read errors.
use fstool::{
    block::{BlockDevice, MemoryBackend},
    fs::hfs_plus::{FormatOpts, HfsPlus},
};
use hfs_bridge::{
    volume,
    windows::{Access, Adapter, BasicTimes, Kind, OpenRequest, hfs_to_filetime},
};
use std::{
    io::{self, Cursor, Read, Seek, SeekFrom, Write},
    sync::{Arc, Mutex},
};

struct State {
    bytes: Cursor<Vec<u8>>,
    reads: usize,
    fail: bool,
}
#[derive(Clone)]
struct Observed(Arc<Mutex<State>>);
impl Observed {
    fn new(bytes: Vec<u8>) -> Self {
        Self(Arc::new(Mutex::new(State {
            bytes: Cursor::new(bytes),
            reads: 0,
            fail: false,
        })))
    }
}
impl Read for Observed {
    fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
        let mut state = self.0.lock().unwrap();
        state.reads += 1;
        if state.fail {
            return Err(io::Error::other("injected read failure"));
        }
        state.bytes.read(b)
    }
}
impl Seek for Observed {
    fn seek(&mut self, p: SeekFrom) -> io::Result<u64> {
        self.0.lock().unwrap().bytes.seek(p)
    }
}
impl Write for Observed {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> {
        panic!("read-only source write");
    }
    fn flush(&mut self) -> io::Result<()> {
        panic!("read-only source flush");
    }
}
impl BlockDevice for Observed {
    fn block_size(&self) -> u32 {
        512
    }
    fn total_size(&self) -> u64 {
        self.0.lock().unwrap().bytes.get_ref().len() as u64
    }
    fn sync(&mut self) -> fstool::Result<()> {
        panic!("read-only source sync");
    }
}
fn read() -> OpenRequest {
    OpenRequest {
        access: Access::READ,
        ..Default::default()
    }
}
fn fixture() -> MemoryBackend {
    let mut d = MemoryBackend::new(8 * 1024 * 1024);
    let mut fs = HfsPlus::format(&mut d, &FormatOpts::default()).unwrap();
    fs.create_file(
        &mut d,
        "/plain",
        &mut &b"data"[..],
        4,
        0o644,
        501,
        20,
        1_700_000_000,
    )
    .unwrap();
    fs.flush(&mut d).unwrap();
    fs.create_file(
        &mut d,
        "/other",
        &mut &b""[..],
        0,
        0o644,
        501,
        20,
        1_700_000_000,
    )
    .unwrap();
    fs.flush(&mut d).unwrap();
    let other = volume::be32(&fs.catalog_record("/other").unwrap(), 8);
    fs.set_inline_attribute(&mut d, other, "user.fixture", Some(b"unrelated attribute"))
        .unwrap();
    fs.flush(&mut d).unwrap();
    d
}

#[test]
fn absent_generation_reuses_validation_but_checks_live_header_and_errors() {
    let observed = Observed::new(fixture().into_bytes());
    let mut a = Adapter::from_read_only_device(observed.clone()).unwrap();
    let h = a.open(r"\plain", read()).unwrap();
    let expected = a.file_info(h).unwrap();
    observed.0.lock().unwrap().reads = 0;
    let info = a.file_info(h).unwrap();
    assert_eq!(info.creation_time, expected.creation_time);
    assert_eq!(
        observed.0.lock().unwrap().reads,
        1,
        "only the live volume marker is needed after validation"
    );
    {
        let mut state = observed.0.lock().unwrap();
        let bytes = state.bytes.get_mut();
        let count = volume::be32(bytes, 1092);
        bytes[1092..1096].copy_from_slice(&(count + 1).to_be_bytes());
        state.reads = 0;
    }
    a.file_info(h).unwrap();
    assert!(
        observed.0.lock().unwrap().reads > 1,
        "changed volume must revalidate generation storage"
    );
    observed.0.lock().unwrap().fail = true;
    assert!(
        a.file_info(h).is_err(),
        "cached metadata must not mask device failure"
    );
}

#[test]
fn cached_generation_preserves_fractions_and_rejects_a_foreign_write_counter() {
    let mut writable = Adapter::from_device(fixture()).unwrap();
    let h = writable
        .create(
            r"\precise",
            Kind::File,
            OpenRequest {
                access: Access::ALL,
                ..Default::default()
            },
        )
        .unwrap();
    let exact = hfs_to_filetime(3_800_000_000) + 1234567;
    writable
        .set_basic_times(
            h,
            BasicTimes {
                creation: Some(exact),
                ..Default::default()
            },
        )
        .unwrap();
    writable.close(h).unwrap();
    let disk = writable.shutdown().unwrap();
    let observed = Observed::new(disk.into_bytes());
    let mut a = Adapter::from_read_only_device(observed.clone()).unwrap();
    let h = a.open(r"\precise", read()).unwrap();
    for _ in 0..3 {
        assert_eq!(a.file_info(h).unwrap().creation_time, exact);
    }
    {
        let mut state = observed.0.lock().unwrap();
        let bytes = state.bytes.get_mut();
        let count = volume::be32(bytes, 1092);
        bytes[1092..1096].copy_from_slice(&(count + 1).to_be_bytes());
    }
    assert_eq!(a.file_info(h).unwrap().creation_time, exact - 1234567);
}

#[test]
fn positive_precision_snapshots_keep_fractions_and_live_failure_checks() {
    let mut writable = Adapter::from_device(fixture()).unwrap();
    let h = writable
        .create(
            r"\precise-cached",
            Kind::File,
            OpenRequest {
                access: Access::ALL,
                ..Default::default()
            },
        )
        .unwrap();
    let exact = hfs_to_filetime(3_800_000_000) + 1234567;
    writable
        .set_basic_times(
            h,
            BasicTimes {
                creation: Some(exact),
                ..Default::default()
            },
        )
        .unwrap();
    writable.close(h).unwrap();
    let observed = Observed::new(writable.shutdown().unwrap().into_bytes());
    let mut a = Adapter::from_read_only_device(observed.clone()).unwrap();
    let h = a.open(r"\precise-cached", read()).unwrap();
    assert_eq!(a.file_info_with_ea(h).unwrap().creation_time, exact);
    observed.0.lock().unwrap().reads = 0;
    for _ in 0..8 {
        assert_eq!(a.file_info_with_ea(h).unwrap().creation_time, exact);
    }
    assert!(
        observed.0.lock().unwrap().reads <= 48,
        "positive precision must reuse committed tree validation"
    );
    {
        let mut state = observed.0.lock().unwrap();
        let bytes = state.bytes.get_mut();
        let count = volume::be32(bytes, 1092);
        bytes[1092..1096].copy_from_slice(&(count + 1).to_be_bytes());
    }
    assert_eq!(
        a.file_info_with_ea(h).unwrap().creation_time,
        exact - 1234567
    );
    observed.0.lock().unwrap().fail = true;
    assert!(
        a.file_info_with_ea(h).is_err(),
        "snapshot must not hide an unreadable device"
    );
}

#[test]
fn readonly_attribute_values_match_uncached_reads_and_surface_device_errors() {
    let bytes = fixture().into_bytes();
    let mut uncached = Adapter::from_device(MemoryBackend::from_bytes(bytes.clone())).unwrap();
    let expected_handle = uncached.open(r"\other", read()).unwrap();
    let expected = uncached.extended_attributes(expected_handle).unwrap();
    assert!(!expected.is_empty());
    let observed = Observed::new(bytes);
    let mut cached = Adapter::from_read_only_device(observed.clone()).unwrap();
    let handle = cached.open(r"\other", read()).unwrap();
    observed.0.lock().unwrap().reads = 0;
    assert_eq!(cached.extended_attributes(handle).unwrap(), expected);
    let cold_reads = observed.0.lock().unwrap().reads;
    observed.0.lock().unwrap().reads = 0;
    for _ in 0..20 {
        assert_eq!(cached.extended_attributes(handle).unwrap(), expected);
    }
    let warm_reads = observed.0.lock().unwrap().reads;
    assert!(
        warm_reads <= 60,
        "cached values should need only live header reads: {warm_reads}"
    );
    assert!(
        cold_reads <= 3,
        "first inline value must use the already validated tree: {cold_reads}"
    );
    observed.0.lock().unwrap().fail = true;
    assert!(cached.extended_attributes(handle).is_err());
}

fn change_bytes(observed: &Observed, old: &[u8], new: &[u8]) {
    assert_eq!(old.len(), new.len());
    let mut state = observed.0.lock().unwrap();
    let bytes = state.bytes.get_mut();
    let locations: Vec<_> = bytes
        .windows(old.len())
        .enumerate()
        .filter_map(|(i, part)| (part == old).then_some(i))
        .collect();
    assert_eq!(locations.len(), 1, "unique committed attribute fixture");
    bytes[locations[0]..locations[0] + new.len()].copy_from_slice(new);
    let count = volume::be32(bytes, 1092);
    bytes[1092..1096].copy_from_slice(&(count + 1).to_be_bytes());
}

#[test]
fn header_change_invalidates_both_attribute_names_and_values() {
    let observed = Observed::new(fixture().into_bytes());
    let mut a = Adapter::from_read_only_device(observed.clone()).unwrap();
    let h = a.open(r"\other", read()).unwrap();
    let initial = a.extended_attributes(h).unwrap();
    change_bytes(&observed, b"unrelated attribute", b"replacement content");
    let changed = a.extended_attributes(h).unwrap();
    assert_ne!(changed, initial);
    assert_eq!(
        changed,
        hfs_bridge::ea::records(&[("user.fixture".into(), b"replacement content".to_vec())])
            .unwrap()
    );
    let utf16 = |s: &str| {
        s.encode_utf16()
            .flat_map(u16::to_be_bytes)
            .collect::<Vec<_>>()
    };
    change_bytes(&observed, &utf16("user.fixture"), &utf16("user.changed"));
    let renamed = a.extended_attributes(h).unwrap();
    assert_ne!(renamed, changed);
    let expected =
        hfs_bridge::ea::records(&[("user.changed".into(), b"replacement content".to_vec())])
            .unwrap();
    assert_eq!(renamed, expected);
}

#[test]
fn changed_header_with_corrupt_attribute_tree_never_returns_cached_values() {
    let observed = Observed::new(fixture().into_bytes());
    let mut a = Adapter::from_read_only_device(observed.clone()).unwrap();
    let h = a.open(r"\other", read()).unwrap();
    a.extended_attributes(h).unwrap();
    {
        let mut state = observed.0.lock().unwrap();
        let bytes = state.bytes.get_mut();
        let block_size = volume::be32(bytes, 1064) as usize;
        let attribute_block = volume::be32(bytes, 1392) as usize;
        assert!(attribute_block > 0 && block_size >= 512);
        // The committed attributes B-tree header must be a header node (kind 1).
        assert_eq!(bytes[attribute_block * block_size + 8], 1);
        bytes[attribute_block * block_size + 8] = 0xff;
        let count = volume::be32(bytes, 1092);
        bytes[1092..1096].copy_from_slice(&(count + 1).to_be_bytes());
    }
    assert!(a.extended_attributes(h).is_err());
    assert!(
        a.extended_attributes(h).is_err(),
        "failed revalidation must not restore the old cache"
    );
}

#[test]
fn warm_directory_lookup_still_checks_the_live_device() {
    let observed = Observed::new(fixture().into_bytes());
    let mut a = Adapter::from_read_only_device(observed.clone()).unwrap();
    for _ in 0..3 {
        let h = a.open(r"\plain", read()).unwrap();
        a.close(h).unwrap();
    }
    observed.0.lock().unwrap().fail = true;
    assert!(a.open(r"\plain", read()).is_err());
    assert!(a.path_info(r"\plain").is_err());
}

// Same counted storage as the read-only tests, with writes enabled solely for
// generated fixtures. The read-only type above still panics on every mutation.
#[derive(Clone)]
struct WritableObserved(Observed);
impl Read for WritableObserved {
    fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
        self.0.read(b)
    }
}
impl Seek for WritableObserved {
    fn seek(&mut self, at: SeekFrom) -> io::Result<u64> {
        self.0.seek(at)
    }
}
impl Write for WritableObserved {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        self.0.0.lock().unwrap().bytes.write(b)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
impl BlockDevice for WritableObserved {
    fn block_size(&self) -> u32 {
        512
    }
    fn total_size(&self) -> u64 {
        self.0.total_size()
    }
    fn sync(&mut self) -> fstool::Result<()> {
        Ok(())
    }
}

#[test]
fn writable_committed_reads_cache_then_invalidate_after_attribute_publication() {
    let observed = Observed::new(fixture().into_bytes());
    let mut a = Adapter::from_device(WritableObserved(observed.clone())).unwrap();
    let h = a
        .open(
            r"\other",
            OpenRequest {
                access: Access::ALL,
                ..Default::default()
            },
        )
        .unwrap();
    let initial = a.extended_attributes(h).unwrap();
    observed.0.lock().unwrap().reads = 0;
    for _ in 0..20 {
        assert_eq!(a.extended_attributes(h).unwrap(), initial);
    }
    assert!(
        observed.0.lock().unwrap().reads <= 80,
        "committed reads should not rescan the tree"
    );
    let changed =
        hfs_bridge::ea::records(&[("user.fixture".into(), b"new committed bytes".to_vec())])
            .unwrap();
    a.set_extended_attributes(h, &hfs_bridge::ea::encode(&changed).unwrap())
        .unwrap();
    assert_eq!(a.extended_attributes(h).unwrap(), changed);
    let exact = hfs_to_filetime(3_800_000_000) + 1234567;
    a.set_basic_times(
        h,
        BasicTimes {
            creation: Some(exact),
            ..Default::default()
        },
    )
    .unwrap();
    for _ in 0..3 {
        assert_eq!(a.file_info(h).unwrap().creation_time, exact);
    }
    // Once one HFS Bridge file publishes the volume marker, ordinary untouched
    // Mac files must still avoid repeated catalog-wide timestamp validation.
    let plain = a.open(r"\plain", read()).unwrap();
    let expected = a.file_info(plain).unwrap();
    observed.0.lock().unwrap().reads = 0;
    for _ in 0..20 {
        assert_eq!(
            a.file_info(plain).unwrap().creation_time,
            expected.creation_time
        );
    }
    assert!(
        observed.0.lock().unwrap().reads <= 60,
        "files without precision records use validated negative lookups"
    );
    observed.0.lock().unwrap().fail = true;
    assert!(
        a.extended_attributes(h).is_err(),
        "a cache hit must still detect device failure"
    );
}

#[test]
fn writable_directory_cache_tracks_create_rename_and_delete() {
    let mut a = Adapter::from_device(fixture()).unwrap();
    let root = a.open(r"\", read()).unwrap();
    for _ in 0..2 {
        assert_eq!(a.read_directory(root).unwrap().len(), 2);
    }
    let h = a
        .create(
            r"\added",
            Kind::File,
            OpenRequest {
                access: Access::ALL,
                ..Default::default()
            },
        )
        .unwrap();
    assert!(
        a.read_directory(root)
            .unwrap()
            .iter()
            .any(|e| e.name == "added")
    );
    a.rename(h, r"\renamed").unwrap();
    let names = a.read_directory(root).unwrap();
    assert!(!names.iter().any(|e| e.name == "added"));
    assert!(names.iter().any(|e| e.name == "renamed"));
    a.cleanup(h, true).unwrap();
    a.close(h).unwrap();
    assert_eq!(a.read_directory(root).unwrap().len(), 2);
    a.close(root).unwrap();
    a.shutdown().unwrap();
}

#[test]
fn staged_engine_metadata_is_ineligible_for_read_snapshots() {
    let mut device = fixture();
    let mut fs = HfsPlus::open(&mut device).unwrap();
    assert!(fs.metadata_is_committed());
    fs.create_file(
        &mut device,
        "/staged",
        &mut &b""[..],
        0,
        0o644,
        501,
        20,
        1_700_000_000,
    )
    .unwrap();
    assert!(!fs.metadata_is_committed());
    fs.flush(&mut device).unwrap();
    assert!(fs.metadata_is_committed());
    let cnid = volume::be32(&fs.catalog_record("/staged").unwrap(), 8);
    fs.set_inline_attribute(&mut device, cnid, "user.staged", Some(b"pending"))
        .unwrap();
    assert!(!fs.metadata_is_committed());
    fs.flush(&mut device).unwrap();
    assert!(fs.metadata_is_committed());
}
