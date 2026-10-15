//! Explicitly invoked diagnostic: fixed generated images, no native mounts.
use fstool::{
    block::{BlockDevice, MemoryBackend},
    fs::hfs_plus::{FormatOpts, HfsPlus},
};
use hfs_bridge::{
    image::Image,
    windows::{Access, Adapter, Kind, OpenRequest},
};
use std::{
    io::{self, Read, Seek, SeekFrom, Write},
    sync::{Arc, Mutex},
    time::Instant,
};

#[test]
#[ignore = "explicit in-memory timing diagnostic"]
fn profile_container_encoding() {
    let (store, id) = hfs_bridge::named_streams::Store::default()
        .with_created("profile", 2 * 1024 * 1024, 4096)
        .unwrap();
    let store = store.with_size(id, 2 * 1024 * 1024, 4096).unwrap();
    let start = Instant::now();
    for _ in 0..64 {
        std::hint::black_box(hfs_bridge::named_streams::encode(&store).unwrap());
    }
    println!("ENCODE_64_MS={}", start.elapsed().as_millis());
    let start = Instant::now();
    for _ in 0..64 {
        std::hint::black_box(
            store
                .with_write(id, 10, &[7; 4096], false, false, 4096)
                .unwrap(),
        );
    }
    println!("PLAN_64_MS={}", start.elapsed().as_millis());
}

#[derive(Debug, Default, Clone)]
struct Counts {
    reads: u64,
    read_bytes: u64,
    writes: u64,
    write_bytes: u64,
    seeks: u64,
    syncs: u64,
    io_ns: u128,
    sync_ns: u128,
    operations: Vec<(&'static str, u64, usize)>,
}

// Measure each ordinary copy callback separately. This diagnostic uses only
// the pinned generated catalog fixture and NEW local copies; it cannot open a
// physical device or mount a drive. FileInfo-with-EA mirrors the metadata work
// returned after a native write, rather than timing only the payload editor.
#[test]
#[ignore = "explicit generated-image copy-callback I/O diagnostic"]
fn profile_regular_copy_callbacks() {
    use sha2::{Digest, Sha256};
    let run_id = std::env::var("HFS_PROFILE_RUN").expect("explicit fresh run name");
    assert!(
        !run_id.is_empty()
            && run_id.len() < 40
            && run_id
                .bytes()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
    );
    let base = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("artifacts/milestone-91");
    let source = base.join("catalog-fixture-ownership-v3/source.img");
    let bytes = std::fs::read(&source).unwrap();
    assert_eq!(bytes.len(), 512 * 1024 * 1024);
    let expected = "04731453c15aaec1e1069e2e57718557f42f0edd4913db4ff2aadc8cf3602882";
    assert_eq!(format!("{:x}", Sha256::digest(&bytes)), expected);
    let output = base.join(run_id);
    std::fs::create_dir(&output).unwrap();
    let chunk_kib = std::env::var("HFS_PROFILE_CHUNK_KIB")
        .unwrap_or_else(|_| "128".into())
        .parse::<usize>()
        .unwrap();
    assert!(matches!(chunk_kib, 128 | 1024));
    fn report(kind: &str, part: u64, stage: &str, elapsed: u128, counts: &Counts) {
        let mut summary = counts.clone();
        summary.operations.clear();
        println!(
            "COPY_CALLBACK kind={kind} part={part} stage={stage} elapsed_ns={elapsed} {summary:?}"
        );
        if part == 1 {
            for (operation, offset, length) in &counts.operations {
                println!(
                    "COPY_IO kind={kind} part={part} stage={stage} op={operation} offset={offset} length={length}"
                );
            }
        }
    }
    fn measure<D: BlockDevice>(kind: &str, device: D, chunk_kib: usize) {
        let counts = Arc::new(Mutex::new(Counts::default()));
        let mut a = Adapter::from_device(Meter {
            inner: device,
            counts: counts.clone(),
            position: 0,
        })
        .unwrap();
        let request = OpenRequest {
            access: Access::ALL,
            ..Default::default()
        };
        let handle = a
            .create("\\Large\\profile-copy.bin", Kind::File, request)
            .unwrap();
        a.set_allocation_size(handle, 16 * 1024 * 1024).unwrap();
        a.set_size(handle, 16 * 1024 * 1024).unwrap();
        let payload = vec![0x73; chunk_kib * 1024];
        for part in 0..8 {
            *counts.lock().unwrap() = Counts::default();
            let clock = Instant::now();
            assert_eq!(
                a.write(handle, part * payload.len() as u64, &payload, false, false)
                    .unwrap(),
                payload.len()
            );
            report(
                kind,
                part,
                "write",
                clock.elapsed().as_nanos(),
                &counts.lock().unwrap(),
            );
            *counts.lock().unwrap() = Counts::default();
            let clock = Instant::now();
            let info = a.file_info_with_ea(handle).unwrap();
            assert_eq!(info.size, 16 * 1024 * 1024);
            report(
                kind,
                part,
                "file-info-ea",
                clock.elapsed().as_nanos(),
                &counts.lock().unwrap(),
            );
        }
        let mut actual = vec![0; 8 * payload.len()];
        assert_eq!(a.read(handle, 0, &mut actual).unwrap(), actual.len());
        assert!(actual.iter().all(|&byte| byte == 0x73));
        a.cleanup(handle, false).unwrap();
        a.close(handle).unwrap();
        let reference = a.open("\\reference.txt", request).unwrap();
        let mut original = [0; 19];
        assert_eq!(a.read(reference, 0, &mut original).unwrap(), 19);
        assert_eq!(&original, b"generated reference");
        a.cleanup(reference, false).unwrap();
        a.close(reference).unwrap();
    }
    measure("MEMORY", MemoryBackend::from_bytes(bytes), chunk_kib);
    measure(
        "IMAGE",
        Image::copy_new(&source, &output.join("copy.img"), 0, None).unwrap(),
        chunk_kib,
    );
    assert_eq!(
        format!("{:x}", Sha256::digest(std::fs::read(&source).unwrap())),
        expected
    );
    println!(
        "COPY_CALLBACK_SCOPE: generated catalog fixture; engine/image calls, not physical Toshiba throughput; payload/reference/source checks passed"
    );
}
struct Meter<D> {
    inner: D,
    counts: Arc<Mutex<Counts>>,
    position: u64,
}
impl<D: Read> Read for Meter<D> {
    fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
        let start = Instant::now();
        let result = self.inner.read(b);
        let elapsed = start.elapsed().as_nanos();
        let mut c = self.counts.lock().unwrap();
        c.reads += 1;
        c.read_bytes += *result.as_ref().unwrap_or(&0) as u64;
        c.operations
            .push(("R", self.position, *result.as_ref().unwrap_or(&0)));
        self.position += *result.as_ref().unwrap_or(&0) as u64;
        c.io_ns += elapsed;
        result
    }
}
impl<D: Write> Write for Meter<D> {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        let start = Instant::now();
        let result = self.inner.write(b);
        let elapsed = start.elapsed().as_nanos();
        let mut c = self.counts.lock().unwrap();
        c.writes += 1;
        c.write_bytes += *result.as_ref().unwrap_or(&0) as u64;
        c.operations
            .push(("W", self.position, *result.as_ref().unwrap_or(&0)));
        self.position += *result.as_ref().unwrap_or(&0) as u64;
        c.io_ns += elapsed;
        result
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}
impl<D: Seek> Seek for Meter<D> {
    fn seek(&mut self, p: SeekFrom) -> io::Result<u64> {
        let start = Instant::now();
        let result = self.inner.seek(p);
        let elapsed = start.elapsed().as_nanos();
        let mut c = self.counts.lock().unwrap();
        c.seeks += 1;
        if let Ok(position) = result {
            self.position = position;
        }
        c.io_ns += elapsed;
        result
    }
}
impl<D: BlockDevice> BlockDevice for Meter<D> {
    fn block_size(&self) -> u32 {
        self.inner.block_size()
    }
    fn total_size(&self) -> u64 {
        self.inner.total_size()
    }
    fn sync(&mut self) -> fstool::Result<()> {
        let start = Instant::now();
        let result = self.inner.sync();
        let elapsed = start.elapsed().as_nanos();
        let mut c = self.counts.lock().unwrap();
        c.syncs += 1;
        c.sync_ns += elapsed;
        result
    }
}
fn run<D: BlockDevice>(kind: &str, device: D) {
    let counts = Arc::new(Mutex::new(Counts::default()));
    let mut a = Adapter::from_device(Meter {
        inner: device,
        counts: counts.clone(),
        position: 0,
    })
    .unwrap();
    let all = OpenRequest {
        access: Access::ALL,
        ..Default::default()
    };
    let base = a.create("\\profile", Kind::File, all).unwrap();
    let stream = a.create("\\profile:stream", Kind::File, all).unwrap();
    let mut expected = vec![0x73; 2 * 1024 * 1024];
    a.write(stream, 0, &expected, false, false).unwrap();
    *counts.lock().unwrap() = Counts::default();
    let start = Instant::now();
    for i in 0..16 {
        let offset = i * 65537;
        let data = vec![i as u8; 4096];
        a.write(stream, offset as u64, &data, false, false).unwrap();
        expected[offset..offset + data.len()].copy_from_slice(&data);
    }
    println!(
        "PROFILE_{kind}: elapsed_ms={} {:?}",
        start.elapsed().as_millis(),
        counts.lock().unwrap()
    );
    let mut actual = vec![0; expected.len()];
    assert_eq!(a.read(stream, 0, &mut actual).unwrap(), expected.len());
    assert_eq!(actual, expected);
    for handle in [stream, base] {
        a.cleanup(handle, false).unwrap();
        a.close(handle).unwrap();
    }
}

#[test]
#[ignore = "explicit bounded diagnostic writes two new generated image files"]
fn profile_sixteen_small_writes_to_large_stream() {
    let run_id = std::env::var("HFS_PROFILE_RUN").expect("explicit fresh run name");
    assert!(
        !run_id.is_empty()
            && run_id.len() < 40
            && run_id
                .bytes()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
    );
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("artifacts/milestone-80");
    let out = root.join(run_id);
    std::fs::create_dir(&out).unwrap();
    let mut memory = MemoryBackend::new(32 * 1024 * 1024);
    let mut fs = HfsPlus::format(
        &mut memory,
        &FormatOpts {
            journaled: true,
            ..Default::default()
        },
    )
    .unwrap();
    fs.flush(&mut memory).unwrap();
    drop(fs);
    let bytes = memory.into_bytes();
    let source = out.join("source.img");
    let output = out.join("copy.img");
    let mut file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&source)
        .unwrap();
    file.write_all(&bytes).unwrap();
    file.sync_all().unwrap();
    drop(file);
    run("MEMORY", MemoryBackend::from_bytes(bytes.clone()));
    run("IMAGE", Image::copy_new(&source, &output, 0, None).unwrap());
    assert_eq!(std::fs::read(source).unwrap(), bytes);
    // Compare the same workload against the actual native acceptance fixture.
    let native_source = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("artifacts/milestone-79/packaged-hfs/source.img");
    let native_bytes = std::fs::read(&native_source).unwrap();
    run(
        "NATIVE_FIXTURE",
        Image::copy_new(&native_source, &out.join("native-fixture.img"), 0, None).unwrap(),
    );
    assert_eq!(std::fs::read(native_source).unwrap(), native_bytes);
}
