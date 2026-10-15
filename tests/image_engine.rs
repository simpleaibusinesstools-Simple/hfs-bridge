use fstool::block::BlockDevice;
use fstool::fs::hfs_plus::{FormatOpts, HfsPlus};
use hfs_bridge::{
    engine::{self, Mutation},
    image::{Image, validate_path},
    volume,
};
use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct TestDir {
    path: PathBuf,
    root: PathBuf,
}
impl TestDir {
    fn new() -> Self {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join(".cache/tests");
        fs::create_dir_all(&root).unwrap();
        let path = root.join(format!(
            "{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        let root = fs::canonicalize(root).unwrap();
        Self { path, root }
    }
    fn file(&self, name: &str) -> PathBuf {
        self.path.join(name)
    }
}
impl Drop for TestDir {
    fn drop(&mut self) {
        // Delete only this test's directory after checking the resolved target.
        if let Ok(resolved) = fs::canonicalize(&self.path)
            && resolved.starts_with(&self.root)
            && resolved != self.root
        {
            let _ = fs::remove_dir_all(resolved);
        }
    }
}
fn hash(path: &Path) -> String {
    engine::sha256(&mut fs::File::open(path).unwrap()).unwrap()
}

#[test]
fn volume_json_reports_unclean_images_without_repair_or_catalog_access() {
    let dir = TestDir::new();
    let invoke = |args: &[&str]| {
        std::process::Command::new(env!("CARGO_BIN_EXE_hfs-bridge"))
            .args(args)
            .output()
            .unwrap()
    };
    for journaled in [false, true] {
        let source = dir.file(if journaled {
            "journaled.img"
        } else {
            "plain.img"
        });
        engine::fixture(&source, journaled).unwrap();
        let before = hash(&source);
        let inspected = invoke(&["inspect", source.to_str().unwrap(), "--json"]);
        assert!(inspected.status.success());
        let json = String::from_utf8(inspected.stdout).unwrap();
        assert!(json.starts_with("{\"schema\":1,\"operation\":\"read-only volume inspection\""));
        assert!(json.contains("\"signature\":18475,\"version\":4"));
        assert!(json.contains("\"engineAccess\":true,\"physicalWrites\":false"));
        assert!(json.contains(if journaled {
            "\"journal\":\"clean\""
        } else {
            "\"journal\":\"absent\""
        }));
        assert_eq!(hash(&source), before);

        let dirty = dir.file(if journaled {
            "dirty-journaled.img"
        } else {
            "dirty-plain.img"
        });
        fs::copy(&source, &dirty).unwrap();
        let mut file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&dirty)
            .unwrap();
        let size = file.metadata().unwrap().len();
        for position in [1028, size - 1020] {
            let mut raw = [0; 4];
            file.seek(SeekFrom::Start(position)).unwrap();
            file.read_exact(&mut raw).unwrap();
            let attributes = u32::from_be_bytes(raw) & !volume::UNMOUNTED;
            file.seek(SeekFrom::Start(position)).unwrap();
            file.write_all(&attributes.to_be_bytes()).unwrap();
        }
        file.sync_all().unwrap();
        drop(file);
        let dirty_before = hash(&dirty);
        let inspected = invoke(&["inspect", dirty.to_str().unwrap(), "--json"]);
        assert!(inspected.status.success());
        assert!(
            String::from_utf8(inspected.stdout)
                .unwrap()
                .contains("\"engineAccess\":false,\"physicalWrites\":false")
        );
        assert!(!invoke(&["list", dirty.to_str().unwrap()]).status.success());
        assert_eq!(hash(&dirty), dirty_before);
        assert_eq!(hash(&source), before);

        let refused = dir.file("refused.img");
        for arguments in [
            vec!["fixture", refused.to_str().unwrap(), "--json"],
            vec!["inspect", source.to_str().unwrap(), "--json", "--json"],
            vec![
                "inspect",
                source.to_str().unwrap(),
                "--json",
                "--output",
                refused.to_str().unwrap(),
            ],
        ] {
            assert!(!invoke(&arguments).status.success());
            assert!(!refused.exists());
        }
        assert_eq!(hash(&source), before);
    }
}

#[test]
fn attribute_cli_new_copies_verify_exact_values_metadata_and_source_safety() {
    let dir = TestDir::new();
    let source = dir.file("attribute-source.img");
    engine::fixture(&source, true).unwrap();
    let source_hash = hash(&source);
    let before = engine::snapshot(&source, "/Transfer/hello.txt", &[], 0, None).unwrap();
    let payload = dir.file("attribute-value.bin");
    let value = [0, 0xff, 0x7f, 0x80, 1];
    fs::write(&payload, value).unwrap();
    let set = dir.file("attribute-set.img");
    let invoke = |args: &[&str]| {
        std::process::Command::new(env!("CARGO_BIN_EXE_hfs-bridge"))
            .args(args)
            .output()
            .unwrap()
    };
    let result = invoke(&[
        "attribute-set",
        source.to_str().unwrap(),
        payload.to_str().unwrap(),
        "/Transfer/hello.txt",
        "com.example.CASE",
        "--output",
        set.to_str().unwrap(),
    ]);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let extracted = dir.file("attribute-extracted.bin");
    assert!(
        invoke(&[
            "attribute-extract",
            set.to_str().unwrap(),
            "/Transfer/hello.txt",
            "com.example.CASE",
            extracted.to_str().unwrap()
        ])
        .status
        .success()
    );
    assert_eq!(fs::read(&extracted).unwrap(), value);
    assert!(
        !invoke(&[
            "attribute-extract",
            set.to_str().unwrap(),
            "/Transfer/hello.txt",
            "com.example.case",
            dir.file("absent.bin").to_str().unwrap()
        ])
        .status
        .success()
    );
    assert!(!dir.file("absent.bin").exists());
    assert!(
        !invoke(&[
            "attribute-extract",
            set.to_str().unwrap(),
            "/Transfer/hello.txt",
            "com.example.CASE",
            extracted.to_str().unwrap()
        ])
        .status
        .success()
    );
    let after =
        engine::snapshot(&set, "/Transfer/hello.txt", &["com.example.CASE"], 0, None).unwrap();
    assert_eq!(
        (after.cnid, after.uid, after.gid, after.mode),
        (before.cnid, before.uid, before.gid, before.mode)
    );
    assert_eq!(after.data_sha256, before.data_sha256);
    assert_eq!(after.resource_sha256, before.resource_sha256);
    let removed = dir.file("attribute-removed.img");
    assert!(
        invoke(&[
            "attribute-remove",
            set.to_str().unwrap(),
            "/Transfer/hello.txt",
            "com.example.CASE",
            "--output",
            removed.to_str().unwrap()
        ])
        .status
        .success()
    );
    assert_eq!(
        engine::snapshot(&removed, "/Transfer/hello.txt", &[], 0, None).unwrap(),
        before
    );
    assert!(
        !invoke(&[
            "attribute-set",
            source.to_str().unwrap(),
            payload.to_str().unwrap(),
            "/Transfer/hello.txt",
            "com.example.CASE",
            "--output",
            set.to_str().unwrap()
        ])
        .status
        .success()
    );
    let rejected = dir.file("attribute-reserved.img");
    assert!(
        !invoke(&[
            "attribute-set",
            source.to_str().unwrap(),
            payload.to_str().unwrap(),
            "/Transfer/hello.txt",
            "com.apple.decmpfs",
            "--output",
            rejected.to_str().unwrap()
        ])
        .status
        .success()
    );
    assert!(
        !rejected.exists(),
        "reserved metadata was refused before output creation"
    );
    assert_eq!(hash(&source), source_hash);
}

#[test]
fn resource_cli_edits_new_copies_preserves_data_and_refuses_existing_outputs() {
    let dir = TestDir::new();
    let source = dir.file("resource-source.img");
    let payload = dir.file("resource-payload.bin");
    engine::fixture(&source, true).unwrap();
    let before = hash(&source);
    let snapshot = engine::snapshot(&source, "/Transfer/hello.txt", &[], 0, None).unwrap();
    let bytes = (0..100_003)
        .map(|n| ((n * 7) % 256) as u8)
        .collect::<Vec<_>>();
    fs::write(&payload, &bytes).unwrap();
    let invoke = |args: &[&str]| {
        let result = std::process::Command::new(env!("CARGO_BIN_EXE_hfs-bridge"))
            .args(args)
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
    };
    let output = dir.file("resource-output.img");
    invoke(&[
        "resource-overwrite",
        source.to_str().unwrap(),
        payload.to_str().unwrap(),
        "/Transfer/hello.txt",
        "--output",
        output.to_str().unwrap(),
    ]);
    let extracted = dir.file("resource-extracted.bin");
    invoke(&[
        "resource-extract",
        output.to_str().unwrap(),
        "/Transfer/hello.txt",
        extracted.to_str().unwrap(),
    ]);
    assert_eq!(fs::read(&extracted).unwrap(), bytes);
    assert_eq!(
        engine::snapshot(&output, "/Transfer/hello.txt", &[], 0, None)
            .unwrap()
            .data_sha256,
        snapshot.data_sha256
    );
    let patched = dir.file("resource-patched.img");
    fs::write(&payload, b"PATCH").unwrap();
    invoke(&[
        "resource-patch",
        output.to_str().unwrap(),
        payload.to_str().unwrap(),
        "/Transfer/hello.txt",
        "--at",
        "100008",
        "--output",
        patched.to_str().unwrap(),
    ]);
    let mut expected = bytes;
    expected.resize(100008, 0);
    expected.extend_from_slice(b"PATCH");
    let extracted = dir.file("resource-patch-extracted.bin");
    engine::extract_resource(&patched, "/Transfer/hello.txt", &extracted, 0, None).unwrap();
    assert_eq!(fs::read(&extracted).unwrap(), expected);
    let truncated = dir.file("resource-truncated.img");
    invoke(&[
        "resource-truncate",
        patched.to_str().unwrap(),
        "/Transfer/hello.txt",
        "0",
        "--output",
        truncated.to_str().unwrap(),
    ]);
    let after = engine::snapshot(&truncated, "/Transfer/hello.txt", &[], 0, None).unwrap();
    assert_eq!(after.data_sha256, snapshot.data_sha256);
    assert_eq!(after.resource_sha256, None);
    assert_eq!(before, hash(&source));
    let output_hash = hash(&output);
    assert!(
        engine::edit_fork(
            &source,
            &output,
            0,
            None,
            "/Transfer/hello.txt",
            engine::FileEdit::Overwrite(&payload),
            engine::FileFork::Resource
        )
        .is_err()
    );
    assert_eq!(output_hash, hash(&output));
    let absent = dir.file("absent-resource.bin");
    assert!(engine::extract_resource(&truncated, "/Transfer/hello.txt", &absent, 0, None).is_err());
    assert!(!absent.exists());
}

#[test]
fn device_names_and_alternate_streams_are_refused() {
    for name in [
        r"\\.\PhysicalDrive1",
        r"\\?\GLOBALROOT\Device\Harddisk1",
        r"\\server\share\test.img",
        "NUL",
        "con.img",
        "COM1",
        "COM¹.txt",
        "LPT².img",
        "CONIN$",
        "CONOUT$",
        "test.img:stream",
    ] {
        assert!(validate_path(Path::new(name)).is_err(), "{name}");
    }
}
#[test]
fn image_bounds_and_read_only_capability_are_enforced() {
    let dir = TestDir::new();
    let path = dir.file("bounds.img");
    fs::write(&path, (0..32).collect::<Vec<u8>>()).unwrap();
    let before = hash(&path);
    let mut image = Image::read_only(&path, 8, Some(8)).unwrap();
    let mut read = [0; 8];
    image.read_at(0, &mut read).unwrap();
    assert_eq!(read, [8, 9, 10, 11, 12, 13, 14, 15]);
    assert!(image.write_at(0, &[99]).is_err());
    assert!(image.read_at(7, &mut [0; 2]).is_err());
    assert!(image.read_at(u64::MAX, &mut [0; 2]).is_err());
    assert!(image.seek(SeekFrom::Current(-9)).is_err());
    assert!(Image::read_only(&path, 33, None).is_err());
    assert_eq!(before, hash(&path));
}
#[test]
fn writable_copy_cannot_escape_slice_or_replace_existing_files() {
    let dir = TestDir::new();
    let source = dir.file("input.img");
    let output = dir.file("output.img");
    fs::write(&source, [0x55; 32]).unwrap();
    let mut image = Image::copy_new(&source, &output, 8, Some(8)).unwrap();
    image.write_at(0, &[1; 8]).unwrap();
    assert!(image.write_at(7, &[2; 2]).is_err());
    image.sync().unwrap();
    drop(image);
    assert_eq!(fs::read(&source).unwrap(), [0x55; 32]);
    let bytes = fs::read(&output).unwrap();
    assert_eq!(&bytes[..8], &[0x55; 8]);
    assert_eq!(&bytes[8..16], &[1; 8]);
    assert_eq!(&bytes[16..], &[0x55; 16]);
    assert!(Image::create(&output, 32).is_err());
    assert!(Image::copy_new(&source, &output, 0, None).is_err());
}
#[test]
fn formatter_sets_internal_journal_flag_and_external_flag_is_refused() {
    let dir = TestDir::new();
    let mut device = Image::create(&dir.file("upstream.img"), 32 * 1024 * 1024).unwrap();
    let _fs = HfsPlus::format(
        &mut device,
        &FormatOpts {
            journaled: true,
            ..Default::default()
        },
    )
    .unwrap();
    let inspected = volume::inspect(&mut device).unwrap();
    assert!(matches!(inspected.journal, volume::Journal::Clean { .. }));
    let offset =
        u64::from(inspected.header.journal_info_block) * u64::from(inspected.header.block_size);
    device.write_at(offset, &2u32.to_be_bytes()).unwrap();
    assert!(
        volume::inspect(&mut device)
            .unwrap_err()
            .to_string()
            .contains("flags 0x2")
    );
}

fn transfer_round_trip(journaled: bool) {
    let dir = TestDir::new();
    let original = dir.file("original.img");
    let modified = dir.file("modified.img");
    let payload = dir.file("payload.bin");
    let extracted = dir.file("extracted.bin");
    let removed = dir.file("removed.img");
    engine::fixture(&original, journaled).unwrap();
    let before = hash(&original);
    // More than one transfer buffer, with binary data and boundary variation.
    let bytes = (0..200_003)
        .map(|index| ((index * 31 + index / 251) % 256) as u8)
        .collect::<Vec<_>>();
    fs::write(&payload, &bytes).unwrap();
    engine::mutate(
        &original,
        &modified,
        0,
        None,
        Mutation::Put {
            source: &payload,
            destination: "/Transfer/payload.bin",
        },
    )
    .unwrap();
    assert_eq!(
        engine::extract(&modified, "/Transfer/payload.bin", &extracted, 0, None).unwrap(),
        hash(&payload)
    );
    assert_eq!(fs::read(&extracted).unwrap(), bytes);
    assert_eq!(before, hash(&original));
    let before_modified = hash(&modified);
    engine::mutate(
        &modified,
        &removed,
        0,
        None,
        Mutation::Delete("/Transfer/payload.bin"),
    )
    .unwrap();
    assert_eq!(before_modified, hash(&modified));
    assert!(
        engine::list(&removed, "/Transfer", 0, None)
            .unwrap()
            .iter()
            .any(|entry| entry.name == "hello.txt")
    );
    let mut readonly = Image::read_only(&removed, 0, None).unwrap();
    let report = volume::inspect(&mut readonly).unwrap();
    assert_eq!(report.header.attributes & volume::JOURNALED != 0, journaled);
}
#[test]
fn nonjournaled_copy_in_out_and_delete_survive_reopen() {
    transfer_round_trip(false)
}
#[test]
fn journaled_copy_in_out_and_delete_survive_reopen() {
    transfer_round_trip(true)
}
#[test]
fn mkdir_is_persistent_and_overwrites_are_refused() {
    let dir = TestDir::new();
    let original = dir.file("original.img");
    let changed = dir.file("changed.img");
    engine::fixture(&original, false).unwrap();
    engine::mutate(&original, &changed, 0, None, Mutation::Mkdir("/New Folder")).unwrap();
    assert!(
        engine::list(&changed, "/", 0, None)
            .unwrap()
            .iter()
            .any(|entry| entry.name == "New Folder")
    );
    let before = hash(&changed);
    assert!(engine::mutate(&original, &changed, 0, None, Mutation::Mkdir("/Other")).is_err());
    assert_eq!(before, hash(&changed));
}

#[test]
fn image_copy_rename_and_move_preserve_input_and_reopened_payload() {
    let dir = TestDir::new();
    let original = dir.file("rename-original.img");
    let renamed = dir.file("renamed.img");
    let moved = dir.file("moved.img");
    let extracted = dir.file("extracted.txt");
    engine::fixture(&original, true).unwrap();
    let before = hash(&original);
    let mut disk = Image::read_only(&original, 0, None).unwrap();
    let fs = engine::open_checked(&mut disk).unwrap();
    let record = fs.catalog_record("/Transfer/hello.txt").unwrap();
    drop(disk);
    engine::mutate(
        &original,
        &renamed,
        0,
        None,
        Mutation::Rename {
            source: "/transfer/HELLO.txt",
            destination: "/Transfer/Hello.TXT",
        },
    )
    .unwrap();
    let before_renamed = hash(&renamed);
    engine::mutate(
        &renamed,
        &moved,
        0,
        None,
        Mutation::Rename {
            source: "/Transfer",
            destination: "/Archive",
        },
    )
    .unwrap();
    let mut disk = Image::read_only(&moved, 0, None).unwrap();
    let fs = engine::open_checked(&mut disk).unwrap();
    assert_eq!(record, fs.catalog_record("/Archive/Hello.TXT").unwrap());
    assert!(fs.catalog_record("/Transfer").is_err());
    engine::extract(&moved, "/Archive/Hello.TXT", &extracted, 0, None).unwrap();
    assert!(
        std::fs::read_to_string(extracted)
            .unwrap()
            .contains("persistent Windows-to-Mac")
    );
    assert_eq!(before, hash(&original));
    assert_eq!(before_renamed, hash(&renamed));
    let invalid = dir.file("invalid.img");
    assert!(
        engine::mutate(
            &original,
            &invalid,
            0,
            None,
            Mutation::Rename {
                source: "/Transfer/../hello.txt",
                destination: "/dest",
            }
        )
        .is_err()
    );
    assert!(!invalid.exists());
}

#[test]
fn image_file_edits_preserve_input_and_verify_expected_streams() {
    use engine::FileEdit;
    let dir = TestDir::new();
    let original = dir.file("edit-original.img");
    engine::fixture(&original, true).unwrap();
    let input_hash = hash(&original);
    let payload = dir.file("replacement.bin");
    let bytes = (0..200_003)
        .map(|i| ((i * 31 + i / 251) % 256) as u8)
        .collect::<Vec<_>>();
    fs::write(&payload, &bytes).unwrap();
    let replaced = dir.file("replaced.img");
    engine::edit_file(
        &original,
        &replaced,
        0,
        None,
        "/Transfer/hello.txt",
        FileEdit::Overwrite(&payload),
    )
    .unwrap();
    let patch = dir.file("patch.bin");
    fs::write(&patch, b"patch").unwrap();
    let patched = dir.file("patched.img");
    engine::edit_file(
        &replaced,
        &patched,
        0,
        None,
        "/Transfer/hello.txt",
        FileEdit::Patch {
            source: &patch,
            offset: 4094,
        },
    )
    .unwrap();
    let truncated = dir.file("truncated.img");
    engine::edit_file(
        &patched,
        &truncated,
        0,
        None,
        "/Transfer/hello.txt",
        FileEdit::Truncate(4100),
    )
    .unwrap();
    let extracted = dir.file("edited.bin");
    engine::extract(&truncated, "/Transfer/hello.txt", &extracted, 0, None).unwrap();
    let mut expected = bytes[..4100].to_vec();
    expected[4094..4099].copy_from_slice(b"patch");
    assert_eq!(fs::read(extracted).unwrap(), expected);
    assert_eq!(hash(&original), input_hash);
    let empty = dir.file("empty.bin");
    fs::write(&empty, []).unwrap();
    let no_op = dir.file("no-op.img");
    engine::edit_file(
        &truncated,
        &no_op,
        0,
        None,
        "/Transfer/hello.txt",
        FileEdit::Patch {
            source: &empty,
            offset: u64::MAX,
        },
    )
    .unwrap();
    let invalid = dir.file("invalid-edit.img");
    assert!(
        engine::edit_file(
            &original,
            &invalid,
            0,
            None,
            "/Transfer/hello.txt",
            FileEdit::Patch {
                source: &patch,
                offset: u64::MAX
            }
        )
        .is_err()
    );
    assert!(!invalid.exists());
}
#[test]
fn filesystem_paths_are_validated_before_creating_outputs() {
    for path in ["relative", "/", "/../data", "/a/./b", "/a//b", "/nul\0name"] {
        assert!(engine::validate_hfs_path(path).is_err());
    }
    assert!(engine::validate_hfs_path(&format!("/{}", "x".repeat(256))).is_err());
    // These are HFS catalog components, not host paths or alternate streams.
    // The Windows directory view supplies aliases for their forbidden characters.
    for path in ["/x:stream", "/back\\slash"] {
        assert!(engine::validate_hfs_path(path).is_ok());
    }
}

struct FaultDevice {
    image: Image,
    fail_write: bool,
    fail_sync: bool,
}
impl Read for FaultDevice {
    fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
        self.image.read(b)
    }
}
impl Seek for FaultDevice {
    fn seek(&mut self, p: SeekFrom) -> std::io::Result<u64> {
        self.image.seek(p)
    }
}
impl Write for FaultDevice {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        if self.fail_write {
            Err(std::io::Error::other("injected disk write failure"))
        } else {
            self.image.write(b)
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        if self.fail_sync {
            Err(std::io::Error::other("injected disk sync failure"))
        } else {
            self.image.flush()
        }
    }
}
impl BlockDevice for FaultDevice {
    fn block_size(&self) -> u32 {
        512
    }
    fn total_size(&self) -> u64 {
        self.image.total_size()
    }
    fn sync(&mut self) -> fstool::Result<()> {
        Ok(self.flush()?)
    }
}
#[test]
fn metadata_write_and_sync_failures_are_returned_to_the_caller() {
    let dir = TestDir::new();
    for journaled in [false, true] {
        let source = dir.file(&format!("original-{journaled}.img"));
        engine::fixture(&source, journaled).unwrap();
        let before = hash(&source);
        for sync in [false, true] {
            let output = dir.file(&format!("fault-{journaled}-{sync}.img"));
            let image = Image::copy_new(&source, &output, 0, None).unwrap();
            let mut device = FaultDevice {
                image,
                fail_write: false,
                fail_sync: false,
            };
            let mut fs = engine::open_checked(&mut device).unwrap();
            fs.create_dir(&mut device, "/Failure", 0o755, 0, 0, 0)
                .unwrap();
            device.fail_write = !sync;
            device.fail_sync = sync;
            let error = fs.flush(&mut device).unwrap_err();
            assert!(error.to_string().contains("injected"), "{error}");
        }
        assert_eq!(before, hash(&source));
    }
}
