//! Multi-identity attribute publication, independently observed after reopen.
use fstool::{
    block::{BlockDevice, MemoryBackend},
    fs::hfs_plus::{FormatOpts, HfsPlus, volume_header::read_volume_header},
};
use hfs_bridge::{engine, volume};
use std::io::{Read, Write};
#[path = "support/fault_disk.rs"]
mod fault;
#[path = "support/attribute_wire.rs"]
#[allow(dead_code)]
mod wire;
use fault::Disk;

const MARKER: &str = "org.hfsbridge.test.generation";
const VALUE: &[u8] = b"new generation, not a timestamp record";
const ATTR: &str = "com.example.note";

fn id(fs: &HfsPlus, path: &str) -> u32 {
    volume::be32(&fs.catalog_record(path).unwrap(), 8)
}
fn fixture(journaled: bool, sensitive: bool, existing: bool) -> Vec<u8> {
    let mut disk = MemoryBackend::new(8 * 1024 * 1024);
    let mut fs = HfsPlus::format(
        &mut disk,
        &FormatOpts {
            journaled,
            ..Default::default()
        },
    )
    .unwrap();
    fs.create_dir(&mut disk, "/folder", 0o755, 501, 20, 1_700_000_000)
        .unwrap();
    for path in ["/victim", "/survivor", "/untouched"] {
        fs.create_file(
            &mut disk,
            path,
            &mut &b"unchanged data"[..],
            14,
            0o644,
            501,
            20,
            1_700_000_000,
        )
        .unwrap();
    }
    fs.flush(&mut disk).unwrap();
    let mut resource = fs
        .open_resource_fork_rw(&mut disk, std::path::Path::new("/survivor"))
        .unwrap();
    resource.write_all(b"user resource").unwrap();
    resource.sync().unwrap();
    drop(resource);
    if existing {
        for path in ["/victim", "/untouched"] {
            let cnid = id(&fs, path);
            fs.set_inline_attribute(&mut disk, cnid, ATTR, Some(&vec![0x5a; 9001]))
                .unwrap();
            fs.flush(&mut disk).unwrap();
        }
    }
    fs.flush(&mut disk).unwrap();
    let mut bytes = disk.into_bytes();
    if sensitive {
        bytes[1024..1026].copy_from_slice(b"HX");
        bytes[1026..1028].copy_from_slice(&5u16.to_be_bytes());
        let catalog = volume::be32(&bytes, 1312) as usize * 4096;
        bytes[catalog + 51] = 0xbc;
        let alternate = bytes.len() - 1024;
        let header = bytes[1024..1536].to_vec();
        bytes[alternate..alternate + 512].copy_from_slice(&header);
        let mut disk = MemoryBackend::from_bytes(bytes);
        let mut fs = HfsPlus::open(&mut disk).unwrap();
        fs.set_catalog_times(2, [None, None, None, Some(1_700_000_000)])
            .unwrap();
        fs.flush(&mut disk).unwrap();
        bytes = disk.into_bytes();
    }
    bytes
}
fn stage(fs: &mut HfsPlus, disk: &mut dyn BlockDevice) {
    let file = id(fs, "/survivor");
    let folder = id(fs, "/folder");
    fs.remove(disk, "/victim").unwrap();
    fs.set_small_attributes_batch(
        disk,
        &[
            (2, MARKER, Some(VALUE)),
            (file, ATTR, Some(b"first")),
            (folder, ATTR, Some(b"folder value")),
            (file, "com.example.CASE", Some(b"upper")),
            (file, "com.example.case", Some(b"lower")),
        ],
    )
    .unwrap();
}
#[derive(Debug, PartialEq)]
struct Observation {
    catalogs: Vec<Option<Vec<u8>>>,
    values: Vec<Option<Vec<u8>>>,
    free: u32,
    generation: u32,
}
fn observe(disk: &mut dyn BlockDevice) -> Observation {
    // Explicit test-only journal replay. The production checked opener refuses
    // dirty journals instead of silently repairing the source.
    let fs = HfsPlus::open(disk).unwrap();
    let header = read_volume_header(disk).unwrap();
    let mut catalogs = vec![Some(fs.catalog_record_cnid(2).unwrap())];
    let mut values = vec![fs.inline_attribute(disk, 2, MARKER).unwrap()];
    for path in ["/victim", "/survivor", "/folder", "/untouched"] {
        let body = fs.catalog_record(path).ok();
        if let Some(ref body) = body {
            let cnid = volume::be32(body, 8);
            values.push(fs.inline_attribute(disk, cnid, ATTR).unwrap());
            if path == "/survivor" {
                for name in ["com.example.CASE", "com.example.case"] {
                    values.push(fs.inline_attribute(disk, cnid, name).unwrap());
                }
                let mut resource = Vec::new();
                fs.open_resource_fork_reader(disk, path)
                    .unwrap()
                    .read_to_end(&mut resource)
                    .unwrap();
                assert_eq!(resource, b"user resource");
            }
            if path != "/folder" {
                let mut payload = Vec::new();
                fs.open_file_reader(disk, path)
                    .unwrap()
                    .read_to_end(&mut payload)
                    .unwrap();
                assert_eq!(payload, b"unchanged data");
            }
        } else {
            assert_eq!(path, "/victim");
            values.push(None);
        }
        catalogs.push(body);
    }
    let mut primary = [0; 512];
    let mut alternate = [0; 512];
    disk.read_at(1024, &mut primary).unwrap();
    disk.read_at(disk.total_size() - 1024, &mut alternate)
        .unwrap();
    assert_eq!(primary, alternate);
    Observation {
        catalogs,
        values,
        free: header.free_blocks,
        generation: volume::be32(&primary, 68),
    }
}
fn retain(name: &str, bytes: &[u8]) {
    if let Some(directory) = std::env::var_os("HFS_ATTRIBUTE_BATCH_ARTIFACT_DIR") {
        std::fs::create_dir_all(&directory).unwrap();
        let path = std::path::PathBuf::from(directory).join(name);
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .unwrap();
        file.write_all(bytes).unwrap();
        file.sync_all().unwrap();
    }
}
#[test]
fn batch_deletion_root_and_multiple_entries_roundtrip_without_touching_other_forks() {
    for journaled in [false, true] {
        for sensitive in [false, true] {
            for existing in [false, true] {
                let input = fixture(journaled, sensitive, existing);
                let mut disk = MemoryBackend::from_bytes(input.clone());
                let mut fs = engine::open_checked(&mut disk).unwrap();
                let original_count = volume::be32(&input, 1092);
                stage(&mut fs, &mut disk);
                assert!(disk.as_slice() == input, "staging wrote device bytes");
                assert!(fs.remove(&mut disk, "/untouched").is_err());
                fs.flush(&mut disk).unwrap();
                let observed = observe(&mut disk);
                assert!(observed.catalogs[1].is_none());
                assert_eq!(observed.values[0], Some(VALUE.to_vec()));
                assert_eq!(observed.generation, original_count.wrapping_add(1));
                let old_free = volume::be32(&input, 1072);
                assert_eq!(
                    observed.free,
                    if existing { old_free + 4 } else { old_free - 7 }
                );
                for index in [0, 2, 3] {
                    assert_eq!(
                        volume::be16(observed.catalogs[index].as_ref().unwrap(), 2) & 4,
                        4
                    );
                }
                let records = wire::audit_initialized(disk.as_slice());
                let victim = id(
                    &HfsPlus::open(&mut MemoryBackend::from_bytes(input)).unwrap(),
                    "/victim",
                );
                assert!(!records.iter().any(|r| volume::be32(r, 4) == victim));
                retain(
                    &format!("batch-{journaled}-{sensitive}-{existing}.img"),
                    disk.as_slice(),
                );
                let committed = disk.as_slice().to_vec();
                fs.flush(&mut disk).unwrap();
                assert!(
                    disk.as_slice() == committed,
                    "unchanged flush mutated the volume"
                );
                let file = id(&fs, "/survivor");
                fs.set_small_attributes_batch(
                    &mut disk,
                    &[
                        (file, ATTR, None),
                        (2, MARKER, Some(b"next")),
                        (file, "com.example.CASE", None),
                        (file, "com.example.case", None),
                    ],
                )
                .unwrap();
                fs.flush(&mut disk).unwrap();
                assert_eq!(
                    volume::be16(&fs.catalog_record("/survivor").unwrap(), 2) & 4,
                    0
                );
                assert!(fs.attribute_names(&mut disk, file).unwrap().is_empty());
                assert_eq!(
                    fs.inline_attribute(&mut disk, 2, MARKER).unwrap(),
                    Some(b"next".to_vec())
                );
            }
        }
    }
}
#[test]
fn invalid_batch_members_cannot_publish_a_valid_prefix() {
    let input = fixture(true, false, false);
    let mut disk = MemoryBackend::from_bytes(input.clone());
    let mut fs = HfsPlus::open(&mut disk).unwrap();
    let file = id(&fs, "/survivor");
    let huge = vec![0; 3803];
    for invalid in [
        (3, ATTR, Some(&b"invalid"[..])),
        (file, "", Some(&b"invalid"[..])),
        (file, "com.apple.decmpfs", None),
        (file, "com.apple.FinderInfo", None),
        (file, "com.apple.ResourceFork", None),
        (file, "com.apple.system.Security", None),
        (file, ATTR, Some(huge.as_slice())),
        (2, MARKER, Some(&b"duplicate"[..])),
    ] {
        assert!(
            fs.set_small_attributes_batch(&mut disk, &[(2, MARKER, Some(VALUE)), invalid])
                .is_err()
        );
        fs.flush(&mut disk).unwrap();
        assert!(disk.as_slice() == input);
    }
    assert!(
        fs.set_inline_attribute(&mut disk, 2, MARKER, Some(VALUE))
            .is_err(),
        "legacy root gate changed"
    );
    let names: Vec<_> = (0..257).map(|i| format!("attr{i}")).collect();
    let changes: Vec<_> = names
        .iter()
        .map(|name| (file, name.as_str(), Some(VALUE)))
        .collect();
    assert!(fs.set_small_attributes_batch(&mut disk, &changes).is_err());
    // Legal count/size but insufficient tree capacity must also fail preflight.
    let payload = vec![0; 3802];
    let changes: Vec<_> = names[..16]
        .iter()
        .map(|name| (file, name.as_str(), Some(payload.as_slice())))
        .collect();
    assert!(fs.set_small_attributes_batch(&mut disk, &changes).is_err());
    fs.flush(&mut disk).unwrap();
    assert!(disk.as_slice() == input);
}
#[test]
fn refused_batch_preserves_preexisting_deletion_and_fork_target() {
    let input = fixture(true, false, true);
    let mut disk = MemoryBackend::from_bytes(input.clone());
    let mut fs = HfsPlus::open(&mut disk).unwrap();
    let other = id(&fs, "/untouched");
    fs.remove(&mut disk, "/victim").unwrap();
    assert!(
        fs.set_small_attributes_batch(
            &mut disk,
            &[(2, MARKER, Some(VALUE)), (other, ATTR, Some(b"small"))]
        )
        .is_err()
    );
    assert!(disk.as_slice() == input);
    fs.flush(&mut disk).unwrap();
    let fs = HfsPlus::open(&mut disk).unwrap();
    assert!(fs.catalog_record("/victim").is_err());
    assert!(fs.inline_attribute(&mut disk, 2, MARKER).unwrap().is_none());
    assert_eq!(
        fs.inline_attribute(&mut disk, other, ATTR).unwrap(),
        Some(vec![0x5a; 9001])
    );
}
#[test]
fn absent_removals_and_full_disk_refusals_preserve_bytes_and_catalog_flags() {
    let input = fixture(true, false, false);
    let mut disk = MemoryBackend::from_bytes(input.clone());
    let mut fs = HfsPlus::open(&mut disk).unwrap();
    fs.set_small_attributes_batch(&mut disk, &[(2, MARKER, None)])
        .unwrap();
    fs.flush(&mut disk).unwrap();
    assert!(disk.as_slice() == input);
    let free = read_volume_header(&mut disk).unwrap().free_blocks;
    fs.set_data_allocation(
        &mut disk,
        std::path::Path::new("/untouched"),
        u64::from(free + 1) * 4096,
        false,
    )
    .unwrap();
    assert_eq!(read_volume_header(&mut disk).unwrap().free_blocks, 0);
    let before = disk.as_slice().to_vec();
    let root = fs.catalog_record_cnid(2).unwrap();
    assert!(
        fs.set_small_attributes_batch(&mut disk, &[(2, MARKER, Some(VALUE))])
            .is_err()
    );
    fs.flush(&mut disk).unwrap();
    assert!(disk.as_slice() == before);
    assert_eq!(fs.catalog_record_cnid(2).unwrap(), root);
}
#[test]
fn new_entry_batch_and_pending_edit_gates_preserve_one_publication() {
    let input = fixture(true, false, false);
    let mut disk = MemoryBackend::from_bytes(input.clone());
    let mut fs = HfsPlus::open(&mut disk).unwrap();
    let created = fs
        .create_file(
            &mut disk,
            "/new",
            &mut &[][..],
            0,
            0o644,
            501,
            20,
            1_700_000_000,
        )
        .unwrap();
    fs.set_small_attributes_batch(
        &mut disk,
        &[(2, MARKER, Some(VALUE)), (created, ATTR, Some(b"new file"))],
    )
    .unwrap();
    assert!(
        fs.set_small_attributes_batch(&mut disk, &[(2, MARKER, Some(b"overwrite pending"))])
            .is_err()
    );
    assert!(
        fs.set_inline_attribute(&mut disk, created, ATTR, Some(b"overwrite pending"))
            .is_err()
    );
    assert!(fs.remove(&mut disk, "/victim").is_err());
    assert!(disk.as_slice() == input);
    fs.flush(&mut disk).unwrap();
    let fs = HfsPlus::open(&mut disk).unwrap();
    assert_eq!(
        fs.inline_attribute(&mut disk, created, ATTR).unwrap(),
        Some(b"new file".to_vec())
    );
    assert_eq!(
        fs.inline_attribute(&mut disk, 2, MARKER).unwrap(),
        Some(VALUE.to_vec())
    );
    assert!(fs.catalog_record("/victim").is_ok());
    assert_eq!(
        volume::be32(disk.as_slice(), 1092),
        volume::be32(&input, 1092).wrapping_add(1)
    );
}
fn attempt(input: &[u8], stop: Option<usize>) -> (bool, Disk) {
    let mut disk = Disk::new(input);
    let mut fs = engine::open_checked(&mut disk).unwrap();
    disk.arm(stop);
    stage(&mut fs, &mut disk);
    assert_eq!(disk.0.lock().unwrap().calls, 0);
    let success = fs.flush(&mut disk).is_ok();
    if !success {
        let calls = disk.0.lock().unwrap().calls;
        assert!(fs.flush(&mut disk).is_err());
        assert_eq!(
            disk.0.lock().unwrap().calls,
            calls,
            "failed flush retried writes"
        );
    }
    (success, disk)
}
#[test]
fn batch_and_deletion_are_atomic_across_commit_and_replay_failures() {
    let mut commits = 0;
    let mut replays = 0;
    for sensitive in [false, true] {
        for existing in [false, true] {
            let input = fixture(true, sensitive, existing);
            let info = volume::be32(&input, 1036) as usize * volume::be32(&input, 1064) as usize;
            let journal = volume::be64(&input, info + 36) as usize;
            let old = observe(&mut Disk::new(&input));
            let (pass, complete) = attempt(&input, None);
            assert!(pass);
            let count = complete.0.lock().unwrap().calls;
            let new = observe(&mut Disk::new(&complete.0.lock().unwrap().durable));
            assert_ne!(old, new);
            let mut pending = None;
            for stop in 0..count {
                let (pass, interrupted) = attempt(&input, Some(stop));
                assert!(!pass);
                for policy in 0..6 {
                    let bytes = interrupted.snapshot(policy, journal);
                    if matches!(
                        volume::inspect(&mut Disk::new(&bytes)).unwrap().journal,
                        volume::Journal::Pending { .. }
                    ) {
                        pending.get_or_insert_with(|| bytes.clone());
                        let guarded = Disk::new(&bytes);
                        guarded.arm(Some(0));
                        assert!(engine::open_checked(&mut guarded.clone()).is_err());
                        assert_eq!(guarded.0.lock().unwrap().calls, 0);
                    }
                    let actual = observe(&mut Disk::new(&bytes));
                    assert!(
                        actual == old || actual == new,
                        "partial batch: {sensitive}/{existing}/{stop}/{policy}"
                    );
                    commits += 1;
                }
            }
            let pending = pending.expect("no pending journal observed");
            retain(
                &format!("batch-pending-{sensitive}-{existing}.img"),
                &pending,
            );
            let mut replay = Disk::new(&pending);
            HfsPlus::open(&mut replay).unwrap();
            let count = replay.0.lock().unwrap().calls;
            for stop in 0..count {
                let mut interrupted = Disk::new(&pending);
                interrupted.arm(Some(stop));
                assert!(HfsPlus::open(&mut interrupted).is_err());
                for policy in 0..6 {
                    assert_eq!(
                        observe(&mut Disk::new(&interrupted.snapshot(policy, journal))),
                        new
                    );
                    replays += 1;
                }
            }
        }
    }
    println!(
        "ATTRIBUTE_BATCH_MATRIX: {commits} commit + {replays} replay persistence checks; 4 scenarios"
    );
}
