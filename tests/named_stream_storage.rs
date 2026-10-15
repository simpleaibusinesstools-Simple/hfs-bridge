//! Codec publication through the existing HFS attribute transaction. Native
//! stream callbacks are not enabled by these storage-foundation checks.
use fstool::fs::Filesystem;
use fstool::{
    block::{BlockDevice, MemoryBackend},
    fs::hfs_plus::{CatalogUpdate, FormatOpts, HfsPlus, PublicationMetadata},
};
use hfs_bridge::{
    engine,
    named_streams::{self as wire, Store, Stream},
    volume,
};
use std::io::{Read, Write};
#[path = "support/fault_disk.rs"]
mod fault;
use fault::Disk;

fn store(new: bool) -> Store {
    Store {
        next_id: if new { 4 } else { 2 },
        streams: vec![Stream {
            id: if new { 3 } else { 1 },
            name: "Zone.Identifier".into(),
            data: if new {
                vec![29; 20019]
            } else {
                b"old".to_vec()
            },
            allocation: if new { 24576 } else { 4096 },
        }],
    }
}
fn fixture(journaled: bool, existing: bool) -> Vec<u8> {
    let mut d = MemoryBackend::new(8 * 1024 * 1024);
    let mut fs = HfsPlus::format(
        &mut d,
        &FormatOpts {
            journaled,
            ..Default::default()
        },
    )
    .unwrap();
    fs.create_file(
        &mut d,
        "/file",
        &mut &b"unchanged data"[..],
        14,
        0o644,
        501,
        20,
        1_700_000_000,
    )
    .unwrap();
    fs.flush(&mut d).unwrap();
    let id = volume::be32(&fs.catalog_record("/file").unwrap(), 8);
    fs.set_inline_attribute(&mut d, id, "unrelated", Some(b"keep"))
        .unwrap();
    fs.flush(&mut d).unwrap();
    if existing {
        fs.set_inline_attribute(
            &mut d,
            id,
            wire::ATTRIBUTE,
            Some(&wire::encode(&store(false)).unwrap()),
        )
        .unwrap();
        fs.flush(&mut d).unwrap();
    }
    d.into_bytes()
}
fn stage(fs: &mut HfsPlus, d: &mut dyn BlockDevice) {
    stage_store(fs, d, &store(true));
}
fn stage_store(fs: &mut HfsPlus, d: &mut dyn BlockDevice, store: &Store) {
    let id = volume::be32(&fs.catalog_record("/file").unwrap(), 8);
    let bytes = wire::encode(store).unwrap();
    let updates = [CatalogUpdate {
        cnid: id,
        times: [None, None, Some(3_800_000_001), Some(3_800_000_001)],
        attributes: None,
    }];
    fs.set_attributes_with_publication(
        d,
        id,
        PublicationMetadata {
            attributes: &[(wire::ATTRIBUTE, Some(&bytes))],
            catalog: &updates,
            related: &[],
        },
    )
    .unwrap();
}
#[test]
fn planned_stream_edits_publish_complete_old_or_new_containers_at_every_boundary() {
    let before = fixture(true, true);
    let original = store(false);
    let info = volume::be32(&before, 1036) as usize * volume::be32(&before, 1064) as usize;
    let journal = volume::be64(&before, info + 36) as usize;
    let old = observe(&mut Disk::new(&before));
    let edits = [
        (
            "create",
            original.with_created("second", 8192, 4096).unwrap().0,
        ),
        (
            "write",
            original
                .with_write(1, 17003, b"new tail", false, false, 4096)
                .unwrap()
                .0,
        ),
        ("grow", original.with_size(1, 10001, 4096).unwrap()),
        ("truncate", original.with_size(1, 1, 4096).unwrap()),
        ("allocation", original.with_allocation(1, 0, 4096).unwrap()),
        ("remove", original.without(1).unwrap().0),
    ];
    let mut snapshots = 0;
    for (name, planned) in edits {
        let attempt = |stop| {
            let mut disk = Disk::new(&before);
            let mut fs = engine::open_checked(&mut disk).unwrap();
            disk.arm(stop);
            stage_store(&mut fs, &mut disk, &planned);
            assert_eq!(disk.0.lock().unwrap().calls, 0);
            let pass = fs.flush(&mut disk).is_ok();
            if !pass {
                let calls = disk.0.lock().unwrap().calls;
                assert!(fs.flush(&mut disk).is_err());
                assert_eq!(disk.0.lock().unwrap().calls, calls);
            }
            (pass, disk)
        };
        let (pass, complete) = attempt(None);
        assert!(pass);
        let new = observe(&mut Disk::new(&complete.snapshot(1, journal)));
        assert_eq!(new, (Some(planned.clone()), 3_800_000_001, 3_800_000_001));
        retain(
            &format!("planned-{name}.img"),
            &complete.snapshot(1, journal),
        );
        for stop in 0..complete.0.lock().unwrap().calls {
            let (pass, interrupted) = attempt(Some(stop));
            assert!(!pass);
            for policy in 0..6 {
                let bytes = interrupted.snapshot(policy, journal);
                let actual = observe(&mut Disk::new(&bytes));
                assert!(
                    actual == old || actual == new,
                    "partial {name}/{stop}/{policy}"
                );
                snapshots += 1;
            }
        }
    }
    eprintln!(
        "NAMED_PLANNED_RECOVERY: {snapshots} persistence snapshots for six stream edits passed"
    );
}
fn observe(d: &mut dyn BlockDevice) -> (Option<Store>, u32, u32) {
    let mut fs = HfsPlus::open(d).unwrap();
    let body = fs.catalog_record("/file").unwrap();
    let id = volume::be32(&body, 8);
    let bytes = fs.inline_attribute(d, id, wire::ATTRIBUTE).unwrap();
    let store = bytes.map(|b| wire::decode(&b).unwrap());
    assert_eq!(
        fs.inline_attribute(d, id, "unrelated").unwrap(),
        Some(b"keep".to_vec())
    );
    let mut data = Vec::new();
    fs.open_file_ro(d, std::path::Path::new("/file"))
        .unwrap()
        .read_to_end(&mut data)
        .unwrap();
    assert_eq!(data, b"unchanged data");
    (store, volume::be32(&body, 16), volume::be32(&body, 20))
}
fn retain(name: &str, bytes: &[u8]) {
    if let Some(directory) = std::env::var_os("HFS_NAMED_STREAM_ARTIFACT_DIR") {
        let path = std::path::Path::new(&directory).join(name);
        let mut output = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .unwrap();
        output.write_all(bytes).unwrap();
        output.sync_all().unwrap();
    }
}
#[test]
fn named_store_and_dates_publish_together_without_changing_file_data() {
    for journaled in [false, true] {
        for existing in [false, true] {
            let before = fixture(journaled, existing);
            let mut d = MemoryBackend::from_bytes(before.clone());
            let mut fs = engine::open_checked(&mut d).unwrap();
            stage(&mut fs, &mut d);
            assert_eq!(d.as_slice(), before);
            fs.flush(&mut d).unwrap();
            assert_eq!(
                observe(&mut d),
                (Some(store(true)), 3_800_000_001, 3_800_000_001)
            );
            retain(&format!("store-{journaled}-{existing}.img"), d.as_slice());
        }
    }
}
fn attempt(before: &[u8], stop: Option<usize>) -> (bool, Disk) {
    let mut d = Disk::new(before);
    let mut fs = engine::open_checked(&mut d).unwrap();
    d.arm(stop);
    stage(&mut fs, &mut d);
    assert_eq!(d.0.lock().unwrap().calls, 0);
    let pass = fs.flush(&mut d).is_ok();
    if !pass {
        let calls = d.0.lock().unwrap().calls;
        assert!(fs.flush(&mut d).is_err());
        assert_eq!(d.0.lock().unwrap().calls, calls);
    }
    (pass, d)
}
#[test]
fn named_store_create_and_replace_recover_as_old_or_new_publications() {
    let mut commits = 0;
    let mut replays = 0;
    for existing in [false, true] {
        let before = fixture(true, existing);
        let info = volume::be32(&before, 1036) as usize * volume::be32(&before, 1064) as usize;
        let journal = volume::be64(&before, info + 36) as usize;
        let old = observe(&mut Disk::new(&before));
        let (pass, complete) = attempt(&before, None);
        assert!(pass);
        let count = complete.0.lock().unwrap().calls;
        let new = observe(&mut Disk::new(&complete.0.lock().unwrap().durable));
        assert_ne!(old, new);
        let mut pending = None;
        for stop in 0..count {
            let (pass, interrupted) = attempt(&before, Some(stop));
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
                    "partial named store: {existing}/{stop}/{policy}"
                );
                commits += 1;
            }
        }
        let pending = pending.expect("no pending transaction captured");
        retain(&format!("store-pending-{existing}.img"), &pending);
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
    println!(
        "NAMED_STORE_MATRIX: {commits} commit and {replays} replay persistence snapshots passed"
    );
}
