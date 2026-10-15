//! Constructors publish their own attributes and related records together.
use fstool::{
    block::{BlockDevice, MemoryBackend},
    fs::hfs_plus::{CatalogUpdate, FormatOpts, HfsPlus, PublicationMetadata},
};
use hfs_bridge::{engine, volume};
use std::io::Write;
#[path = "support/fault_disk.rs"]
mod fault;
const MARKER: &str = "org.hfsbridge.test.creation";
const ENTRY: &str = "org.hfsbridge.test.entry";
const VALUE: &[u8] = b"one constructor publication";

fn fixture(journaled: bool, sensitive: bool, existing: bool) -> Vec<u8> {
    let mut d = MemoryBackend::new(8 * 1024 * 1024);
    let mut fs = HfsPlus::format(
        &mut d,
        &FormatOpts {
            journaled,
            ..Default::default()
        },
    )
    .unwrap();
    fs.create_dir(&mut d, "/parent", 0o755, 501, 20, 1_700_000_000)
        .unwrap();
    fs.flush(&mut d).unwrap();
    if existing {
        fs.set_attributes_batch(&mut d, &[(2, MARKER, Some(b"old generation"))])
            .unwrap();
        fs.flush(&mut d).unwrap();
    }
    let mut bytes = d.into_bytes();
    if sensitive {
        bytes[1024..1026].copy_from_slice(b"HX");
        bytes[1026..1028].copy_from_slice(&5u16.to_be_bytes());
        let catalog = volume::be32(&bytes, 1312) as usize * 4096;
        bytes[catalog + 51] = 0xbc;
        let alternate = bytes.len() - 1024;
        let header = bytes[1024..1536].to_vec();
        bytes[alternate..alternate + 512].copy_from_slice(&header);
        let mut d = MemoryBackend::from_bytes(bytes);
        let mut fs = HfsPlus::open(&mut d).unwrap();
        fs.set_catalog_times(2, [None, None, None, Some(3_782_844_800)])
            .unwrap();
        fs.flush(&mut d).unwrap();
        bytes = d.into_bytes();
    }
    bytes
}
fn create(fs: &mut HfsPlus, d: &mut dyn BlockDevice, directory: bool) -> fstool::Result<u32> {
    let cnid = fs.creation_cnid("/parent/new")?;
    let parent = volume::be32(&fs.catalog_record("/parent")?, 8);
    fs.create_entry_with_publication(
        d,
        "/parent/new",
        cnid,
        directory,
        501,
        20,
        1_700_000_000,
        if directory { 0 } else { 12288 },
        PublicationMetadata {
            attributes: &[
                ("com.example.large", Some(&vec![0x53; 6001])),
                ("com.apple.FinderInfo", Some(&[0; 32])),
            ],
            related: &[
                (2, MARKER, Some(VALUE)),
                (parent, ENTRY, Some(b"parent precision")),
                (cnid, ENTRY, Some(b"entry precision")),
            ],
            catalog: &[
                CatalogUpdate {
                    cnid,
                    times: [
                        Some(3_800_000_000),
                        Some(3_800_000_001),
                        Some(3_800_000_002),
                        Some(3_800_000_003),
                    ],
                    attributes: Some(if directory { 0x33 } else { 0x23 }),
                },
                CatalogUpdate {
                    cnid: parent,
                    times: [None, None, Some(3_800_000_004), Some(3_800_000_005)],
                    attributes: None,
                },
            ],
        },
    )
}
fn retain(name: &str, bytes: &[u8]) {
    if let Some(dir) = std::env::var_os("HFS_RELATED_ARTIFACT_DIR") {
        std::fs::create_dir_all(&dir).unwrap();
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(std::path::Path::new(&dir).join(name))
            .unwrap();
        f.write_all(bytes).unwrap();
        f.sync_all().unwrap();
    }
}
#[derive(Debug, PartialEq, Eq)]
struct State {
    counters: Vec<u8>,
    bodies: Vec<Option<Vec<u8>>>,
    values: Vec<Option<Vec<u8>>>,
}
fn observe(d: &mut dyn BlockDevice) -> State {
    let fs = HfsPlus::open(d).unwrap();
    let mut header = [0; 1536];
    d.read_at(0, &mut header).unwrap();
    let mut state = State {
        counters: header[1064..1096].to_vec(),
        bodies: Vec::new(),
        values: vec![fs.inline_attribute(d, 2, MARKER).unwrap()],
    };
    for path in ["/", "/parent", "/parent/new"] {
        let body = fs.catalog_record(path).ok();
        if let Some(body) = &body {
            let cnid = volume::be32(body, 8);
            state
                .values
                .push(fs.inline_attribute(d, cnid, ENTRY).unwrap());
            state
                .values
                .push(fs.inline_attribute(d, cnid, "com.example.large").unwrap());
        }
        state.bodies.push(body);
    }
    state
}
#[test]
fn constructors_publish_future_identity_large_values_and_parent_root_records() {
    for journaled in [false, true] {
        for sensitive in [false, true] {
            for directory in [false, true] {
                for existing in [false, true] {
                    let before = fixture(journaled, sensitive, existing);
                    let mut d = MemoryBackend::from_bytes(before.clone());
                    let mut fs = HfsPlus::open(&mut d).unwrap();
                    let cnid = create(&mut fs, &mut d, directory).unwrap();
                    // Fresh reserved blocks were already zero in this fixture.
                    // Catalog, allocation bitmap and header await caller flush.
                    assert!(d.as_slice() == before);
                    fs.flush(&mut d).unwrap();
                    assert_eq!(
                        fs.inline_attribute(&mut d, 2, MARKER).unwrap(),
                        Some(VALUE.to_vec())
                    );
                    assert_eq!(
                        fs.inline_attribute(&mut d, cnid, ENTRY).unwrap(),
                        Some(b"entry precision".to_vec())
                    );
                    assert_eq!(
                        fs.inline_attribute(&mut d, cnid, "com.example.large")
                            .unwrap(),
                        Some(vec![0x53; 6001])
                    );
                    let parent = volume::be32(&fs.catalog_record("/parent").unwrap(), 8);
                    assert_eq!(
                        fs.inline_attribute(&mut d, parent, ENTRY).unwrap(),
                        Some(b"parent precision".to_vec())
                    );
                    let body = fs.catalog_record("/parent/new").unwrap();
                    assert_eq!(volume::be16(&body, 0), if directory { 1 } else { 2 });
                    assert_eq!(volume::be16(&body, 2) & 4, 4);
                    assert_eq!(volume::be32(&body, 12), 3_800_000_000);
                    assert_eq!(volume::be32(&body, 24), 3_800_000_001);
                    assert_eq!(volume::be32(&body, 16), 3_800_000_002);
                    assert_eq!(volume::be32(&body, 20), 3_800_000_003);
                    if !directory {
                        assert_eq!(volume::be32(&body, 100), 3);
                        let run = volume::be32(&body, 104) as usize * 4096;
                        assert!(d.as_slice()[run..run + 12288].iter().all(|&b| b == 0));
                    }
                    assert_eq!(
                        volume::be32(d.as_slice(), 1072),
                        volume::be32(&before, 1072)
                            - if existing { 2 } else { 10 }
                            - if directory { 0 } else { 3 }
                    );
                    if !existing {
                        retain(
                            &format!("creation-{journaled}-{sensitive}-{directory}.img"),
                            d.as_slice(),
                        );
                    }
                    let after = d.as_slice().to_vec();
                    fs.flush(&mut d).unwrap();
                    assert!(d.as_slice() == after);
                }
            }
        }
    }
}
#[test]
fn constructor_refusals_do_not_consume_identity_allocate_or_stage_a_prefix() {
    let before = fixture(true, false, false);
    for variant in 0..11 {
        let mut d = MemoryBackend::from_bytes(before.clone());
        let mut fs = HfsPlus::open(&mut d).unwrap();
        let cnid = fs.creation_cnid("/parent/new").unwrap();
        let oversized = vec![0; 3803];
        let mut related = vec![
            (2, MARKER, Some(VALUE)),
            (cnid, ENTRY, Some(b"entry".as_slice())),
        ];
        match variant {
            0 => related.push((999999, ENTRY, Some(VALUE))),
            1 => related.push((cnid, "com.example.large", Some(VALUE))),
            2 => related.push((2, "com.apple.decmpfs", None)),
            3 => related.push((2, "com.apple.FinderInfo", None)),
            4 => related.push((2, "com.apple.system.Security", None)),
            5 => related.push((2, "com.apple.ResourceFork", None)),
            6 => related.push((2, "", None)),
            7 => related.push((2, "com.example.oversized", Some(&oversized))),
            8 => related.extend(std::iter::repeat_n((2, "com.example.repeat", None), 15)),
            9 | 10 => {}
            _ => unreachable!(),
        }
        let mut expected = cnid;
        // The value alone fits, but its new attribute tree does not.
        let huge = vec![0; volume::be32(&before, 1072) as usize * 4096];
        let value = if variant == 9 {
            huge.as_slice()
        } else {
            b"user"
        };
        if variant == 10 {
            expected += 1;
        }
        assert!(
            fs.create_entry_with_related_attributes(
                &mut d,
                "/parent/new",
                expected,
                false,
                501,
                20,
                0,
                &[("com.example.large", Some(value))],
                &related
            )
            .is_err(),
            "variant {variant}"
        );
        assert!(fs.catalog_record("/parent/new").is_err());
        assert_eq!(fs.creation_cnid("/parent/new").unwrap(), cnid);
        fs.flush(&mut d).unwrap();
        assert!(d.as_slice() == before, "variant {variant}");
        create(&mut fs, &mut d, false).unwrap();
        fs.flush(&mut d).unwrap();
    }
}
#[test]
fn constructor_preserves_full_user_budget_and_prior_pending_work() {
    let before = fixture(true, false, false);
    let mut d = MemoryBackend::from_bytes(before.clone());
    let mut fs = HfsPlus::open(&mut d).unwrap();
    let names = (0..256).map(|i| format!("u{i:03}")).collect::<Vec<_>>();
    let changes = names
        .iter()
        .map(|n| (n.as_str(), Some(b"x".as_slice())))
        .collect::<Vec<_>>();
    let cnid = fs.creation_cnid("/parent/new").unwrap();
    fs.create_entry_with_related_attributes(
        &mut d,
        "/parent/new",
        cnid,
        false,
        501,
        20,
        0,
        &changes,
        &[(2, MARKER, Some(VALUE)), (cnid, ENTRY, Some(VALUE))],
    )
    .unwrap();
    fs.flush(&mut d).unwrap();
    assert_eq!(fs.attribute_names(&mut d, cnid).unwrap().len(), 257);
    let next = fs.creation_cnid("/another").unwrap();
    fs.set_attributes_batch(&mut d, &[(2, MARKER, Some(b"earlier work"))])
        .unwrap();
    assert!(
        fs.create_entry_with_related_attributes(
            &mut d,
            "/another",
            next,
            false,
            501,
            20,
            0,
            &[],
            &[(2, MARKER, Some(VALUE))]
        )
        .is_err()
    );
    assert!(fs.catalog_record("/another").is_err());
    fs.flush(&mut d).unwrap();
    assert_eq!(
        fs.inline_attribute(&mut d, 2, MARKER).unwrap(),
        Some(b"earlier work".to_vec())
    );

    let mut d = MemoryBackend::from_bytes(before);
    let mut fs = HfsPlus::open(&mut d).unwrap();
    let free = volume::be32(d.as_slice(), 1072);
    let cnid = fs.creation_cnid("/empty").unwrap();
    fs.create_entry_with_related_attributes(
        &mut d,
        "/empty",
        cnid,
        true,
        501,
        20,
        0,
        &[],
        &[(2, MARKER, None)],
    )
    .unwrap();
    fs.flush(&mut d).unwrap();
    assert_eq!(volume::be32(d.as_slice(), 1072), free);
    assert_eq!(volume::be32(d.as_slice(), 1388), 0); // Absent tree stays absent.
}

#[test]
fn constructor_rejects_identity_collisions_and_insufficient_growth_space_before_creation() {
    let before = fixture(true, false, false);
    let fs = HfsPlus::open(&mut MemoryBackend::from_bytes(before.clone())).unwrap();
    let parent = volume::be32(&fs.catalog_record("/parent").unwrap(), 8);
    for next in [15, parent, u32::MAX] {
        let mut bytes = before.clone();
        let alternate = bytes.len() - 1024;
        for start in [1024, alternate] {
            bytes[start + 64..start + 68].copy_from_slice(&next.to_be_bytes());
        }
        let mut d = MemoryBackend::from_bytes(bytes.clone());
        let mut fs = HfsPlus::open(&mut d).unwrap();
        assert!(fs.creation_cnid("/parent/new").is_err());
        assert!(
            fs.create_entry_with_related_attributes(
                &mut d,
                "/parent/new",
                next,
                false,
                501,
                20,
                0,
                &[],
                &[(2, MARKER, Some(VALUE))]
            )
            .is_err()
        );
        assert!(d.as_slice() == bytes);
        // The existing writer may normalize a deliberately malformed header
        // even on an otherwise empty flush. Compare the unchanged control.
        let mut control = MemoryBackend::from_bytes(bytes);
        HfsPlus::open(&mut control)
            .unwrap()
            .flush(&mut control)
            .unwrap();
        fs.flush(&mut d).unwrap();
        assert!(d.as_slice() == control.as_slice());
    }
    let mut d = MemoryBackend::from_bytes(before.clone());
    let mut fs = HfsPlus::open(&mut d).unwrap();
    let filler = fs.creation_cnid("/filler").unwrap();
    fs.create_entry_with_related_attributes(&mut d, "/filler", filler, false, 501, 20, 0, &[], &[])
        .unwrap();
    fs.flush(&mut d).unwrap();
    let free = volume::be32(d.as_slice(), 1072);
    fs.set_data_allocation(
        &mut d,
        std::path::Path::new("/filler"),
        u64::from(free - 8) * 4096,
        false,
    )
    .unwrap();
    assert_eq!(volume::be32(d.as_slice(), 1072), 8);
    let before = d.as_slice().to_vec();
    let cnid = fs.creation_cnid("/parent/new").unwrap();
    let names = (0..256).map(|i| format!("u{i:03}")).collect::<Vec<_>>();
    let data = vec![0; 3802];
    let changes = names
        .iter()
        .map(|n| (n.as_str(), Some(data.as_slice())))
        .collect::<Vec<_>>();
    assert!(
        fs.create_entry_with_related_attributes(
            &mut d,
            "/parent/new",
            cnid,
            false,
            501,
            20,
            0,
            &changes,
            &[(2, MARKER, Some(VALUE))]
        )
        .is_err()
    );
    assert!(fs.catalog_record("/parent/new").is_err());
    fs.flush(&mut d).unwrap();
    assert!(d.as_slice() == before);

    // An orphan attribute for a future identity must not be inherited, even
    // when the caller asks for no new metadata at all.
    let mut bytes = fixture(true, false, true);
    let fs = HfsPlus::open(&mut MemoryBackend::from_bytes(bytes.clone())).unwrap();
    let next = fs.creation_cnid("/parent/new").unwrap();
    let tree = volume::be32(&bytes, 1392) as usize * 4096;
    let node_size = volume::be16(&bytes, tree + 32) as usize;
    let leaf = tree + volume::be32(&bytes, tree + 24) as usize * node_size;
    let key = leaf + volume::be16(&bytes, leaf + node_size - 2) as usize;
    assert_eq!(volume::be32(&bytes, key + 4), 2);
    bytes[key + 4..key + 8].copy_from_slice(&next.to_be_bytes());
    let mut d = MemoryBackend::from_bytes(bytes.clone());
    let mut fs = HfsPlus::open(&mut d).unwrap();
    assert!(
        fs.create_entry_with_related_attributes(
            &mut d,
            "/parent/new",
            next,
            false,
            501,
            20,
            0,
            &[],
            &[]
        )
        .is_err()
    );
    assert!(fs.catalog_record("/parent/new").is_err());
    fs.flush(&mut d).unwrap();
    assert!(d.as_slice() == bytes);
}

#[test]
fn unexpected_constructor_failure_refuses_later_publication() {
    let mut bytes = fixture(true, false, false);
    let fs = HfsPlus::open(&mut MemoryBackend::from_bytes(bytes.clone())).unwrap();
    let parent = volume::be32(&fs.catalog_record("/parent").unwrap(), 8);
    let tree = volume::be32(&bytes, 1312) as usize * 4096;
    let node_size = volume::be16(&bytes, tree + 32) as usize;
    let mut leaf = volume::be32(&bytes, tree + 24);
    let mut changed = false;
    while leaf != 0 {
        let node = tree + leaf as usize * node_size;
        for i in 0..volume::be16(&bytes, node + 10) as usize {
            let key = node + volume::be16(&bytes, node + node_size - 2 * (i + 1)) as usize;
            if volume::be32(&bytes, key + 2) == parent && volume::be16(&bytes, key + 6) == 0 {
                let body = key + 2 + volume::be16(&bytes, key) as usize;
                // The directory exists, but its thread points to no parent.
                bytes[body + 4..body + 8].copy_from_slice(&u32::MAX.to_be_bytes());
                changed = true;
            }
        }
        leaf = volume::be32(&bytes, node);
    }
    assert!(changed);
    let mut d = fault::Disk::new(&bytes);
    let mut fs = HfsPlus::open(&mut d).unwrap();
    let next = fs.creation_cnid("/parent/new").unwrap();
    d.arm(None);
    assert!(
        fs.create_entry_with_related_attributes(
            &mut d,
            "/parent/new",
            next,
            false,
            501,
            20,
            0,
            &[],
            &[(2, MARKER, Some(VALUE))]
        )
        .is_err()
    );
    assert!(fs.flush(&mut d).is_err());
    assert_eq!(d.0.lock().unwrap().calls, 0);
    assert!(d.snapshot(1, 0) == bytes);
}
fn attempt(bytes: &[u8], directory: bool, failure: Option<usize>) -> (bool, fault::Disk) {
    let mut d = fault::Disk::new(bytes);
    let mut fs = HfsPlus::open(&mut d).unwrap();
    d.arm(failure);
    let pass = create(&mut fs, &mut d, directory)
        .and_then(|_| fs.flush(&mut d))
        .is_ok();
    if !pass {
        let count = d.0.lock().unwrap().calls;
        assert!(fs.flush(&mut d).is_err());
        assert_eq!(d.0.lock().unwrap().calls, count);
    }
    (pass, d)
}
#[test]
fn constructor_recovery_never_separates_new_entry_and_related_metadata() {
    let mut commits = 0;
    let mut replays = 0;
    for sensitive in [false, true] {
        for directory in [false, true] {
            let before = fixture(true, sensitive, false);
            let info = volume::be32(&before, 1036) as usize * 4096;
            let journal = volume::be64(&before, info + 36) as usize;
            let old = observe(&mut MemoryBackend::from_bytes(before.clone()));
            let (pass, completed) = attempt(&before, directory, None);
            assert!(pass);
            let new = observe(&mut MemoryBackend::from_bytes(
                completed.0.lock().unwrap().durable.clone(),
            ));
            let count = completed.0.lock().unwrap().calls;
            let mut pending = None;
            for failure in 0..count {
                let (pass, d) = attempt(&before, directory, Some(failure));
                assert!(!pass);
                for policy in 0..6 {
                    let bytes = d.snapshot(policy, journal);
                    if matches!(
                        volume::inspect(&mut MemoryBackend::from_bytes(bytes.clone()))
                            .unwrap()
                            .journal,
                        volume::Journal::Pending { .. }
                    ) {
                        pending.get_or_insert_with(|| bytes.clone());
                        let guarded = fault::Disk::new(&bytes);
                        guarded.arm(Some(0));
                        assert!(engine::open_checked(&mut guarded.clone()).is_err());
                        assert_eq!(guarded.0.lock().unwrap().calls, 0);
                    }
                    let got = observe(&mut MemoryBackend::from_bytes(bytes));
                    assert!(
                        got == old || got == new,
                        "partial constructor {sensitive}/{directory}/{failure}/{policy}"
                    );
                    commits += 1;
                }
            }
            let pending = pending.unwrap();
            retain(
                &format!("creation-pending-{sensitive}-{directory}.img"),
                &pending,
            );
            let mut replay = fault::Disk::new(&pending);
            HfsPlus::open(&mut replay).unwrap();
            let count = replay.0.lock().unwrap().calls;
            for failure in 0..count {
                let mut d = fault::Disk::new(&pending);
                d.arm(Some(failure));
                assert!(HfsPlus::open(&mut d).is_err());
                for policy in 0..6 {
                    assert_eq!(
                        observe(&mut MemoryBackend::from_bytes(d.snapshot(policy, journal))),
                        new
                    );
                    replays += 1;
                }
            }
        }
    }
    println!("CREATION_RELATED_MATRIX: {commits} commit + {replays} replay snapshots; 4 scenarios");
}
