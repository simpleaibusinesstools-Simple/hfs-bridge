//! Ordinary fork publication must not separate payload and related metadata.
use fstool::{
    block::{BlockDevice, MemoryBackend},
    fs::hfs_plus::{CatalogUpdate, ForkEdit, FormatOpts, HfsPlus, PublicationMetadata},
};
use hfs_bridge::{engine, volume};
use std::{
    io::{Read, Write},
    path::Path,
};
#[path = "support/fault_disk.rs"]
mod fault;
const MARKER: &str = "org.hfsbridge.test.fork";
const VALUE: &[u8] = b"one fork publication";
const PATCH: &[u8] = &[0x54; 513];

fn fixture(journaled: bool, sensitive: bool) -> Vec<u8> {
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
        &mut vec![0x41; 6003].as_slice(),
        6003,
        0o644,
        501,
        20,
        1_700_000_000,
    )
    .unwrap();
    fs.flush(&mut d).unwrap();
    {
        let mut f = fs
            .open_resource_fork_rw(&mut d, Path::new("/file"))
            .unwrap();
        f.write_all(&vec![0x52; 5001]).unwrap();
        f.sync().unwrap();
    }
    fs.set_data_allocation(&mut d, Path::new("/file"), 12288, false)
        .unwrap();
    fs.set_resource_allocation(&mut d, Path::new("/file"), 12288, false)
        .unwrap();
    let cnid = volume::be32(&fs.catalog_record("/file").unwrap(), 8);
    fs.set_attributes_batch(
        &mut d,
        &[
            (2, MARKER, Some(b"old")),
            (cnid, "com.example.large", Some(&vec![0x53; 6500])),
        ],
    )
    .unwrap();
    fs.flush(&mut d).unwrap();
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
fn edit(kind: usize) -> ForkEdit<'static> {
    match kind {
        0 => ForkEdit::Write {
            offset: 37,
            bytes: PATCH,
        },
        1 => ForkEdit::Write {
            offset: 14000,
            bytes: PATCH,
        },
        2 => ForkEdit::Resize(14001),
        3 => ForkEdit::Resize(37),
        4 => ForkEdit::Allocate {
            bytes: 16384,
            truncate: false,
        },
        5 => ForkEdit::Allocate {
            bytes: 8192,
            truncate: true,
        },
        6 => ForkEdit::Allocate {
            bytes: 4096,
            truncate: false,
        },
        _ => unreachable!(),
    }
}
fn apply(
    fs: &mut HfsPlus,
    d: &mut dyn BlockDevice,
    resource: bool,
    kind: usize,
) -> fstool::Result<bool> {
    let cnid = volume::be32(&fs.catalog_record("/file")?, 8);
    fs.edit_fork_with_publication(
        d,
        Path::new("/file"),
        resource,
        edit(kind),
        PublicationMetadata {
            attributes: &[("com.example.large", Some(&vec![0x55; 7003]))],
            related: &[
                (2, MARKER, Some(VALUE)),
                (cnid, MARKER, Some(b"entry precision")),
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
                    attributes: Some(0x23),
                },
                CatalogUpdate {
                    cnid: 2,
                    times: [None, None, Some(3_800_000_004), Some(3_800_000_005)],
                    attributes: None,
                },
            ],
        },
    )
}
fn retain(name: &str, bytes: &[u8]) {
    if let Some(dir) = std::env::var_os("HFS_FORK_ARTIFACT_DIR") {
        std::fs::create_dir_all(&dir).unwrap();
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(Path::new(&dir).join(name))
            .unwrap();
        f.write_all(bytes).unwrap();
        f.sync_all().unwrap();
    }
}
#[derive(Debug, PartialEq, Eq)]
struct State {
    header: Vec<u8>,
    bodies: Vec<Vec<u8>>,
    data: Vec<Vec<u8>>,
    values: Vec<Option<Vec<u8>>>,
}
fn observe(d: &mut dyn BlockDevice) -> State {
    let fs = HfsPlus::open(d).unwrap();
    let mut header = [0; 1536];
    d.read_at(0, &mut header).unwrap();
    let body = fs.catalog_record("/file").unwrap();
    let cnid = volume::be32(&body, 8);
    let mut data = Vec::new();
    fs.open_file_reader(d, "/file")
        .unwrap()
        .read_to_end(&mut data)
        .unwrap();
    let mut resource = Vec::new();
    if volume::be64(&body, 168) != 0 {
        fs.open_resource_fork_reader(d, "/file")
            .unwrap()
            .read_to_end(&mut resource)
            .unwrap();
    }
    State {
        header: header[1064..1096].to_vec(),
        bodies: vec![fs.catalog_record_cnid(2).unwrap(), body],
        data: vec![data, resource],
        values: vec![
            fs.inline_attribute(d, 2, MARKER).unwrap(),
            fs.inline_attribute(d, cnid, MARKER).unwrap(),
            fs.inline_attribute(d, cnid, "com.example.large").unwrap(),
        ],
    }
}
#[test]
fn fork_edits_publish_all_metadata_and_preserve_the_other_fork() {
    for journaled in [false, true] {
        for sensitive in [false, true] {
            for resource in [false, true] {
                for kind in 0..7 {
                    let before = fixture(journaled, sensitive);
                    let old = observe(&mut MemoryBackend::from_bytes(before.clone()));
                    let mut d = MemoryBackend::from_bytes(before.clone());
                    let mut fs = HfsPlus::open(&mut d).unwrap();
                    assert!(apply(&mut fs, &mut d, resource, kind).unwrap());
                    let new = observe(&mut d);
                    let index = usize::from(resource);
                    let mut expected = old.data[index].clone();
                    match edit(kind) {
                        ForkEdit::Write { offset, bytes } => {
                            expected.resize(expected.len().max(offset as usize + bytes.len()), 0);
                            expected[offset as usize..offset as usize + bytes.len()]
                                .copy_from_slice(bytes);
                        }
                        ForkEdit::Resize(size) => expected.resize(size as usize, 0),
                        ForkEdit::Allocate { bytes, truncate } => {
                            if truncate {
                                expected.clear();
                            } else {
                                expected.truncate(bytes as usize);
                            }
                        }
                    }
                    assert_eq!(new.data[index], expected);
                    assert_eq!(new.data[1 - index], old.data[1 - index]);
                    for (offset, value) in [
                        (12, 3_800_000_000),
                        (24, 3_800_000_001),
                        (16, 3_800_000_002),
                        (20, 3_800_000_003),
                    ] {
                        assert_eq!(volume::be32(&new.bodies[1], offset), value);
                    }
                    assert_eq!(volume::be16(&new.bodies[1], 2) & 1, 1);
                    assert_eq!(volume::be16(&new.bodies[1], 56) & 0x4000, 0x4000);
                    assert_eq!(volume::be32(&new.bodies[0], 16), 3_800_000_004);
                    assert_eq!(volume::be32(&new.bodies[0], 20), 3_800_000_005);
                    assert_eq!(
                        new.values,
                        vec![
                            Some(VALUE.to_vec()),
                            Some(b"entry precision".to_vec()),
                            Some(vec![0x55; 7003])
                        ]
                    );
                    assert_eq!(
                        volume::be32(d.as_slice(), 1092),
                        volume::be32(&before, 1092) + 1
                    );
                    let after = d.as_slice().to_vec();
                    fs.flush(&mut d).unwrap();
                    assert!(d.as_slice() == after);
                    // Export representative overwrite, hole, grow, shrink and
                    // allocation cases across both forks and volume variants.
                    if (journaled && sensitive && kind <= 3) || (!sensitive && kind >= 4) {
                        retain(
                            &format!("fork-{journaled}-{sensitive}-{resource}-{kind}.img"),
                            d.as_slice(),
                        );
                    }
                }
            }
        }
    }
}
#[test]
fn ineffective_fork_edits_do_not_publish_supplied_related_records() {
    let before = fixture(true, false);
    for resource in [false, true] {
        for edit in [
            ForkEdit::Write {
                offset: u64::MAX,
                bytes: &[],
            },
            ForkEdit::Resize(if resource { 5001 } else { 6003 }),
            ForkEdit::Allocate {
                bytes: 12288,
                truncate: false,
            },
        ] {
            let mut d = fault::Disk::new(&before);
            let mut fs = HfsPlus::open(&mut d).unwrap();
            d.arm(None);
            assert!(
                !fs.edit_fork_with_related_attributes(
                    &mut d,
                    Path::new("/file"),
                    resource,
                    edit,
                    &[("com.example.new", Some(VALUE))],
                    &[(2, MARKER, Some(VALUE))]
                )
                .unwrap()
            );
            assert_eq!(d.0.lock().unwrap().calls, 0);
            fs.flush(&mut d).unwrap();
            assert!(d.snapshot(1, 0) == before);
        }
    }
}
#[test]
fn refused_fork_edits_leave_no_metadata_or_payload_prefix() {
    let before = fixture(true, false);
    let free = volume::be32(&before, 1072) as u64;
    for resource in [false, true] {
        for variant in 0..11 {
            let mut d = fault::Disk::new(&before);
            let mut fs = HfsPlus::open(&mut d).unwrap();
            let cnid = volume::be32(&fs.catalog_record("/file").unwrap(), 8);
            let oversized = vec![0; 3803];
            let mut related = vec![(2, MARKER, Some(VALUE))];
            let mut op = edit(1);
            match variant {
                0 => related.push((999999, MARKER, Some(VALUE))),
                1 => related.push((cnid, "com.example.large", Some(VALUE))),
                2 => related.push((2, "com.apple.FinderInfo", None)),
                3 => related.push((2, "com.apple.decmpfs", None)),
                4 => related.push((2, "", None)),
                5 => related.push((2, "large", Some(&oversized))),
                6 => related.extend(std::iter::repeat_n((2, "repeated", None), 16)),
                7 => {
                    op = ForkEdit::Write {
                        offset: u64::MAX,
                        bytes: PATCH,
                    }
                }
                8 => {
                    op = ForkEdit::Allocate {
                        bytes: 8193,
                        truncate: true,
                    }
                }
                // The fork alone fits, but the COW attribute tree/values do not.
                9 => {
                    op = ForkEdit::Allocate {
                        bytes: (3 + free) * 4096,
                        truncate: false,
                    }
                }
                10 => {
                    op = ForkEdit::Allocate {
                        bytes: free * 4096,
                        truncate: true,
                    }
                }
                _ => unreachable!(),
            }
            d.arm(None);
            assert!(
                fs.edit_fork_with_related_attributes(
                    &mut d,
                    Path::new("/file"),
                    resource,
                    op,
                    &[("com.example.large", Some(&vec![0x55; 7003]))],
                    &related
                )
                .is_err(),
                "variant {variant}"
            );
            assert_eq!(d.0.lock().unwrap().calls, 0);
            fs.flush(&mut d).unwrap();
            assert!(d.snapshot(1, 0) == before);
        }
    }
}
#[test]
fn full_user_attribute_budget_keeps_sixteen_separate_related_slots() {
    for metadata_only in [false, true] {
        let mut d = MemoryBackend::from_bytes(fixture(true, false));
        let mut fs = HfsPlus::open(&mut d).unwrap();
        let cnid = volume::be32(&fs.catalog_record("/file").unwrap(), 8);
        let names = (0..257).map(|i| format!("u{i:03}")).collect::<Vec<_>>();
        let changes = names
            .iter()
            .map(|n| (n.as_str(), Some(b"u".as_slice())))
            .collect::<Vec<_>>();
        let related = (0..16)
            .map(|i| (2, names[i].as_str(), Some(VALUE)))
            .collect::<Vec<_>>();
        let before = d.as_slice().to_vec();
        assert!(
            fs.set_attributes_with_related_records(&mut d, cnid, &changes, &related)
                .is_err()
        );
        fs.flush(&mut d).unwrap();
        assert!(d.as_slice() == before);
        if metadata_only {
            fs.set_attributes_with_related_records(&mut d, cnid, &changes[..256], &related)
                .unwrap();
            assert!(d.as_slice() == before);
            fs.flush(&mut d).unwrap();
        } else {
            fs.edit_fork_with_related_attributes(
                &mut d,
                Path::new("/file"),
                false,
                edit(0),
                &changes[..256],
                &related,
            )
            .unwrap();
        }
        for name in &names[..256] {
            assert_eq!(
                fs.inline_attribute(&mut d, cnid, name).unwrap(),
                Some(b"u".to_vec())
            );
        }
        for (_, name, _) in related {
            assert_eq!(
                fs.inline_attribute(&mut d, 2, name).unwrap(),
                Some(VALUE.to_vec())
            );
        }
    }
}

#[test]
fn new_attribute_tree_and_finder_info_share_fork_publication() {
    for resource in [false, true] {
        let mut d = MemoryBackend::new(8 * 1024 * 1024);
        let mut fs = HfsPlus::format(
            &mut d,
            &FormatOpts {
                journaled: true,
                ..Default::default()
            },
        )
        .unwrap();
        let cnid = fs
            .create_file(&mut d, "/file", &mut &[][..], 0, 0o644, 501, 20, 0)
            .unwrap();
        fs.flush(&mut d).unwrap();
        let mut finder = [0; 32];
        finder[..8].copy_from_slice(b"TESTTEST");
        let before_counter = volume::be32(d.as_slice(), 1092);
        fs.edit_fork_with_related_attributes(
            &mut d,
            Path::new("/file"),
            resource,
            edit(1),
            &[("com.apple.FinderInfo", Some(&finder))],
            &[(2, MARKER, Some(VALUE))],
        )
        .unwrap();
        let body = fs.catalog_record_cnid(cnid).unwrap();
        assert_eq!(&body[48..80], &finder);
        assert_eq!(
            fs.inline_attribute(&mut d, 2, MARKER).unwrap(),
            Some(VALUE.to_vec())
        );
        assert_eq!(volume::be32(d.as_slice(), 1092), before_counter + 1);
        let mut payload = Vec::new();
        if resource {
            fs.open_resource_fork_reader(&mut d, "/file")
                .unwrap()
                .read_to_end(&mut payload)
                .unwrap();
        } else {
            fs.open_file_reader(&mut d, "/file")
                .unwrap()
                .read_to_end(&mut payload)
                .unwrap();
        }
        assert_eq!(payload.len(), 14513);
        assert!(payload[..14000].iter().all(|&b| b == 0));
        assert_eq!(&payload[14000..], PATCH);
    }
}

#[test]
fn pending_metadata_is_not_replaced_and_invalid_metadata_only_batches_are_pure() {
    let before = fixture(true, false);
    for metadata_only in [false, true] {
        let mut d = MemoryBackend::from_bytes(before.clone());
        let mut fs = HfsPlus::open(&mut d).unwrap();
        let cnid = volume::be32(&fs.catalog_record("/file").unwrap(), 8);
        assert!(
            fs.set_attributes_with_related_records(
                &mut d,
                cnid,
                &[("com.example.large", Some(VALUE))],
                &[(2, MARKER, Some(VALUE)), (u32::MAX, MARKER, Some(VALUE))]
            )
            .is_err()
        );
        fs.flush(&mut d).unwrap();
        assert!(d.as_slice() == before);
        fs.set_attributes_with_related_records(
            &mut d,
            cnid,
            &[("com.example.large", Some(b"pending"))],
            &[],
        )
        .unwrap();
        let refused = if metadata_only {
            fs.set_attributes_with_related_records(&mut d, cnid, &[], &[(2, MARKER, Some(VALUE))])
                .is_err()
        } else {
            apply(&mut fs, &mut d, false, 1).is_err()
        };
        assert!(refused);
        assert!(d.as_slice() == before);
        fs.flush(&mut d).unwrap();
        let after = observe(&mut d);
        let old = observe(&mut MemoryBackend::from_bytes(before.clone()));
        assert_eq!(after.data, old.data);
        assert_eq!(
            after.values,
            vec![Some(b"old".to_vec()), None, Some(b"pending".to_vec())]
        );
    }
}
fn attempt(
    bytes: &[u8],
    resource: bool,
    kind: usize,
    failure: Option<usize>,
) -> (bool, fault::Disk) {
    let mut d = fault::Disk::new(bytes);
    let mut fs = HfsPlus::open(&mut d).unwrap();
    d.arm(failure);
    let pass = apply(&mut fs, &mut d, resource, kind).is_ok();
    if !pass {
        let count = d.0.lock().unwrap().calls;
        assert!(fs.flush(&mut d).is_err());
        assert_eq!(d.0.lock().unwrap().calls, count);
    }
    (pass, d)
}
#[test]
fn interrupted_fork_edits_recover_complete_payload_and_related_metadata() {
    let mut commits = 0;
    let mut replays = 0;
    for sensitive in [false, true] {
        for resource in [false, true] {
            for kind in [1, 5] {
                let before = fixture(true, sensitive);
                let info = volume::be32(&before, 1036) as usize * 4096;
                let journal = volume::be64(&before, info + 36) as usize;
                let old = observe(&mut MemoryBackend::from_bytes(before.clone()));
                let (pass, completed) = attempt(&before, resource, kind, None);
                assert!(pass);
                let new = observe(&mut MemoryBackend::from_bytes(
                    completed.0.lock().unwrap().durable.clone(),
                ));
                let count = completed.0.lock().unwrap().calls;
                let mut pending = None;
                for failure in 0..count {
                    let (pass, d) = attempt(&before, resource, kind, Some(failure));
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
                            "partial fork {sensitive}/{resource}/{kind}/{failure}/{policy}"
                        );
                        commits += 1;
                    }
                }
                let pending = pending.unwrap();
                retain(
                    &format!("fork-pending-{sensitive}-{resource}-{kind}.img"),
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
    }
    println!("FORK_RELATED_MATRIX: {commits} commit + {replays} replay snapshots; 8 scenarios");
}
