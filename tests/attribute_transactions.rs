//! Complete multi-entry inline/fork attribute plans, including pending deletion.
use fstool::{
    block::{BlockDevice, MemoryBackend},
    fs::hfs_plus::{CatalogUpdate, FormatOpts, HfsPlus},
};
use hfs_bridge::{engine, volume};
use std::io::{Read, Write};
#[path = "support/fault_disk.rs"]
mod fault;
#[path = "support/attribute_wire.rs"]
#[allow(dead_code)]
mod wire;

const NAME: &str = "com.example.large";
const MARKER: &str = "org.hfsbridge.test.complete-generation";
const MARKER_VALUE: &[u8] = b"combined metadata transaction";
const TIMES: [Option<u32>; 4] = [
    Some(3_800_000_000),
    Some(3_800_000_001),
    Some(3_800_000_002),
    Some(3_800_000_003),
];
fn id(fs: &HfsPlus, path: &str) -> u32 {
    volume::be32(&fs.catalog_record(path).unwrap(), 8)
}
fn payload(len: usize, salt: u8) -> Vec<u8> {
    (0..len)
        .map(|i| (i as u8).wrapping_mul(17).wrapping_add(salt))
        .collect()
}
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
    fs.create_dir(&mut d, "/folder", 0o755, 501, 20, 1_700_000_000)
        .unwrap();
    for path in ["/file", "/victim", "/keep"] {
        fs.create_file(
            &mut d,
            path,
            &mut &b"user data"[..],
            9,
            0o644,
            501,
            20,
            1_700_000_000,
        )
        .unwrap();
    }
    fs.flush(&mut d).unwrap();
    let mut resource = fs
        .open_resource_fork_rw(&mut d, std::path::Path::new("/file"))
        .unwrap();
    resource.write_all(b"resource bytes").unwrap();
    resource.sync().unwrap();
    drop(resource);
    if existing {
        for (path, len, salt) in [("/file", 5001, 1), ("/victim", 4003, 2), ("/keep", 9001, 3)] {
            let cnid = id(&fs, path);
            fs.set_inline_attribute(&mut d, cnid, NAME, Some(&payload(len, salt)))
                .unwrap();
            fs.flush(&mut d).unwrap();
        }
    }
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
fn stage(fs: &mut HfsPlus, d: &mut dyn BlockDevice) {
    let file = id(fs, "/file");
    let folder = id(fs, "/folder");
    fs.remove(d, "/victim").unwrap();
    fs.set_attributes_batch_with_publication(
        d,
        &[
            (file, NAME, Some(&payload(12017, 4))),
            (folder, NAME, Some(&payload(4099, 5))),
            (file, "com.example.small", Some(b"small metadata")),
            (file, "com.example.Case", Some(b"upper")),
            (file, "com.example.case", Some(b"lower")),
        ],
        &[(2, MARKER, Some(MARKER_VALUE))],
        &[file, folder, 2].map(|cnid| CatalogUpdate {
            cnid,
            times: TIMES,
            attributes: None,
        }),
    )
    .unwrap();
}
fn retain(name: &str, bytes: &[u8]) {
    if let Some(dir) = std::env::var_os("HFS_ATTRIBUTE_TRANSACTION_ARTIFACT_DIR") {
        std::fs::create_dir_all(&dir).unwrap();
        let path = std::path::Path::new(&dir).join(name);
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .unwrap();
        file.write_all(bytes).unwrap();
        file.sync_all().unwrap();
    }
}
#[derive(Debug, PartialEq, Eq)]
struct Observation {
    free: u32,
    count: u32,
    bodies: Vec<Option<Vec<u8>>>,
    values: Vec<Option<Vec<u8>>>,
}
fn observe(d: &mut dyn BlockDevice) -> Observation {
    let fs = HfsPlus::open(d).unwrap();
    let mut header = [0; 1536];
    d.read_at(0, &mut header).unwrap();
    let mut result = Observation {
        free: volume::be32(&header, 1072),
        count: volume::be32(&header, 1092),
        bodies: Vec::new(),
        values: vec![fs.inline_attribute(d, 2, MARKER).unwrap()],
    };
    for path in ["/file", "/folder", "/keep", "/victim"] {
        let body = fs.catalog_record(path).ok();
        if let Some(ref body) = body {
            let cnid = volume::be32(body, 8);
            result
                .values
                .push(fs.inline_attribute(d, cnid, NAME).unwrap());
            if path != "/folder" {
                let mut bytes = Vec::new();
                fs.open_file_reader(d, path)
                    .unwrap()
                    .read_to_end(&mut bytes)
                    .unwrap();
                assert_eq!(bytes, b"user data");
            }
            if path == "/file" {
                let mut bytes = Vec::new();
                fs.open_resource_fork_reader(d, path)
                    .unwrap()
                    .read_to_end(&mut bytes)
                    .unwrap();
                assert_eq!(bytes, b"resource bytes");
                for name in ["com.example.small", "com.example.Case", "com.example.case"] {
                    result
                        .values
                        .push(fs.inline_attribute(d, cnid, name).unwrap());
                }
            }
        } else {
            assert_eq!(path, "/victim");
            result.values.push(None);
        }
        result.bodies.push(body);
    }
    result.bodies.push(Some(fs.catalog_record_cnid(2).unwrap()));
    result
}
#[test]
fn complete_batches_publish_new_large_values_root_records_and_deletion_together() {
    for journaled in [false, true] {
        for sensitive in [false, true] {
            for existing in [false, true] {
                let original = fixture(journaled, sensitive, existing);
                let mut d = MemoryBackend::from_bytes(original.clone());
                let mut fs = engine::open_checked(&mut d).unwrap();
                let file = id(&fs, "/file");
                let folder = id(&fs, "/folder");
                let victim = id(&fs, "/victim");
                let keep = id(&fs, "/keep");
                stage(&mut fs, &mut d);
                assert!(d.as_slice() == original, "preflight/staging wrote bytes");
                fs.flush(&mut d).unwrap();
                let fs = engine::open_checked(&mut d).unwrap();
                assert!(fs.catalog_record("/victim").is_err());
                for cnid in [file, folder, 2] {
                    let body = fs.catalog_record_cnid(cnid).unwrap();
                    for (offset, expected) in [12, 24, 16, 20].into_iter().zip(TIMES) {
                        assert_eq!(volume::be32(&body, offset), expected.unwrap());
                    }
                }
                for (cnid, name, value) in [
                    (file, NAME, payload(12017, 4)),
                    (folder, NAME, payload(4099, 5)),
                    (2, MARKER, MARKER_VALUE.to_vec()),
                    (file, "com.example.small", b"small metadata".to_vec()),
                    (file, "com.example.Case", b"upper".to_vec()),
                    (file, "com.example.case", b"lower".to_vec()),
                ] {
                    assert_eq!(
                        fs.inline_attribute(&mut d, cnid, name).unwrap(),
                        Some(value)
                    );
                    assert_eq!(
                        volume::be16(&fs.catalog_record_cnid(cnid).unwrap(), 2) & 4,
                        4
                    );
                }
                assert_eq!(
                    fs.inline_attribute(&mut d, keep, NAME).unwrap(),
                    existing.then(|| payload(9001, 3))
                );
                assert_eq!(
                    volume::be32(d.as_slice(), 1092),
                    volume::be32(&original, 1092) + 1
                );
                // Deleted data+attribute blocks and replaced old value blocks are
                // retired only once; new tree/value allocations are fully accounted.
                assert_eq!(
                    volume::be32(d.as_slice(), 1072),
                    volume::be32(&original, 1072) - if existing { 1 } else { 12 }
                );
                let wire = wire::audit_initialized(d.as_slice());
                assert!(!wire.iter().any(|r| volume::be32(r, 4) == victim));
                observe(&mut d);
                retain(
                    &format!("transaction-{journaled}-{sensitive}-{existing}.img"),
                    d.as_slice(),
                );
                let committed = d.as_slice().to_vec();
                let mut fs = HfsPlus::open(&mut d).unwrap();
                fs.flush(&mut d).unwrap();
                assert!(d.as_slice() == committed);
                fs.set_attributes_batch(
                    &mut d,
                    &[
                        (file, NAME, Some(b"now small")),
                        (folder, NAME, None),
                        (2, MARKER, Some(b"second batch")),
                    ],
                )
                .unwrap();
                fs.flush(&mut d).unwrap();
                assert_eq!(
                    volume::be32(d.as_slice(), 1072),
                    volume::be32(&committed, 1072) + 5
                );
                assert_eq!(
                    volume::be16(&fs.catalog_record("/folder").unwrap(), 2) & 4,
                    0
                );
                assert_eq!(
                    fs.inline_attribute(&mut d, file, NAME).unwrap(),
                    Some(b"now small".to_vec())
                );
            }
        }
    }
}
#[test]
fn bad_final_members_and_tree_growth_space_leave_no_prefix_or_allocation_staged() {
    for existing in [false, true] {
        let original = fixture(true, false, existing);
        let mut d = MemoryBackend::from_bytes(original.clone());
        let mut fs = HfsPlus::open(&mut d).unwrap();
        let file = id(&fs, "/file");
        let large = payload(12017, 8);
        for last in [
            (0, NAME, Some(&b"bad"[..])),
            (2, "", None),
            (2, "com.apple.system.test", None),
            (2, "com.apple.decmpfs", None),
            (2, "com.apple.FinderInfo", None),
            (file, NAME, None),
        ] {
            assert!(
                fs.set_attributes_batch(&mut d, &[(file, NAME, Some(&large)), last])
                    .is_err()
            );
            fs.flush(&mut d).unwrap();
            assert!(d.as_slice() == original);
        }
        // Growth is now supported. Leave room for the first value reservation,
        // but not the replacement tree, to exercise a real preflight refusal.
        let free = volume::be32(d.as_slice(), 1072);
        fs.set_data_allocation(
            &mut d,
            std::path::Path::new("/keep"),
            u64::from(free - 3 + 1) * 4096,
            false,
        )
        .unwrap();
        assert_eq!(volume::be32(d.as_slice(), 1072), 3);
        let original = d.as_slice().to_vec();
        let values = vec![0; 3802];
        let names = (0..20).map(|i| format!("attr{i}")).collect::<Vec<_>>();
        let mut changes = vec![(file, NAME, Some(large.as_slice()))];
        changes.extend(
            names
                .iter()
                .map(|name| (2, name.as_str(), Some(values.as_slice()))),
        );
        assert!(
            fs.set_attributes_batch(&mut d, &changes).is_err(),
            "insufficient tree growth space was not refused"
        );
        fs.flush(&mut d).unwrap();
        assert!(
            d.as_slice() == original,
            "temporary payload allocation escaped tree preflight"
        );
        let names = (0..257).map(|i| format!("attr{i}")).collect::<Vec<_>>();
        let changes = names
            .iter()
            .map(|name| (file, name.as_str(), None))
            .collect::<Vec<_>>();
        assert!(fs.set_attributes_batch(&mut d, &changes).is_err());
        let too_large = vec![0; 16 * 1024 * 1024 + 1];
        assert!(
            fs.set_attributes_batch(&mut d, &[(file, NAME, Some(&too_large))])
                .is_err()
        );
        let half = &too_large[..9 * 1024 * 1024];
        assert!(
            fs.set_attributes_batch(&mut d, &[(file, NAME, Some(half)), (2, MARKER, Some(half))])
                .is_err()
        );
        fs.flush(&mut d).unwrap();
        assert!(d.as_slice() == original);
    }
}
#[test]
fn failed_batch_keeps_earlier_deletion_and_pending_edit_refusals_keep_original_plan() {
    let mut limited = MemoryBackend::from_bytes(fixture(true, false, true));
    let mut limited_fs = HfsPlus::open(&mut limited).unwrap();
    let free = volume::be32(limited.as_slice(), 1072);
    limited_fs
        .set_data_allocation(
            &mut limited,
            std::path::Path::new("/keep"),
            u64::from(free - 3 + 1) * 4096,
            false,
        )
        .unwrap();
    let original = limited.into_bytes();
    let mut expected = MemoryBackend::from_bytes(original.clone());
    let mut fs = HfsPlus::open(&mut expected).unwrap();
    fs.remove(&mut expected, "/victim").unwrap();
    fs.flush(&mut expected).unwrap();
    let mut d = MemoryBackend::from_bytes(original.clone());
    let mut fs = HfsPlus::open(&mut d).unwrap();
    let file = id(&fs, "/file");
    fs.remove(&mut d, "/victim").unwrap();
    let names = (0..20).map(|i| format!("full{i}")).collect::<Vec<_>>();
    let value = vec![1; 3802];
    let large = payload(12017, 8);
    let mut changes = vec![(file, NAME, Some(large.as_slice()))];
    changes.extend(
        names
            .iter()
            .map(|name| (2, name.as_str(), Some(value.as_slice()))),
    );
    assert!(fs.set_attributes_batch(&mut d, &changes).is_err());
    fs.flush(&mut d).unwrap();
    assert_eq!(d.as_slice(), expected.as_slice());
    for prior_batch in [false, true] {
        let mut d = MemoryBackend::from_bytes(original.clone());
        let mut fs = HfsPlus::open(&mut d).unwrap();
        if prior_batch {
            fs.set_attributes_batch(&mut d, &[(file, NAME, Some(&large))])
                .unwrap();
        } else {
            fs.set_inline_attribute(&mut d, file, NAME, Some(&large))
                .unwrap();
        }
        assert!(
            fs.set_attributes_batch(&mut d, &[(2, MARKER, Some(MARKER_VALUE))])
                .is_err()
        );
        assert!(fs.remove(&mut d, "/victim").is_err());
        assert!(fs.set_inline_attribute(&mut d, file, NAME, None).is_err());
        fs.flush(&mut d).unwrap();
        assert_eq!(
            fs.inline_attribute(&mut d, file, NAME).unwrap(),
            Some(large.clone())
        );
        assert!(fs.inline_attribute(&mut d, 2, MARKER).unwrap().is_none());
        assert!(fs.catalog_record("/victim").is_ok());
    }
}
#[test]
fn aggregate_copy_on_write_space_is_preflighted_and_absent_removals_allocate_nothing() {
    for existing in [false, true] {
        let original = fixture(true, false, existing);
        let mut d = MemoryBackend::from_bytes(original.clone());
        let mut fs = HfsPlus::open(&mut d).unwrap();
        let file = id(&fs, "/file");
        if !existing {
            fs.set_attributes_batch(&mut d, &[(2, MARKER, None), (file, NAME, None)])
                .unwrap();
            fs.flush(&mut d).unwrap();
            assert!(d.as_slice() == original);
        }
        let free = volume::be32(d.as_slice(), 1072);
        // Keep only enough free space for the first reservation (and a new
        // tree if needed), never enough for the final second large value.
        let leave = if existing { 3 } else { 11 };
        fs.set_data_allocation(
            &mut d,
            std::path::Path::new("/keep"),
            u64::from(free - leave + 1) * 4096,
            false,
        )
        .unwrap();
        assert_eq!(volume::be32(d.as_slice(), 1072), leave);
        let before = d.as_slice().to_vec();
        let root = fs.catalog_record_cnid(2).unwrap();
        assert!(
            fs.set_attributes_batch(
                &mut d,
                &[
                    (file, NAME, Some(&payload(12017, 8))),
                    (2, MARKER, Some(&payload(4099, 9)))
                ]
            )
            .is_err()
        );
        fs.flush(&mut d).unwrap();
        assert!(d.as_slice() == before);
        assert_eq!(fs.catalog_record_cnid(2).unwrap(), root);
    }
}

#[test]
fn full_public_and_related_budgets_commit_with_sixteen_catalog_updates() {
    for journaled in [false, true] {
        for sensitive in [false, true] {
            let mut d = MemoryBackend::from_bytes(fixture(journaled, sensitive, false));
            let mut fs = HfsPlus::open(&mut d).unwrap();
            let file = id(&fs, "/file");
            let mut cnids = vec![file, id(&fs, "/folder"), id(&fs, "/keep"), 2];
            for i in 0..12 {
                cnids.push(
                    fs.create_dir(&mut d, &format!("/extra{i}"), 0o755, 501, 20, 0)
                        .unwrap(),
                );
            }
            fs.flush(&mut d).unwrap();
            let before = d.as_slice().to_vec();
            let victim = id(&fs, "/victim");
            fs.remove(&mut d, "/victim").unwrap();
            let public_names = (0..256).map(|i| format!("p{i:03}")).collect::<Vec<_>>();
            let related_names = (0..16).map(|i| format!("r{i:02}")).collect::<Vec<_>>();
            let public = public_names
                .iter()
                .map(|name| (file, name.as_str(), Some(&b"public"[..])))
                .collect::<Vec<_>>();
            let inline_limit = vec![42; 3802];
            let related = related_names
                .iter()
                .enumerate()
                .map(|(i, name)| {
                    (
                        cnids[i],
                        name.as_str(),
                        Some(if i == 0 {
                            inline_limit.as_slice()
                        } else {
                            &b"related"[..]
                        }),
                    )
                })
                .collect::<Vec<_>>();
            let catalog = cnids
                .iter()
                .map(|&cnid| CatalogUpdate {
                    cnid,
                    times: TIMES,
                    attributes: None,
                })
                .collect::<Vec<_>>();
            fs.set_attributes_batch_with_publication(&mut d, &public, &related, &catalog)
                .unwrap();
            assert!(d.as_slice() == before);
            fs.flush(&mut d).unwrap();
            let fs = HfsPlus::open(&mut d).unwrap();
            assert!(fs.catalog_record("/victim").is_err());
            assert_eq!(
                volume::be32(d.as_slice(), 1092),
                volume::be32(&before, 1092) + 1
            );
            for (cnid, name, value) in public.iter().chain(related.iter()) {
                assert_eq!(
                    fs.inline_attribute(&mut d, *cnid, name).unwrap().as_deref(),
                    *value
                );
            }
            for cnid in cnids {
                let body = fs.catalog_record_cnid(cnid).unwrap();
                for (offset, expected) in [12, 24, 16, 20].into_iter().zip(TIMES) {
                    assert_eq!(volume::be32(&body, offset), expected.unwrap());
                }
            }
            assert!(
                !wire::audit_initialized(d.as_slice())
                    .iter()
                    .any(|r| volume::be32(r, 4) == victim)
            );
        }
    }
}

#[test]
fn publication_refusals_preserve_pending_deletion_and_do_not_stage_valid_prefixes() {
    for existing in [false, true] {
        let original = fixture(true, false, existing);
        for pending in [false, true] {
            for variant in 0..15 {
                let mut expected = MemoryBackend::from_bytes(original.clone());
                let mut control = HfsPlus::open(&mut expected).unwrap();
                if pending {
                    control.remove(&mut expected, "/victim").unwrap();
                }
                control.flush(&mut expected).unwrap();
                let mut d = MemoryBackend::from_bytes(original.clone());
                let mut fs = HfsPlus::open(&mut d).unwrap();
                let file = id(&fs, "/file");
                let victim = id(&fs, "/victim");
                if pending {
                    fs.remove(&mut d, "/victim").unwrap();
                }
                let missing = if pending { victim } else { 999999 };
                let large = payload(12017, 8);
                let public_names = (0..257).map(|i| format!("p{i}")).collect::<Vec<_>>();
                let related_names = (0..17).map(|i| format!("r{i}")).collect::<Vec<_>>();
                let oversized = vec![0; 3803];
                let update = CatalogUpdate {
                    cnid: file,
                    times: TIMES,
                    attributes: Some(0x22),
                };
                let mut public = vec![(file, NAME, Some(large.as_slice()))];
                let mut related = vec![(2, MARKER, Some(MARKER_VALUE))];
                let mut catalog = vec![update];
                match variant {
                    0 => related.push((file, NAME, None)),
                    1 => related.push((2, MARKER, None)),
                    2 => {
                        related = related_names
                            .iter()
                            .map(|n| (2, n.as_str(), None))
                            .collect()
                    }
                    3 => related.push((file, "large-related", Some(&oversized))),
                    4 => {
                        public = public_names
                            .iter()
                            .map(|n| (file, n.as_str(), None))
                            .collect()
                    }
                    5 => catalog.push(update),
                    6 => catalog.push(CatalogUpdate {
                        cnid: missing,
                        ..update
                    }),
                    7 => catalog[0].attributes = Some(0x10),
                    8 => catalog[0].attributes = Some(0x8000),
                    9 => catalog.extend(std::iter::repeat_n(update, 16)),
                    10 => related.push((missing, "revived", Some(b"no"))),
                    11 => public.push((missing, "revived", Some(b"no"))),
                    12 => related.push((2, "com.apple.decmpfs", None)),
                    13 => related.push((2, "com.apple.system.test", None)),
                    14 => related.push((2, "", None)),
                    _ => unreachable!(),
                }
                assert!(
                    fs.set_attributes_batch_with_publication(&mut d, &public, &related, &catalog)
                        .is_err(),
                    "variant {variant}"
                );
                assert!(!fs.requires_reopen(), "pure refusal poisoned writer");
                assert!(d.as_slice() == original);
                fs.flush(&mut d).unwrap();
                assert!(
                    d.as_slice() == expected.as_slice(),
                    "refusal changed staged work: {existing}/{pending}/{variant}"
                );
            }
        }
    }
}

#[test]
fn catalog_only_and_absent_removals_keep_deletions_without_allocating_attributes() {
    for existing in [false, true] {
        let original = fixture(true, false, existing);
        for absent_removals in [false, true] {
            let mut d = MemoryBackend::from_bytes(original.clone());
            let mut fs = HfsPlus::open(&mut d).unwrap();
            let file = id(&fs, "/file");
            fs.remove(&mut d, "/victim").unwrap();
            let mut control = MemoryBackend::from_bytes(original.clone());
            let mut expected = HfsPlus::open(&mut control).unwrap();
            expected.remove(&mut control, "/victim").unwrap();
            expected
                .set_catalog_windows_info(file, TIMES, Some(0x23))
                .unwrap();
            expected.flush(&mut control).unwrap();
            let removals = [(file, "absent", None)];
            fs.set_attributes_batch_with_publication(
                &mut d,
                if absent_removals { &removals } else { &[] },
                &[],
                &[CatalogUpdate {
                    cnid: file,
                    times: TIMES,
                    attributes: Some(0x23),
                }],
            )
            .unwrap();
            assert!(d.as_slice() == original);
            fs.flush(&mut d).unwrap();
            assert_eq!(observe(&mut d), observe(&mut control));
            if !existing {
                assert_eq!(volume::be32(d.as_slice(), 1388), 0);
            }
        }
    }
    let original = fixture(true, false, true);
    let mut d = MemoryBackend::from_bytes(original.clone());
    let mut fs = HfsPlus::open(&mut d).unwrap();
    let file = id(&fs, "/file");
    let original_body = fs.catalog_record("/file").unwrap();
    fs.set_attributes_batch(&mut d, &[(file, NAME, Some(b"earlier plan"))])
        .unwrap();
    assert!(
        fs.set_attributes_batch_with_publication(
            &mut d,
            &[],
            &[],
            &[CatalogUpdate {
                cnid: file,
                times: TIMES,
                attributes: None
            }]
        )
        .is_err()
    );
    assert!(!fs.requires_reopen());
    fs.flush(&mut d).unwrap();
    assert_eq!(
        fs.inline_attribute(&mut d, file, NAME).unwrap(),
        Some(b"earlier plan".to_vec())
    );
    assert_eq!(fs.catalog_record("/file").unwrap(), original_body);
}

#[test]
fn unrelated_shared_or_unallocated_fork_values_refuse_the_entire_batch() {
    let original = fixture(true, false, true);
    let fs = HfsPlus::open(&mut MemoryBackend::from_bytes(original.clone())).unwrap();
    let file = id(&fs, "/file");
    let keep = id(&fs, "/keep");
    let tree = volume::be32(&original, 1392) as usize * 4096;
    let mut leaf = volume::be32(&original, tree + 24);
    let mut target = None;
    let mut other = None;
    while leaf != 0 {
        let node = tree + leaf as usize * 4096;
        for index in 0..wire::u16be(&original, node + 10) as usize {
            let key = node + wire::u16be(&original, node + 4096 - 2 * (index + 1)) as usize;
            let body = key + 2 + wire::u16be(&original, key) as usize;
            if volume::be32(&original, body) == 0x20 {
                match volume::be32(&original, key + 4) {
                    cnid if cnid == file => target = Some(body),
                    cnid if cnid == keep => other = Some(body),
                    _ => {}
                }
            }
        }
        leaf = volume::be32(&original, node);
    }
    let target = target.unwrap();
    let other = other.unwrap();
    let extent = volume::be32(&original, target + 24);
    for shared in [false, true] {
        let mut broken = original.clone();
        if shared {
            // Independent wire edit: two different CNIDs claim one valid fork.
            broken[other + 8..other + 88].copy_from_slice(&original[target + 8..target + 88]);
        } else {
            let map = volume::be32(&broken, 1152) as usize * 4096;
            broken[map + extent as usize / 8] &= !(0x80 >> (extent % 8));
            let free = volume::be32(&broken, 1072) + 1;
            let alternate = broken.len() - 1024;
            for header in [1024, alternate] {
                wire::p32(&mut broken, header + 48, free);
            }
        }
        let mut d = MemoryBackend::from_bytes(broken.clone());
        let mut fs = HfsPlus::open(&mut d).unwrap();
        // Neither damaged value is a target; even a small root-only batch must
        // validate the complete fork ownership set before reserving anything.
        assert!(
            fs.set_attributes_batch(&mut d, &[(2, MARKER, Some(MARKER_VALUE))])
                .is_err()
        );
        fs.flush(&mut d).unwrap();
        assert!(d.as_slice() == broken);
    }
}
fn attempt(bytes: &[u8], failure: Option<usize>) -> (bool, fault::Disk) {
    let mut d = fault::Disk::new(bytes);
    let mut fs = HfsPlus::open(&mut d).unwrap();
    stage(&mut fs, &mut d);
    d.arm(failure);
    let pass = fs.flush(&mut d).is_ok();
    if !pass {
        let calls = d.0.lock().unwrap().calls;
        assert!(fs.flush(&mut d).is_err());
        assert_eq!(d.0.lock().unwrap().calls, calls);
    }
    (pass, d)
}
#[test]
fn large_payloads_catalog_and_generation_recover_as_one_complete_publication() {
    let mut commits = 0;
    let mut replays = 0;
    for sensitive in [false, true] {
        for existing in [false, true] {
            let original = fixture(true, sensitive, existing);
            let info = volume::be32(&original, 1036) as usize * 4096;
            let journal = volume::be64(&original, info + 36) as usize;
            let old = observe(&mut MemoryBackend::from_bytes(original.clone()));
            let (pass, complete) = attempt(&original, None);
            assert!(pass);
            let new = observe(&mut MemoryBackend::from_bytes(
                complete.0.lock().unwrap().durable.clone(),
            ));
            assert_ne!(old, new);
            let count = complete.0.lock().unwrap().calls;
            let mut pending = None;
            for failure in 0..count {
                let (pass, d) = attempt(&original, Some(failure));
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
                    let result = observe(&mut MemoryBackend::from_bytes(bytes));
                    assert!(
                        result == old || result == new,
                        "partial transaction {sensitive}/{existing}/{failure}/{policy}"
                    );
                    commits += 1;
                }
            }
            let pending = pending.expect("expected a committed pending journal");
            retain(
                &format!("transaction-pending-{sensitive}-{existing}.img"),
                &pending,
            );
            let mut completed = fault::Disk::new(&pending);
            HfsPlus::open(&mut completed).unwrap();
            let boundaries = completed.0.lock().unwrap().calls;
            for failure in 0..boundaries {
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
    println!(
        "ATTRIBUTE_TRANSACTION_MATRIX: {commits} commit + {replays} replay persistence snapshots; 4 scenarios"
    );
}
