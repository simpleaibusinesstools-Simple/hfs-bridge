//! Larger attribute deletion is checked against independent wire fixtures.
use fstool::{
    block::MemoryBackend,
    fs::hfs_plus::{
        FormatOpts, HfsPlus,
        attributes::{AttrRecord, Attributes},
        btree::ForkReader,
        volume_header::read_volume_header,
    },
};
use hfs_bridge::{
    volume,
    windows::{Access, Adapter, OpenRequest},
};
#[path = "support/attribute_wire.rs"]
mod wire;
const PATHS: [&str; 3] = ["/victim", "/survivor", "/last"];
#[test]
fn warm_catalog_ownership_tracks_data_resource_rename_and_deletion() {
    use fstool::fs::hfs_plus::{ForkEdit, PublicationMetadata};
    use std::path::Path;
    for journal in [false, true] {
        for sensitive in [false, true] {
            let (mut disk, ids) = fixture(journal, sensitive, 256, true);
            let mut fs = HfsPlus::open(&mut disk).unwrap();
            let name = format!("com.example.000.{}", "x".repeat(106));
            // Warm the index, then exercise real mutable CatalogMap access and
            // clean publications before the next ownership query.
            assert_eq!(
                fs.inline_attribute(&mut disk, ids[1], &name).unwrap(),
                Some(vec![0; 17])
            );
            for resource in [false, true] {
                fs.edit_fork_with_publication(
                    &mut disk,
                    Path::new(PATHS[0]),
                    resource,
                    ForkEdit::Write {
                        offset: 0,
                        bytes: &vec![0x57; 131071],
                    },
                    PublicationMetadata {
                        attributes: &[],
                        related: &[],
                        catalog: &[],
                    },
                )
                .unwrap();
                assert_eq!(
                    fs.inline_attribute(&mut disk, ids[1], &name).unwrap(),
                    Some(vec![0; 17])
                );
            }
            fs.create_file(&mut disk, "/new", &mut &b"fresh"[..], 5, 0o644, 501, 20, 0)
                .unwrap();
            fs.flush(&mut disk).unwrap();
            assert_eq!(
                fs.inline_attribute(&mut disk, ids[1], &name).unwrap(),
                Some(vec![0; 17])
            );
            fs.rename(&mut disk, "/new", "/renamed").unwrap();
            fs.remove(&mut disk, "/renamed").unwrap();
            fs.flush(&mut disk).unwrap();
            assert_eq!(
                fs.inline_attribute(&mut disk, ids[1], &name).unwrap(),
                Some(vec![0; 17])
            );
            let fs = HfsPlus::open(&mut disk).unwrap();
            assert_eq!(
                fs.inline_attribute(&mut disk, ids[1], &name).unwrap(),
                Some(vec![0; 17])
            );
        }
    }
}
#[test]
fn finder_public_view_and_updates_preserve_destination_private_catalog_fields() {
    let (disk, ids) = fixture(true, false, 256, false);
    let mut bytes = disk.into_bytes();
    let cat = volume::be32(&bytes, 1312) as usize * 4096;
    let size = wire::u16be(&bytes, cat + 32) as usize;
    let mut leaf = volume::be32(&bytes, cat + 24);
    let mut found = false;
    while leaf != 0 {
        let node = cat + leaf as usize * size;
        for i in 0..wire::u16be(&bytes, node + 10) as usize {
            let key = node + wire::u16be(&bytes, node + size - 2 * (i + 1)) as usize;
            let body = key + 2 + wire::u16be(&bytes, key) as usize;
            if wire::u16be(&bytes, body) == 2 && volume::be32(&bytes, body + 8) == ids[0] {
                bytes[body + 64..body + 72].copy_from_slice(b"DOCIDATE");
                bytes[body + 76..body + 80].copy_from_slice(b"GEN1");
                found = true;
            }
        }
        leaf = volume::be32(&bytes, node);
    }
    assert!(found);
    let mut disk = MemoryBackend::from_bytes(bytes);
    let mut fs = HfsPlus::open(&mut disk).unwrap();
    assert!(
        fs.inline_attribute(&mut disk, ids[0], "com.apple.FinderInfo")
            .unwrap()
            .is_none()
    );
    assert!(
        !fs.attribute_names(&mut disk, ids[0])
            .unwrap()
            .iter()
            .any(|n| n == "com.apple.FinderInfo")
    );
    for value in [Some([7; 32]), None] {
        fs.set_inline_attribute(
            &mut disk,
            ids[0],
            "com.apple.FinderInfo",
            value.as_ref().map(|b| b.as_slice()),
        )
        .unwrap();
        fs.flush(&mut disk).unwrap();
        let body = fs.catalog_record(PATHS[0]).unwrap();
        assert_eq!(&body[64..72], b"DOCIDATE");
        assert_eq!(&body[76..80], b"GEN1");
        let actual = fs
            .inline_attribute(&mut disk, ids[0], "com.apple.FinderInfo")
            .unwrap();
        if value.is_some() {
            let mut expected = vec![7; 32];
            expected[16..24].fill(0);
            expected[28..32].fill(0);
            assert_eq!(actual, Some(expected));
        } else {
            assert!(actual.is_none());
        }
    }
}
#[test]
fn macos_zero_attribute_comparison_selector_reads_and_edits_binary_names() {
    let (disk, ids) = fixture(true, false, 256, false);
    let mut bytes = disk.into_bytes();
    let start = volume::be32(&bytes, 1024 + 352 + 16) as usize * 4096;
    bytes[start + 51] = 0;
    let mut disk = MemoryBackend::from_bytes(bytes);
    let mut fs = HfsPlus::open(&mut disk).unwrap();
    fs.set_inline_attributes(
        &mut disk,
        ids[0],
        &[
            ("org.hfsbridge.Case", Some(b"upper")),
            ("org.hfsbridge.case", Some(b"lower")),
        ],
    )
    .unwrap();
    fs.flush(&mut disk).unwrap();
    assert_eq!(disk.as_slice()[start + 51], 0);
    let fs = HfsPlus::open(&mut disk).unwrap();
    for (name, value) in [
        ("org.hfsbridge.Case", b"upper"),
        ("org.hfsbridge.case", b"lower"),
    ] {
        assert_eq!(
            fs.inline_attribute(&mut disk, ids[0], name).unwrap(),
            Some(value.to_vec())
        );
    }
}
fn fixture(
    journal: bool,
    sensitive: bool,
    capacity: u32,
    sparse: bool,
) -> (MemoryBackend, [u32; 3]) {
    let mut disk = MemoryBackend::new(if sparse { 160 } else { 16 } * 1024 * 1024);
    let mut fs = HfsPlus::format(
        &mut disk,
        &FormatOpts {
            journaled: journal,
            ..Default::default()
        },
    )
    .unwrap();
    if sensitive {
        drop(fs);
        let mut bytes = disk.into_bytes();
        bytes[1024..1026].copy_from_slice(b"HX");
        wire::p16(&mut bytes, 1026, 5);
        let cat = volume::be32(&bytes, 1312) as usize * 4096;
        bytes[cat + 51] = 0xbc;
        let alt = bytes.len() - 1024;
        let hdr = bytes[1024..1536].to_vec();
        bytes[alt..alt + 512].copy_from_slice(&hdr);
        disk = MemoryBackend::from_bytes(bytes);
        fs = HfsPlus::open(&mut disk).unwrap();
    }
    let mut ids = [0; 3];
    for (i, path) in PATHS.iter().enumerate() {
        fs.create_file(&mut disk, path, &mut &b"payload"[..], 7, 0o640, 501, 20, 0)
            .unwrap();
        ids[i] = volume::be32(&fs.catalog_record(path).unwrap(), 8);
    }
    fs.flush(&mut disk).unwrap();
    drop(fs);
    let mut bytes = disk.into_bytes();
    let counts = if sparse { [1, 1, 1] } else { [80, 10, 1] };
    let mut records = Vec::new();
    for (id, count) in ids.into_iter().zip(counts) {
        for i in 0..count {
            let name = format!("com.example.{i:03}.{}", "x".repeat(106));
            records.push(wire::record(
                id,
                &name,
                &vec![i as u8; if sparse { 17 } else { 1801 }],
            ));
        }
    }
    // Mark every independently located file catalog body as having attributes.
    let cat = volume::be32(&bytes, 1312) as usize * 4096;
    let mut leaf = volume::be32(&bytes, cat + 24);
    while leaf != 0 {
        let ns = wire::u16be(&bytes, cat + 32) as usize;
        let node = cat + leaf as usize * ns;
        for i in 0..wire::u16be(&bytes, node + 10) as usize {
            let key = node + wire::u16be(&bytes, node + ns - 2 * (i + 1)) as usize;
            let body = key + 2 + wire::u16be(&bytes, key) as usize;
            if wire::u16be(&bytes, body) == 2 && ids.contains(&volume::be32(&bytes, body + 8)) {
                bytes[body + 3] |= 4;
            }
        }
        leaf = volume::be32(&bytes, node);
    }
    wire::install(&mut bytes, records, capacity, 4, sparse);
    (MemoryBackend::from_bytes(bytes), ids)
}
fn retain(bytes: &[u8], name: &str) {
    if let Some(path) = std::env::var_os("HFS_ATTRIBUTE_ARTIFACT_DIR") {
        std::fs::create_dir_all(&path).unwrap();
        std::fs::write(std::path::PathBuf::from(path).join(name), bytes).unwrap();
    }
}
#[test]
fn multi_level_inline_deletion_keeps_raw_records_then_collapses_to_empty() {
    for journal in [false, true] {
        for sensitive in [false, true] {
            let (mut disk, ids) = fixture(journal, sensitive, 256, false);
            let mut expected = wire::audit(disk.as_slice());
            let tree = volume::be32(disk.as_slice(), 1392) as usize * 4096;
            assert!(wire::u16be(disk.as_slice(), tree + 14) >= 3);
            retain(
                disk.as_slice(),
                &format!("attribute-baseline-{journal}-{sensitive}.img"),
            );
            let mut fs = HfsPlus::open(&mut disk).unwrap();
            for (step, (path, id)) in PATHS.into_iter().zip(ids).enumerate() {
                fs.remove(&mut disk, path).unwrap();
                fs.flush(&mut disk).unwrap();
                expected.retain(|record| volume::be32(record, 4) != id);
                assert_eq!(wire::audit(disk.as_slice()), expected);
                assert_eq!(wire::u16be(disk.as_slice(), tree + 14), [2, 1, 0][step]);
                assert!(fs.catalog_record(path).is_err());
                retain(
                    disk.as_slice(),
                    &format!("attribute-deleted-{step}-{journal}-{sensitive}.img"),
                );
            }
            HfsPlus::open(&mut disk).unwrap();
        }
    }
}
#[test]
fn continuation_maps_and_sparse_node_ids_survive_deletion() {
    let (mut disk, ids) = fixture(true, false, 30_722, true);
    let expected: Vec<_> = wire::audit(disk.as_slice())
        .into_iter()
        .filter(|record| volume::be32(record, 4) != ids[0])
        .collect();
    let mut fs = HfsPlus::open(&mut disk).unwrap();
    fs.remove(&mut disk, PATHS[0]).unwrap();
    fs.flush(&mut disk).unwrap();
    assert_eq!(wire::audit(disk.as_slice()), expected);
    HfsPlus::open(&mut disk).unwrap();
    retain(disk.as_slice(), "attribute-map-continuation.img");
}
#[test]
fn malformed_larger_trees_are_refused_before_any_staging() {
    let (disk, _) = fixture(false, false, 256, false);
    for variant in 0..11 {
        let mut bytes = disk.as_slice().to_vec();
        let tree = volume::be32(&bytes, 1392) as usize * 4096;
        let root = volume::be32(&bytes, tree + 16) as usize;
        let leaf = volume::be32(&bytes, tree + 24) as usize;
        let root_node = tree + root * 4096;
        let root_key = root_node + 14;
        let pointer = root_key + 2 + wire::u16be(&bytes, root_key) as usize;
        let leaf_node = tree + leaf * 4096;
        match variant {
            0 => wire::p32(&mut bytes, pointer, root as u32), // Cycle/shared child.
            1 => bytes[root_key + 15] ^= 1,                   // Stale index boundary key.
            2 => wire::p32(&mut bytes, leaf_node, 0),         // Broken leaf sibling.
            3 => wire::p32(&mut bytes, tree + 24, leaf as u32 + 1), // Wrong endpoint.
            4 => wire::p32(&mut bytes, tree + 20, 1),         // Count mismatch.
            5 => bytes[leaf_node + 9] = 2,                    // Wrong child height.
            6 => {
                bytes[tree + 248 + 255 / 8] |= 0x80 >> (255 % 8);
                let free = volume::be32(&bytes, tree + 40);
                wire::p32(&mut bytes, tree + 40, free - 1);
            } // Unreachable allocation.
            7 => wire::p16(&mut bytes, leaf_node + 4092, 4094), // Offset table overlap.
            8 => wire::p32(&mut bytes, tree, root as u32),    // Map chain targets index.
            9 => {
                bytes[tree + 248 + leaf / 8] &= !(0x80 >> (leaf % 8));
                let free = volume::be32(&bytes, tree + 40);
                wire::p32(&mut bytes, tree + 40, free + 1);
            } // Free leaf pointer.
            10 => wire::p32(&mut bytes, pointer, 256),        // Out-of-range child.
            _ => unreachable!(),
        }
        let before = bytes.clone();
        let mut disk = MemoryBackend::from_bytes(bytes);
        let mut fs = HfsPlus::open(&mut disk).unwrap();
        let body = fs.catalog_record(PATHS[0]).unwrap();
        assert!(
            fs.set_inline_attribute(
                &mut disk,
                volume::be32(&body, 8),
                "com.example.new",
                Some(b"new")
            )
            .is_err(),
            "attribute variant {variant}"
        );
        assert!(fs.remove(&mut disk, PATHS[0]).is_err(), "variant {variant}");
        assert_eq!(fs.catalog_record(PATHS[0]).unwrap(), body);
        assert!(disk.as_slice() == before, "refusal changed bytes");
        let mut control = MemoryBackend::from_bytes(before);
        HfsPlus::open(&mut control)
            .unwrap()
            .flush(&mut control)
            .unwrap();
        fs.flush(&mut disk).unwrap();
        assert!(
            disk.as_slice() == control.as_slice(),
            "refusal staged changes"
        );
        let before_open = disk.as_slice().to_vec();
        let mut adapter = Adapter::from_device(disk).unwrap();
        // Basic Windows flags now consult the attribute tree. A corrupt tree
        // must be refused at open, before a deletion handle can be acquired.
        assert!(
            adapter
                .open(
                    r"\victim",
                    OpenRequest {
                        access: Access::ALL,
                        ..Default::default()
                    },
                )
                .is_err(),
            "corrupt attribute tree opened: variant {variant}"
        );
        assert!(adapter.failure().is_none());
        assert_eq!(adapter.shutdown().unwrap().as_slice(), before_open);
    }
}
#[test]
fn opaque_non_target_records_are_preserved_and_target_unknown_is_refused() {
    let (disk, ids) = fixture(false, false, 256, false);
    let mut bytes = disk.into_bytes();
    let tree = volume::be32(&bytes, 1392) as usize * 4096;
    let mut leaf = volume::be32(&bytes, tree + 24) as usize;
    while leaf != 0 {
        let node = tree + leaf * 4096;
        let key = node + 14;
        if volume::be32(&bytes, key + 4) == ids[1] {
            let body = key + 2 + wire::u16be(&bytes, key) as usize;
            wire::p32(&mut bytes, body, 0x7fffffff);
        }
        leaf = volume::be32(&bytes, node) as usize;
    }
    let expected: Vec<_> = wire::audit(&bytes)
        .into_iter()
        .filter(|record| volume::be32(record, 4) != ids[0])
        .collect();
    let mut disk = MemoryBackend::from_bytes(bytes);
    let mut fs = HfsPlus::open(&mut disk).unwrap();
    fs.remove(&mut disk, PATHS[0]).unwrap();
    fs.flush(&mut disk).unwrap();
    assert_eq!(wire::audit(disk.as_slice()), expected);
    let before = disk.as_slice().to_vec();
    assert!(fs.remove(&mut disk, PATHS[1]).is_err());
    assert!(disk.as_slice() == before);
}
#[test]
fn attribute_names_use_binary_order_even_on_case_folding_hfs_plus() {
    let (disk, ids) = fixture(false, false, 256, false);
    let mut bytes = disk.into_bytes();
    // Replace the already reserved tree in this synthetic fixture, releasing
    // its old reservation explicitly before independently installing a new one.
    let block = volume::be32(&bytes, 1392);
    let count = volume::be32(&bytes, 1388);
    let allocation = volume::be32(&bytes, 1152) as usize * 4096;
    for id in block..block + count {
        bytes[allocation + id as usize / 8] &= !(0x80 >> (id % 8));
    }
    let free = volume::be32(&bytes, 1072);
    wire::p32(&mut bytes, 1072, free + count);
    wire::install(
        &mut bytes,
        vec![
            wire::record(ids[0], "com.example.CASE", b"UPPER"),
            wire::record(ids[0], "com.example.case", b"lower"),
        ],
        8,
        4,
        false,
    );
    let mut disk = MemoryBackend::from_bytes(bytes);
    let vh = read_volume_header(&mut disk).unwrap();
    let reader = ForkReader::from_inline(&vh.attributes_file, vh.block_size, "test").unwrap();
    let attributes = Attributes::open(&mut disk, reader, false).unwrap();
    for (name, expected) in [
        ("com.example.CASE", b"UPPER"),
        ("com.example.case", b"lower"),
    ] {
        assert!(
            matches!(attributes.lookup(&mut disk,ids[0],name).unwrap(),Some(AttrRecord::Inline{data}) if data == expected)
        );
    }
    assert!(
        attributes
            .lookup(&mut disk, ids[0], "com.example.Case")
            .unwrap()
            .is_none()
    );
}

#[test]
fn root_and_volume_attributes_remain_opaque_to_user_file_deletion() {
    let (disk, ids) = fixture(false, false, 256, false);
    let mut bytes = disk.into_bytes();
    let block = volume::be32(&bytes, 1392);
    let count = volume::be32(&bytes, 1388);
    let allocation = volume::be32(&bytes, 1152) as usize * 4096;
    for id in block..block + count {
        bytes[allocation + id as usize / 8] &= !(0x80 >> (id % 8));
    }
    let free = volume::be32(&bytes, 1072);
    wire::p32(&mut bytes, 1072, free + count);
    let expected = vec![
        wire::record(1, "com.example.volume", b"volume metadata"),
        wire::record(2, "com.example.root", b"root metadata"),
    ];
    let mut records = expected.clone();
    records.push(wire::record(ids[0], "com.example.file", b"victim metadata"));
    wire::install(&mut bytes, records, 8, 4, false);
    let mut disk = MemoryBackend::from_bytes(bytes);
    let mut fs = HfsPlus::open(&mut disk).unwrap();
    fs.remove(&mut disk, PATHS[0]).unwrap();
    fs.flush(&mut disk).unwrap();
    assert_eq!(wire::audit(disk.as_slice()), expected);
}

#[test]
fn inline_edits_preserve_binary_names_raw_records_forks_and_ownership() {
    for journal in [false, true] {
        for sensitive in [false, true] {
            let (mut disk, ids) = fixture(journal, sensitive, 256, false);
            let mut fs = HfsPlus::open(&mut disk).unwrap();
            {
                use std::io::Write;
                let mut resource = fs
                    .open_resource_fork_rw(&mut disk, std::path::Path::new(PATHS[0]))
                    .unwrap();
                resource.write_all(b"resource payload\0\xff").unwrap();
                resource.sync().unwrap();
            }
            let before = fs.catalog_record(PATHS[0]).unwrap();
            let mut expected = wire::audit(disk.as_slice());
            for (step, (name, value)) in [
                ("com.example.CASE", Some(&b"UPPER\0\xff"[..])),
                ("com.example.case", Some(&b"lower"[..])),
                ("com.example.CASE", Some(&b"replacement"[..])),
                ("com.example.CASE", None),
                ("com.example.zero", Some(&b""[..])),
                ("com.example.e\u{301}", Some(&b"decomposed"[..])),
                ("com.example.\u{e9}", Some(&b"composed"[..])),
            ]
            .into_iter()
            .enumerate()
            {
                fs.set_inline_attribute(&mut disk, ids[0], name, value)
                    .unwrap();
                assert!(
                    fs.inline_attribute(&mut disk, ids[0], name).is_err(),
                    "staged read must not return stale data"
                );
                assert!(
                    fs.remove(&mut disk, PATHS[1]).is_err(),
                    "mixed pending deletion must be refused"
                );
                fs.flush(&mut disk).unwrap();
                let key = wire::record(ids[0], name, &[]);
                let key_length = 2 + usize::from(wire::u16be(&key, 0));
                expected.retain(|raw| raw[..key_length.min(raw.len())] != key[..key_length]);
                if let Some(value) = value {
                    let mut new_record = wire::record(ids[0], name, value);
                    if value.len() % 2 != 0 {
                        *new_record.last_mut().unwrap() = 0;
                    }
                    expected.push(new_record);
                }
                let actual = wire::audit(disk.as_slice());
                let mut actual_sorted = actual.clone();
                actual_sorted.sort();
                let mut sorted = expected.clone();
                sorted.sort();
                assert!(
                    actual_sorted == sorted,
                    "independent raw records differ at edit {step}"
                );
                assert_eq!(
                    fs.inline_attribute(&mut disk, ids[0], name).unwrap(),
                    value.map(Vec::from)
                );
                let after = fs.catalog_record(PATHS[0]).unwrap();
                assert_eq!(
                    after, before,
                    "already-set flag and all catalog fields retained"
                );
                retain(
                    disk.as_slice(),
                    &format!("attribute-edit-{journal}-{sensitive}-{step}.img"),
                );
            }
            assert!(
                fs.inline_attribute(&mut disk, ids[0], "com.example.Case")
                    .unwrap()
                    .is_none()
            );
            assert_eq!(
                fs.inline_attribute(&mut disk, ids[0], "com.example.case")
                    .unwrap()
                    .unwrap(),
                b"lower"
            );
            assert_eq!(fs.attribute_names(&mut disk, ids[0]).unwrap().len(), 84);
            drop(fs);
            HfsPlus::open(&mut disk).unwrap();
        }
    }
}

#[test]
fn first_attribute_tree_initialization_and_empty_removal_update_catalog_flags() {
    for journal in [false, true] {
        let mut disk = MemoryBackend::new(16 * 1024 * 1024);
        let mut fs = HfsPlus::format(
            &mut disk,
            &FormatOpts {
                journaled: journal,
                ..Default::default()
            },
        )
        .unwrap();
        fs.create_file(
            &mut disk,
            "/file",
            &mut &b"payload"[..],
            7,
            0o640,
            501,
            20,
            0,
        )
        .unwrap();
        fs.create_dir(&mut disk, "/folder", 0o750, 502, 21, 0)
            .unwrap();
        fs.flush(&mut disk).unwrap();
        let file = volume::be32(&fs.catalog_record("/file").unwrap(), 8);
        let folder = volume::be32(&fs.catalog_record("/folder").unwrap(), 8);
        let before = fs.catalog_record("/file").unwrap();
        let free = read_volume_header(&mut disk).unwrap().free_blocks;
        let longest = "x".repeat(127);
        let payload = vec![0x9a; 3794];
        fs.set_inline_attribute(&mut disk, file, &longest, Some(&payload))
            .unwrap();
        fs.flush(&mut disk).unwrap();
        let header = read_volume_header(&mut disk).unwrap();
        assert_eq!(header.free_blocks, free - 8);
        assert_eq!(header.attributes_file.logical_size, 32768);
        assert_eq!(header.attributes_file.total_blocks, 8);
        let tree = header.attributes_file.extents[0].start_block as usize * 4096;
        assert!(
            disk.as_slice()[tree + 120..tree + 248]
                .iter()
                .all(|&byte| byte == 0)
        );
        assert_eq!(
            wire::audit_initialized(disk.as_slice()),
            vec![wire::record(file, &longest, &payload)]
        );
        let mut expected = before.clone();
        expected[3] |= 4;
        assert_eq!(fs.catalog_record("/file").unwrap(), expected);
        assert_eq!(
            fs.inline_attribute(&mut disk, file, &longest)
                .unwrap()
                .unwrap(),
            payload
        );
        fs.set_inline_attribute(
            &mut disk,
            folder,
            "com.example.directory",
            Some(b"directory metadata"),
        )
        .unwrap();
        fs.flush(&mut disk).unwrap();
        assert_eq!(
            volume::be16(&fs.catalog_record("/folder").unwrap(), 2) & 4,
            4
        );
        fs.set_inline_attribute(&mut disk, file, &longest, None)
            .unwrap();
        fs.flush(&mut disk).unwrap();
        assert_eq!(fs.catalog_record("/file").unwrap(), before);
        fs.set_inline_attribute(&mut disk, folder, "com.example.directory", None)
            .unwrap();
        fs.flush(&mut disk).unwrap();
        assert!(wire::audit_initialized(disk.as_slice()).is_empty());
        assert_eq!(
            volume::be16(&fs.catalog_record("/folder").unwrap(), 2) & 4,
            0
        );
        assert_eq!(
            read_volume_header(&mut disk).unwrap().free_blocks,
            free - 8,
            "empty tree retains its reservation"
        );
        retain(
            disk.as_slice(),
            &format!("attribute-initialized-empty-{journal}.img"),
        );
        drop(fs);
        HfsPlus::open(&mut disk).unwrap();
    }
}

#[test]
fn inline_bounds_reserved_names_and_tree_capacity_refuse_without_staging() {
    let mut disk = MemoryBackend::new(16 * 1024 * 1024);
    let mut fs = HfsPlus::format(&mut disk, &FormatOpts::default()).unwrap();
    fs.create_file(
        &mut disk,
        "/file",
        &mut &b"payload"[..],
        7,
        0o644,
        501,
        20,
        0,
    )
    .unwrap();
    fs.flush(&mut disk).unwrap();
    let id = volume::be32(&fs.catalog_record("/file").unwrap(), 8);
    let original = fs.catalog_record("/file").unwrap();
    let bytes = disk.as_slice().to_vec();
    for (name, value) in [
        ("".to_owned(), vec![]),
        ("x".repeat(128), vec![]),
        ("a\0b".to_owned(), vec![]),
        ("com.example.long".to_owned(), vec![0; 16 * 1024 * 1024 + 1]),
        ("com.apple.FinderInfo".to_owned(), vec![0; 31]),
        ("com.apple.ResourceFork".to_owned(), vec![]),
        ("com.apple.decmpfs".to_owned(), vec![]),
        ("com.apple.system.Security".to_owned(), vec![]),
    ] {
        assert!(
            fs.set_inline_attribute(&mut disk, id, &name, Some(&value))
                .is_err()
        );
        assert_eq!(fs.catalog_record("/file").unwrap(), original);
        assert!(disk.as_slice() == bytes);
    }
    assert!(
        fs.set_inline_attribute(&mut disk, 2, "com.example.root", Some(b"root"))
            .is_err()
    );
    let payload = vec![0x37; 3802];
    let mut inserted = 0;
    loop {
        let before = disk.as_slice().to_vec();
        let body = fs.catalog_record("/file").unwrap();
        match fs.set_inline_attribute(
            &mut disk,
            id,
            &format!("com.example.{inserted}"),
            Some(&payload),
        ) {
            Ok(()) => {
                fs.flush(&mut disk).unwrap();
                inserted += 1;
                assert!(inserted < 8);
            }
            Err(_) => {
                assert!(inserted >= 2);
                assert!(disk.as_slice() == before);
                assert_eq!(fs.catalog_record("/file").unwrap(), body);
                let mut control = MemoryBackend::from_bytes(before);
                HfsPlus::open(&mut control)
                    .unwrap()
                    .flush(&mut control)
                    .unwrap();
                fs.flush(&mut disk).unwrap();
                // Reopening deliberately discards the allocation search hint.
                // It is advisory; compare every other byte of both headers.
                let mut actual = disk.as_slice().to_vec();
                let mut expected = control.as_slice().to_vec();
                for offset in [1076, actual.len() - 1024 + 52] {
                    actual[offset..offset + 4].fill(0);
                    expected[offset..offset + 4].fill(0);
                }
                assert!(actual == expected, "capacity refusal staged hidden changes");
                break;
            }
        }
    }
    retain(disk.as_slice(), "attribute-existing-reservation-full.img");
}

#[test]
fn attribute_batches_preflight_all_values_before_one_catalog_publication() {
    let (mut disk, ids) = fixture(true, false, 256, false);
    let mut fs = HfsPlus::open(&mut disk).unwrap();
    let before = disk.as_slice().to_vec();
    let body = fs.catalog_record(PATHS[0]).unwrap();
    for changes in [
        vec![
            ("com.example.first", Some(&b"valid"[..])),
            ("com.apple.decmpfs", Some(&b"bad"[..])),
        ],
        vec![
            ("com.example.duplicate", Some(&b"one"[..])),
            ("com.example.duplicate", None),
        ],
    ] {
        assert!(
            fs.set_inline_attributes(&mut disk, ids[0], &changes)
                .is_err()
        );
        assert!(disk.as_slice() == before);
        assert_eq!(fs.catalog_record(PATHS[0]).unwrap(), body);
    }
    let first = "com.example.000.".to_owned() + &"x".repeat(106);
    let old = wire::audit(disk.as_slice());
    fs.set_inline_attributes(
        &mut disk,
        ids[0],
        &[
            ("com.example.CASE", Some(b"UPPER")),
            ("com.example.case", Some(b"lower")),
            (&first, None),
        ],
    )
    .unwrap();
    fs.flush(&mut disk).unwrap();
    assert_eq!(
        fs.inline_attribute(&mut disk, ids[0], "com.example.CASE")
            .unwrap()
            .unwrap(),
        b"UPPER"
    );
    assert_eq!(
        fs.inline_attribute(&mut disk, ids[0], "com.example.case")
            .unwrap()
            .unwrap(),
        b"lower"
    );
    assert!(
        fs.inline_attribute(&mut disk, ids[0], &first)
            .unwrap()
            .is_none()
    );
    let records = wire::audit(disk.as_slice());
    assert_eq!(records.len(), old.len() + 1);
    for record in old
        .into_iter()
        .filter(|raw| wire::order(raw).1 != first.encode_utf16().collect::<Vec<_>>())
    {
        assert!(
            records.contains(&record),
            "batch changed unrelated raw record"
        );
    }
    retain(disk.as_slice(), "attribute-atomic-batch.img");
}

#[test]
fn first_attribute_allocation_refuses_full_disk_and_keeps_existing_files_usable() {
    let mut disk = MemoryBackend::new(8 * 1024 * 1024);
    let mut fs = HfsPlus::format(
        &mut disk,
        &FormatOpts {
            journaled: true,
            ..Default::default()
        },
    )
    .unwrap();
    fs.create_file(
        &mut disk,
        "/file",
        &mut &b"old bytes"[..],
        9,
        0o644,
        501,
        20,
        0,
    )
    .unwrap();
    fs.create_file(&mut disk, "/filler", &mut &b""[..], 0, 0o644, 501, 20, 0)
        .unwrap();
    fs.flush(&mut disk).unwrap();
    let free = read_volume_header(&mut disk).unwrap().free_blocks;
    fs.set_data_allocation(
        &mut disk,
        std::path::Path::new("/filler"),
        u64::from(free) * 4096,
        false,
    )
    .unwrap();
    assert_eq!(read_volume_header(&mut disk).unwrap().free_blocks, 0);
    let body = fs.catalog_record("/file").unwrap();
    let cnid = volume::be32(&body, 8);
    let bytes = disk.as_slice().to_vec();
    assert!(
        fs.set_inline_attribute(&mut disk, cnid, "com.example.first", Some(b"value"))
            .is_err()
    );
    assert!(disk.as_slice() == bytes);
    assert_eq!(fs.catalog_record("/file").unwrap(), body);
    assert!(fs.attribute_names(&mut disk, cnid).unwrap().is_empty());
    fs.set_catalog_times(cnid, [None, None, None, Some(123)])
        .unwrap();
    fs.flush(&mut disk).unwrap();
    assert_eq!(volume::be32(&fs.catalog_record("/file").unwrap(), 20), 123);
    let mut payload = Vec::new();
    use std::io::Read;
    fs.open_file_reader(&mut disk, "/file")
        .unwrap()
        .read_to_end(&mut payload)
        .unwrap();
    assert_eq!(payload, b"old bytes");
    retain(disk.as_slice(), "attribute-initial-full-disk.img");
}
