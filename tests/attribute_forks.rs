//! Fork-backed attribute fixtures encoded independently of the engine.
use fstool::{
    block::MemoryBackend,
    fs::hfs_plus::{FormatOpts, HfsPlus},
};
use hfs_bridge::volume;
#[path = "support/attribute_wire.rs"]
#[allow(dead_code)]
mod wire;
const NAME: &str = "com.example.large";
fn raw(cnid: u32, name: &str, logical: u32, extents: &[(u32, u32)], length: usize) -> Vec<u8> {
    let mut record = wire::record(cnid, name, &[]);
    record.truncate(14 + name.encode_utf16().count() * 2);
    wire::p32(&mut record, 8, logical);
    record.extend_from_slice(&(if logical == 0 { 0x20u32 } else { 0x30u32 }).to_be_bytes());
    record.extend_from_slice(&0u32.to_be_bytes());
    if logical == 0 {
        record.extend_from_slice(&(length as u64).to_be_bytes());
        record.extend_from_slice(&4096u32.to_be_bytes());
        record.extend_from_slice(&9u32.to_be_bytes());
    }
    for i in 0..8 {
        let (start, count) = extents.get(i).copied().unwrap_or_default();
        record.extend_from_slice(&start.to_be_bytes());
        record.extend_from_slice(&count.to_be_bytes());
    }
    record
}
fn fixture(journal: bool, sensitive: bool) -> (Vec<u8>, u32, Vec<u8>, Vec<u32>) {
    let mut disk = MemoryBackend::new(16 * 1024 * 1024);
    let mut fs = HfsPlus::format(
        &mut disk,
        &FormatOpts {
            journaled: journal,
            ..Default::default()
        },
    )
    .unwrap();
    fs.create_file(&mut disk, "/file", &mut &b"data"[..], 4, 0o640, 501, 20, 0)
        .unwrap();
    let cnid = volume::be32(&fs.catalog_record("/file").unwrap(), 8);
    fs.flush(&mut disk).unwrap();
    drop(fs);
    let mut bytes = disk.into_bytes();
    if sensitive {
        bytes[1024..1026].copy_from_slice(b"HX");
        wire::p16(&mut bytes, 1026, 5);
        let cat = volume::be32(&bytes, 1312) as usize * 4096;
        bytes[cat + 51] = 0xbc;
        // This independently encoded HFSX fixture has only the root folder.
        // HFSX requires its HasFolderCount flag even with zero subfolders.
        let node_size = wire::u16be(&bytes, cat + 32) as usize;
        let mut leaf = volume::be32(&bytes, cat + 24);
        let mut roots = 0;
        while leaf != 0 {
            let node = cat + leaf as usize * node_size;
            for i in 0..wire::u16be(&bytes, node + 10) as usize {
                let key = node + wire::u16be(&bytes, node + node_size - 2 * (i + 1)) as usize;
                let body = key + 2 + wire::u16be(&bytes, key) as usize;
                if wire::u16be(&bytes, body) == 1 {
                    assert_eq!(volume::be32(&bytes, body + 8), 2);
                    let flags = wire::u16be(&bytes, body + 2) | 0x10;
                    wire::p16(&mut bytes, body + 2, flags);
                    wire::p32(&mut bytes, body + 84, 0);
                    roots += 1;
                }
            }
            leaf = volume::be32(&bytes, node);
        }
        assert_eq!(roots, 1);
    }
    let bitmap = volume::be32(&bytes, 1152) as usize * 4096;
    let mut blocks = Vec::new();
    let payload = (0..9 * 4096 - 37)
        .map(|i| (i * 17 + i / 127) as u8)
        .collect::<Vec<_>>();
    for block in (16..volume::be32(&bytes, 1068) - 1).step_by(2) {
        if bytes[bitmap + block as usize / 8] & (0x80 >> (block % 8)) != 0 {
            continue;
        }
        bytes[bitmap + block as usize / 8] |= 0x80 >> (block % 8);
        let begin = blocks.len() * 4096;
        let size = 4096.min(payload.len() - begin);
        bytes[block as usize * 4096..block as usize * 4096 + size]
            .copy_from_slice(&payload[begin..begin + size]);
        blocks.push(block);
        if blocks.len() == 9 {
            break;
        }
    }
    assert_eq!(blocks.len(), 9);
    let free = volume::be32(&bytes, 1072);
    wire::p32(&mut bytes, 1072, free - 9);
    let extents = blocks.iter().map(|&start| (start, 1)).collect::<Vec<_>>();
    // Set HasAttributes on the independently found file record.
    let cat = volume::be32(&bytes, 1312) as usize * 4096;
    let node_size = wire::u16be(&bytes, cat + 32) as usize;
    let leaf = cat + volume::be32(&bytes, cat + 24) as usize * node_size;
    for i in 0..wire::u16be(&bytes, leaf + 10) as usize {
        let key = leaf + wire::u16be(&bytes, leaf + node_size - 2 * (i + 1)) as usize;
        let body = key + 2 + wire::u16be(&bytes, key) as usize;
        if wire::u16be(&bytes, body) == 2 && volume::be32(&bytes, body + 8) == cnid {
            bytes[body + 3] |= 4;
        }
    }
    wire::install(
        &mut bytes,
        vec![
            raw(cnid, NAME, 0, &extents[..8], payload.len()),
            raw(cnid, NAME, 8, &extents[8..], 0),
        ],
        8,
        4,
        false,
    );
    (bytes, cnid, payload, blocks)
}
fn retain(bytes: &[u8], name: &str) {
    if let Some(path) = std::env::var_os("HFS_ATTRIBUTE_FORK_ARTIFACT_DIR") {
        std::fs::create_dir_all(&path).unwrap();
        std::fs::write(std::path::PathBuf::from(path).join(name), bytes).unwrap();
    }
}
fn assert_unused_attribute_nodes_erased(bytes: &[u8]) {
    let start = volume::be32(bytes, 1024 + 352 + 16) as usize * 4096;
    let size = wire::u16be(bytes, start + 32) as usize;
    let total = volume::be32(bytes, start + 36) as usize;
    let map = wire::u16be(bytes, start + size - 6) as usize;
    assert!(total <= (size - map - 8) * 8);
    for id in 1..total {
        if bytes[start + map + id / 8] & (0x80 >> (id % 8)) == 0 {
            assert!(
                bytes[start + id * size..start + (id + 1) * size]
                    .iter()
                    .all(|byte| *byte == 0),
                "unused attribute node {id} retained data"
            );
        }
    }
}
#[test]
fn fragmented_attribute_continuation_reads_exact_payload_and_keeps_source() {
    for (journal, sensitive) in [(false, false), (true, false), (true, true)] {
        let (bytes, cnid, payload, _) = fixture(journal, sensitive);
        let mut disk = MemoryBackend::from_bytes(bytes.clone());
        let fs = HfsPlus::open(&mut disk).unwrap();
        assert_eq!(volume::be16(&fs.catalog_record("/file").unwrap(), 2) & 4, 4);
        assert_eq!(fs.attribute_names(&mut disk, cnid).unwrap(), [NAME]);
        let index = fs.attribute_read_index(&mut disk).unwrap();
        assert_eq!(index.names(cnid), [NAME]);
        assert_eq!(
            fs.indexed_attribute(&mut disk, &index, cnid, NAME).unwrap(),
            Some(payload.clone())
        );
        assert_eq!(
            fs.inline_attribute(&mut disk, cnid, NAME).unwrap(),
            Some(payload)
        );
        assert!(
            fs.inline_attribute(&mut disk, cnid, "missing")
                .unwrap()
                .is_none()
        );
        assert_eq!(disk.as_slice(), bytes);
        retain(
            &bytes,
            &format!("attribute-fork-read-{journal}-{sensitive}.img"),
        );
    }
}
#[test]
fn removing_file_reclaims_complete_attribute_chain_in_same_flush() {
    for journal in [false, true] {
        let (bytes, _, _, blocks) = fixture(journal, false);
        let free = volume::be32(&bytes, 1072);
        let mut disk = MemoryBackend::from_bytes(bytes.clone());
        let mut fs = HfsPlus::open(&mut disk).unwrap();
        fs.remove(&mut disk, "/file").unwrap();
        assert_eq!(disk.as_slice(), bytes);
        fs.flush(&mut disk).unwrap();
        assert_unused_attribute_nodes_erased(disk.as_slice());
        assert!(fs.catalog_record("/file").is_err());
        let bitmap = volume::be32(disk.as_slice(), 1152) as usize * 4096;
        for block in &blocks {
            assert_eq!(
                disk.as_slice()[bitmap + *block as usize / 8] & (0x80 >> (*block % 8)),
                0
            );
        }
        assert_eq!(volume::be32(disk.as_slice(), 1072), free + 10);
        retain(
            disk.as_slice(),
            &format!("attribute-fork-file-deleted-{journal}.img"),
        );
    }
}
#[test]
fn attribute_fork_edits_replace_shrink_and_reclaim_without_changing_file_data() {
    for (journal, sensitive) in [(false, false), (true, false), (true, true)] {
        let (bytes, cnid, old, blocks) = fixture(journal, sensitive);
        let original_free = volume::be32(&bytes, 1072);
        let mut disk = MemoryBackend::from_bytes(bytes.clone());
        let mut fs = HfsPlus::open(&mut disk).unwrap();
        let original_catalog = fs.catalog_record("/file").unwrap();
        let value = (0..70_019).map(|i| (i * 29) as u8).collect::<Vec<_>>();
        fs.set_inline_attributes(
            &mut disk,
            cnid,
            &[
                (NAME, Some(&value)),
                ("com.example.small", Some(b"sibling")),
            ],
        )
        .unwrap();
        assert_eq!(disk.as_slice(), bytes, "preflight/staging changed source");
        fs.flush(&mut disk).unwrap();
        assert_unused_attribute_nodes_erased(disk.as_slice());
        assert_eq!(
            fs.inline_attribute(&mut disk, cnid, NAME).unwrap(),
            Some(value.clone())
        );
        assert_eq!(
            fs.catalog_record("/file").unwrap()[88..248],
            original_catalog[88..248]
        );
        let bitmap = volume::be32(disk.as_slice(), 1152) as usize * 4096;
        for block in &blocks {
            assert_eq!(
                disk.as_slice()[bitmap + *block as usize / 8] & (0x80 >> (*block % 8)),
                0
            );
        }
        assert_eq!(
            volume::be32(disk.as_slice(), 1072),
            original_free + 9 - value.len().div_ceil(4096) as u32
        );
        retain(
            disk.as_slice(),
            &format!("attribute-fork-replaced-{journal}-{sensitive}.img"),
        );
        drop(fs);
        let mut fs = HfsPlus::open(&mut disk).unwrap();
        fs.set_inline_attribute(&mut disk, cnid, NAME, Some(b"small now"))
            .unwrap();
        fs.flush(&mut disk).unwrap();
        assert_unused_attribute_nodes_erased(disk.as_slice());
        assert_eq!(
            fs.inline_attribute(&mut disk, cnid, NAME).unwrap(),
            Some(b"small now".to_vec())
        );
        assert_eq!(volume::be32(disk.as_slice(), 1072), original_free + 9);
        retain(
            disk.as_slice(),
            &format!("attribute-fork-shrunk-{journal}-{sensitive}.img"),
        );
        assert_ne!(old, b"small now");
    }
}
#[test]
fn new_fork_attribute_tree_and_payload_are_one_publication() {
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
        "/new",
        &mut &b"file contents"[..],
        13,
        0o600,
        501,
        20,
        0,
    )
    .unwrap();
    fs.flush(&mut disk).unwrap();
    let cnid = volume::be32(&fs.catalog_record("/new").unwrap(), 8);
    let before = disk.as_slice().to_vec();
    let value = vec![0x5a; 3803];
    fs.set_inline_attribute(&mut disk, cnid, NAME, Some(&value))
        .unwrap();
    assert_eq!(disk.as_slice(), before);
    fs.flush(&mut disk).unwrap();
    assert_eq!(
        fs.inline_attribute(&mut disk, cnid, NAME).unwrap(),
        Some(value)
    );
    retain(disk.as_slice(), "attribute-fork-created.img");
    fs.set_inline_attribute(&mut disk, cnid, NAME, None)
        .unwrap();
    fs.flush(&mut disk).unwrap();
    assert_eq!(
        fs.attribute_names(&mut disk, cnid).unwrap(),
        Vec::<String>::new()
    );
    retain(disk.as_slice(), "attribute-fork-removed.img");
}
#[test]
fn fork_continuation_in_same_leaf_is_equivalent() {
    let (mut bytes, cnid, payload, _) = fixture(false, false);
    let tree = volume::be32(&bytes, 1392) as usize * 4096;
    let raw = wire::audit(&bytes);
    let mut leaf = vec![0; 4096];
    leaf[8] = 0xff;
    leaf[9] = 1;
    wire::p16(&mut leaf, 10, 2);
    let mut position = 14;
    for (i, record) in raw.iter().enumerate() {
        wire::p16(&mut leaf, 4096 - 2 * (i + 1), position as u16);
        leaf[position..position + record.len()].copy_from_slice(record);
        position += record.len();
    }
    wire::p16(&mut leaf, 4090, position as u16);
    bytes[tree + 4096..tree + 8192].copy_from_slice(&leaf);
    bytes[tree + 8192..tree + 4 * 4096].fill(0);
    wire::p16(&mut bytes, tree + 14, 1);
    for offset in [16, 24, 28] {
        wire::p32(&mut bytes, tree + offset, 1);
    }
    wire::p32(&mut bytes, tree + 40, 6);
    bytes[tree + 248] = 0xc0;
    assert_eq!(wire::audit(&bytes), raw);
    let mut disk = MemoryBackend::from_bytes(bytes.clone());
    let fs = HfsPlus::open(&mut disk).unwrap();
    assert_eq!(
        fs.inline_attribute(&mut disk, cnid, NAME).unwrap(),
        Some(payload)
    );
    retain(&bytes, "attribute-fork-same-leaf.img");
}
#[test]
fn malformed_attribute_forks_fail_without_mutation() {
    let (baseline, cnid, _, blocks) = fixture(true, false);
    let tree = volume::be32(&baseline, 1392) as usize * 4096;
    let primary = tree + volume::be32(&baseline, tree + 24) as usize * 4096 + 14;
    let continuation = tree + volume::be32(&baseline, tree + 28) as usize * 4096 + 14;
    let body = primary + 14 + NAME.len() * 2;
    let extra = continuation + 14 + NAME.len() * 2;
    for variant in 0..14 {
        let mut bytes = baseline.clone();
        match variant {
            0 => wire::p32(&mut bytes, continuation + 8, 7),
            1 => wire::p32(&mut bytes, continuation + 8, 9),
            2 => wire::p32(&mut bytes, extra, 0x10),
            3 => wire::p32(&mut bytes, body + 20, 8),
            4 => wire::p32(&mut bytes, body + 20, 10),
            5 => bytes[body + 8..body + 16].copy_from_slice(&u64::MAX.to_be_bytes()),
            6 => wire::p32(&mut bytes, extra + 8, blocks[0]),
            7 => wire::p32(&mut bytes, extra + 8, u32::MAX),
            8 => wire::p32(&mut bytes, body + 24 + 3 * 8 + 4, 0),
            9 => wire::p32(&mut bytes, extra + 16, 1),
            10 => {
                let bitmap = volume::be32(&bytes, 1152) as usize * 4096;
                bytes[bitmap + blocks[0] as usize / 8] &= !(0x80 >> (blocks[0] % 8));
            }
            11 => {
                let catalog = volume::be32(&bytes, 1312);
                wire::p32(&mut bytes, extra + 8, catalog);
            }
            12 => wire::p32(&mut bytes, extra + 8, 0),
            13 => wire::p32(&mut bytes, body + 24, 1),
            _ => unreachable!(),
        }
        let mut disk = MemoryBackend::from_bytes(bytes.clone());
        let fs = HfsPlus::open(&mut disk).unwrap();
        assert!(
            fs.inline_attribute(&mut disk, cnid, NAME).is_err(),
            "variant {variant}"
        );
        if let Ok(index) = fs.attribute_read_index(&mut disk) {
            assert!(
                fs.indexed_attribute(&mut disk, &index, cnid, NAME).is_err(),
                "indexed variant {variant}"
            );
        }
        assert_eq!(disk.as_slice(), bytes, "variant {variant}");
    }
}

// Keep the valid journal/JIB bytes and pointers while independently removing
// their catalog ownership descriptors, so catalog overlap checks cannot help.
fn hide_journal_catalog_forks(bytes: &mut [u8]) {
    let catalog = volume::be32(bytes, 1312) as usize * 4096;
    let size = volume::be16(bytes, catalog + 32) as usize;
    let mut leaf = volume::be32(bytes, catalog + 24) as usize;
    let mut found = 0;
    while leaf != 0 {
        let start = catalog + leaf * size;
        let count = volume::be16(bytes, start + 10) as usize;
        for i in 0..count {
            let record = start + volume::be16(bytes, start + size - 2 * (i + 1)) as usize;
            let length = volume::be16(bytes, record + 6) as usize;
            let name = String::from_utf16(
                &(0..length)
                    .map(|j| volume::be16(bytes, record + 8 + 2 * j))
                    .collect::<Vec<_>>(),
            )
            .unwrap();
            let body = record + 2 + volume::be16(bytes, record) as usize;
            if matches!(name.as_str(), ".journal" | ".journal_info_block")
                && volume::be16(bytes, body) == 2
            {
                bytes[body + 88..body + 168].fill(0);
                found += 1;
            }
        }
        leaf = volume::be32(bytes, start) as usize;
    }
    assert_eq!(found, 2);
}

#[test]
fn journal_and_jib_attribute_overlaps_refuse_even_without_catalog_ownership() {
    let (mut baseline, cnid, _, _) = fixture(true, false);
    let jib = volume::be32(&baseline, 1036);
    let journal = (volume::be64(&baseline, jib as usize * 4096 + 36) / 4096) as u32;
    hide_journal_catalog_forks(&mut baseline);
    let tree = volume::be32(&baseline, 1392) as usize * 4096;
    let continuation = tree + volume::be32(&baseline, tree + 28) as usize * 4096 + 14;
    let extra = continuation + 14 + NAME.len() * 2;
    for target in [jib, journal] {
        // An apparently allocated attribute extent lies inside reserved journal storage.
        let mut bytes = baseline.clone();
        wire::p32(&mut bytes, extra + 8, target);
        let mut disk = MemoryBackend::from_bytes(bytes.clone());
        let mut fs = HfsPlus::open(&mut disk).unwrap();
        let body = fs.catalog_record("/file").unwrap();
        assert!(fs.inline_attribute(&mut disk, cnid, NAME).is_err());
        assert!(
            fs.set_inline_attribute(&mut disk, cnid, NAME, None)
                .is_err()
        );
        assert!(fs.remove(&mut disk, "/file").is_err());
        assert_eq!(fs.catalog_record("/file").unwrap(), body);
        assert_eq!(disk.as_slice(), bytes);

        // A damaged bitmap must not turn reserved storage into COW payload space.
        let mut bytes = baseline.clone();
        let bitmap = volume::be32(&bytes, 1152) as usize * 4096;
        for block in 0..target {
            bytes[bitmap + block as usize / 8] |= 0x80 >> (block % 8);
        }
        bytes[bitmap + target as usize / 8] &= !(0x80 >> (target % 8));
        let total = volume::be32(&bytes, 1068);
        let free = (0..total)
            .filter(|&b| bytes[bitmap + b as usize / 8] & (0x80 >> (b % 8)) == 0)
            .count() as u32;
        wire::p32(&mut bytes, 1072, free);
        let mut disk = MemoryBackend::from_bytes(bytes.clone());
        let mut fs = HfsPlus::open(&mut disk).unwrap();
        assert!(
            fs.set_inline_attribute(&mut disk, cnid, NAME, Some(&[7; 3803]))
                .is_err()
        );
        assert_eq!(fs.catalog_record("/file").unwrap(), body);
        assert_eq!(disk.as_slice(), bytes);
    }
}
