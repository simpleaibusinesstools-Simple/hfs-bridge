//! Independently encoded metadata fixtures. These are not Mac-created media.
use fstool::block::MemoryBackend;
use fstool::fs::hfs_plus::{
    attributes::{AttrRecord, Attributes},
    btree::ForkReader,
    volume_header::read_volume_header,
};
use fstool::fs::{
    Filesystem,
    hfs_plus::{FormatOpts, HfsPlus},
};
use hfs_bridge::volume;
use std::io::{Read, Write};

const SIZE: u64 = 32 * 1024 * 1024;
const DATA: &[u8] = b"Original data fork survives a move.\n";
const RESOURCE: &[u8] = b"Resource fork with binary bytes: \0\xff\x80\x01";
const ATTRIBUTE: &[u8] = b"Existing Finder metadata: \0\xff\x80";

fn base(journaled: bool) -> MemoryBackend {
    base_with_case(journaled, false)
}
fn base_with_case(journaled: bool, case_sensitive: bool) -> MemoryBackend {
    let mut disk = MemoryBackend::new(SIZE);
    let mut fs = HfsPlus::format(
        &mut disk,
        &FormatOpts {
            journaled,
            ..Default::default()
        },
    )
    .unwrap();
    if case_sensitive {
        // Select HFSX before adding keys: changing a populated HFS+ tree's
        // compare flag alone does not put mixed-case keys into binary order.
        drop(fs);
        let mut bytes = disk.into_bytes();
        bytes[1024..1026].copy_from_slice(b"HX");
        put16(&mut bytes, 1026, 5);
        let cat = volume::be32(&bytes, 1024 + 272 + 16) as usize * 4096;
        bytes[cat + 51] = 0xbc;
        headers(&mut bytes);
        disk = MemoryBackend::from_bytes(bytes);
        fs = HfsPlus::open(&mut disk).unwrap();
    }
    for path in ["/Transfer", "/Transfer/Sub", "/Destination"] {
        fs.create_dir(&mut disk, path, 0o755, 501, 20, 1_700_000_000)
            .unwrap();
    }
    fs.create_file(
        &mut disk,
        "/Transfer/hello.txt",
        &mut &DATA[..],
        DATA.len() as u64,
        0o640,
        501,
        20,
        1_700_000_000,
    )
    .unwrap();
    fs.flush(&mut disk).unwrap();
    disk
}
fn read(fs: &mut HfsPlus, disk: &mut MemoryBackend, path: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    Filesystem::read_file(fs, disk, std::path::Path::new(path))
        .unwrap()
        .read_to_end(&mut bytes)
        .unwrap();
    bytes
}
fn be16(bytes: &[u8], off: usize) -> u16 {
    u16::from_be_bytes(bytes[off..off + 2].try_into().unwrap())
}
fn put16(bytes: &mut [u8], off: usize, n: u16) {
    bytes[off..off + 2].copy_from_slice(&n.to_be_bytes());
}
fn put32(bytes: &mut [u8], off: usize, n: u32) {
    bytes[off..off + 4].copy_from_slice(&n.to_be_bytes());
}
fn put64(bytes: &mut [u8], off: usize, n: u64) {
    bytes[off..off + 8].copy_from_slice(&n.to_be_bytes());
}

// Independently walk the fixture's single-extent catalog leaf chain and
// offsets. Do not call the engine's catalog encoder or decoder here.
fn record_offset(bytes: &[u8], cnid: u32) -> usize {
    let block_size = volume::be32(bytes, 1064) as usize;
    let cat = volume::be32(bytes, 1024 + 272 + 16) as usize * block_size;
    let node_size = be16(bytes, cat + 14 + 18) as usize;
    let mut leaf = volume::be32(bytes, cat + 14 + 10);
    while leaf != 0 {
        let node = cat + leaf as usize * node_size;
        assert_eq!(bytes[node + 8], 0xff);
        for i in 0..be16(bytes, node + 10) as usize {
            let start = node + be16(bytes, node + node_size - 2 * (i + 1)) as usize;
            let body = start + 2 + be16(bytes, start) as usize;
            if [1, 2].contains(&be16(bytes, body)) && volume::be32(bytes, body + 8) == cnid {
                return body;
            }
        }
        leaf = volume::be32(bytes, node);
    }
    panic!("CNID {cnid} absent");
}
fn headers(bytes: &mut [u8]) {
    let end = bytes.len() - 1024;
    let primary = bytes[1024..1536].to_vec();
    bytes[end..end + 512].copy_from_slice(&primary);
}
fn allocate(bytes: &mut [u8], blocks: u32) -> u32 {
    let size = volume::be32(bytes, 1064) as usize;
    let total = volume::be32(bytes, 1068);
    let bitmap = volume::be32(bytes, 1024 + 112 + 16) as usize * size;
    let start = (1..total - blocks)
        .find(|start| {
            (*start..*start + blocks)
                .all(|b| bytes[bitmap + b as usize / 8] & (0x80 >> (b % 8)) == 0)
        })
        .unwrap();
    for b in start..start + blocks {
        bytes[bitmap + b as usize / 8] |= 0x80 >> (b % 8);
    }
    let free = volume::be32(bytes, 1072);
    put32(bytes, 1072, free - blocks);
    start
}
fn fork(bytes: &mut [u8], off: usize, start: u32, blocks: u32, logical_size: u64) {
    bytes[off..off + 80].fill(0);
    put64(bytes, off, logical_size);
    put32(bytes, off + 8, 4096);
    put32(bytes, off + 12, blocks);
    put32(bytes, off + 16, start);
    put32(bytes, off + 20, blocks);
}
fn attribute_tree(cnid: u32) -> Vec<u8> {
    const NS: usize = 4096;
    let mut tree = vec![0; NS * 2];
    tree[8] = 1; // header node
    put16(&mut tree, 10, 3);
    put16(&mut tree, 14, 1); // depth
    for off in [16, 20, 24, 28] {
        put32(&mut tree, off, 1);
    } // root, records, first/last leaf
    put16(&mut tree, 32, NS as u16);
    put16(&mut tree, 34, 266); // Apple's maximum attribute key length
    put32(&mut tree, 36, 2); // total nodes
    put32(&mut tree, 46, NS as u32); // clump size
    tree[51] = 0xbc; // binary comparison
    put32(&mut tree, 52, 6);
    for (i, off) in [14, 120, 248, NS - 8].into_iter().enumerate() {
        put16(&mut tree, NS - 2 * (i + 1), off as u16);
    }
    tree[248] = 0xc0; // both nodes allocated
    tree[NS + 8] = 0xff;
    tree[NS + 9] = 1;
    put16(&mut tree, NS + 10, 1);
    let name: Vec<u16> = "com.example.hfsbridge".encode_utf16().collect();
    let key = NS + 14;
    put16(&mut tree, key, (12 + 2 * name.len()) as u16);
    put32(&mut tree, key + 4, cnid);
    put16(&mut tree, key + 12, name.len() as u16);
    for (i, n) in name.iter().enumerate() {
        put16(&mut tree, key + 14 + 2 * i, *n);
    }
    let body = key + 14 + 2 * name.len();
    put32(&mut tree, body, 0x10);
    // recordType + two reserved u32 words + attrSize = sixteen bytes.
    put32(&mut tree, body + 12, ATTRIBUTE.len() as u32);
    tree[body + 16..body + 16 + ATTRIBUTE.len()].copy_from_slice(ATTRIBUTE);
    let end = (body + 16 + ATTRIBUTE.len() + 1) & !1;
    put16(&mut tree, NS * 2 - 2, 14);
    put16(&mut tree, NS * 2 - 4, (end - NS) as u16);
    tree
}
fn metadata_fixture(journaled: bool) -> MemoryBackend {
    let mut disk = base(journaled);
    let fs = HfsPlus::open(&mut disk).unwrap();
    let cnid = volume::be32(&fs.catalog_record("/Transfer/hello.txt").unwrap(), 8);
    let mut bytes = disk.into_bytes();
    let body = record_offset(&bytes, cnid);
    // BSD ownership/mode, all five dates, Finder type/creator/flags/location,
    // extended Finder bytes, encoding hint. Avoid immutable/compressed flags.
    for (i, off) in [12, 16, 20, 24, 28].into_iter().enumerate() {
        put32(&mut bytes, body + off, 3_000_000_000 + i as u32);
    }
    put32(&mut bytes, body + 32, 501);
    put32(&mut bytes, body + 36, 20);
    put16(&mut bytes, body + 42, 0o100640);
    bytes[body + 48..body + 56].copy_from_slice(b"TEXTttxt");
    put16(&mut bytes, body + 56, 0x0100);
    put16(&mut bytes, body + 58, 125);
    put16(&mut bytes, body + 60, 250);
    bytes[body + 64..body + 80].copy_from_slice(&[0, 1, 0, 2, 0, 3, 0, 4, 0, 0, 0, 0, 0, 0, 0, 5]);
    put32(&mut bytes, body + 80, 0);
    let flags = be16(&bytes, body + 2);
    put16(&mut bytes, body + 2, flags | 4); // has attributes
    let resource = allocate(&mut bytes, 1);
    let resource_off = resource as usize * 4096;
    bytes[resource_off..resource_off + RESOURCE.len()].copy_from_slice(RESOURCE);
    fork(&mut bytes, body + 168, resource, 1, RESOURCE.len() as u64);
    let attrs = allocate(&mut bytes, 2);
    let tree = attribute_tree(cnid);
    bytes[attrs as usize * 4096..attrs as usize * 4096 + tree.len()].copy_from_slice(&tree);
    fork(&mut bytes, 1024 + 352, attrs, 2, tree.len() as u64);
    for (i, off) in [16, 20, 24, 28].into_iter().enumerate() {
        put32(&mut bytes, 1024 + off, 3_000_000_100 + i as u32);
    }
    put32(&mut bytes, 1024 + 56, 8192);
    put32(&mut bytes, 1024 + 60, 16384);
    put32(&mut bytes, 1024 + 68, 987);
    put64(&mut bytes, 1024 + 72, 1);
    // Finder volume UUID is the final two words.
    bytes[1024 + 104..1024 + 112].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
    headers(&mut bytes);
    MemoryBackend::from_bytes(bytes)
}
fn metadata_move(journaled: bool) {
    let mut disk = metadata_fixture(journaled);
    let before = disk.as_slice().to_vec();
    let mut fs = HfsPlus::open(&mut disk).unwrap();
    let record = fs.catalog_record("/Transfer/hello.txt").unwrap();
    let cnid = volume::be32(&record, 8);
    fs.rename(
        &mut disk,
        "/Transfer/hello.txt",
        "/Destination/Mac file.txt",
    )
    .unwrap();
    fs.flush(&mut disk).unwrap();
    let mut fs = HfsPlus::open(&mut disk).unwrap();
    assert_eq!(
        record,
        fs.catalog_record("/Destination/Mac file.txt").unwrap()
    );
    assert!(fs.catalog_record("/Transfer/hello.txt").is_err());
    assert_eq!(read(&mut fs, &mut disk, "/Destination/Mac file.txt"), DATA);
    let mut resource = Vec::new();
    fs.open_resource_fork_reader(&mut disk, "/Destination/Mac file.txt")
        .unwrap()
        .read_to_end(&mut resource)
        .unwrap();
    assert_eq!(resource, RESOURCE);
    let vh = read_volume_header(&mut disk).unwrap();
    let attrs = Attributes::open(
        &mut disk,
        ForkReader::from_inline(&vh.attributes_file, vh.block_size, "fixture attributes").unwrap(),
        false,
    )
    .unwrap();
    let AttrRecord::Inline { data } = attrs
        .lookup(&mut disk, cnid, "com.example.hfsbridge")
        .unwrap()
        .unwrap()
    else {
        panic!("wrong attribute type")
    };
    assert_eq!(data, ATTRIBUTE);
    let attr_off = volume::be32(&before, 1024 + 352 + 16) as usize * 4096;
    assert_eq!(
        &before[attr_off..attr_off + 8192],
        &disk.as_slice()[attr_off..attr_off + 8192]
    );
    assert_eq!(
        &disk.as_slice()[1032..1036],
        if journaled { b"HFSJ" } else { b"HB39" }
    );
    assert_eq!(volume::be32(disk.as_slice(), 1092), 988);
    for range in [16..32, 56..64, 72..112] {
        assert_eq!(
            &before[1024 + range.start..1024 + range.end],
            &disk.as_slice()[1024 + range.start..1024 + range.end]
        );
    }
    volume::require_engine_access(&volume::inspect(&mut disk).unwrap()).unwrap();
    if let Some(directory) = std::env::var_os("HFS_CRASH_ARTIFACT_DIR") {
        let path = std::path::Path::new(&directory).join(format!(
            "metadata-moved-{}.img",
            if journaled { "journaled" } else { "plain" }
        ));
        let mut file = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(path)
            .unwrap();
        file.write_all(disk.as_slice()).unwrap();
        file.sync_all().unwrap();
    }
}
#[test]
fn readonly_snapshots_cover_complete_resource_and_binary_attribute_after_windows_changes() {
    use hfs_bridge::{
        engine,
        windows::{Access, Adapter, Kind, OpenRequest},
    };
    for journaled in [false, true] {
        let mut disk = metadata_fixture(journaled);
        let bytes = disk.as_slice().to_vec();
        let before = engine::snapshot_device(
            &mut disk,
            "/Transfer/hello.txt",
            &["com.example.hfsbridge", "missing"],
        )
        .unwrap();
        assert_eq!(disk.as_slice(), bytes);
        assert_eq!((before.uid, before.gid, before.mode), (501, 20, 0o100640));
        assert_eq!(
            before.resource_sha256,
            Some(engine::sha256(&mut &RESOURCE[..]).unwrap())
        );
        assert_eq!(
            before.attributes[0].1,
            Some(engine::sha256(&mut &ATTRIBUTE[..]).unwrap())
        );
        assert_eq!(before.attributes[1].1, None);
        let mut adapter = Adapter::from_device(disk).unwrap();
        let other = adapter
            .create(
                r"\Transfer\Windows.txt",
                Kind::File,
                OpenRequest {
                    access: Access::ALL,
                    ..Default::default()
                },
            )
            .unwrap();
        adapter
            .write(other, 0, b"Separate Windows payload", false, false)
            .unwrap();
        adapter.rename(other, r"\Transfer\Renamed.txt").unwrap();
        adapter.close(other).unwrap();
        let mut disk = adapter.shutdown().unwrap();
        let after = engine::snapshot_device(
            &mut disk,
            "/Transfer/hello.txt",
            &["com.example.hfsbridge", "missing"],
        )
        .unwrap();
        assert_eq!(before, after);
        if let Some(directory) = std::env::var_os("HFS_MAC_WORKFLOW_FIXTURE_DIR") {
            let mut fs = engine::open_checked(&mut disk).unwrap();
            fs.rename(&mut disk, "/Transfer", "/Mac fixture").unwrap();
            fs.rename(
                &mut disk,
                "/Mac fixture/hello.txt",
                "/Mac fixture/original.txt",
            )
            .unwrap();
            fs.flush(&mut disk).unwrap();
            let variant = if journaled { "journaled" } else { "plain" };
            let folder = std::path::Path::new(&directory).join(variant);
            std::fs::create_dir(&folder).unwrap();
            let mut output =
                hfs_bridge::image::create_output(&folder.join(format!("mac-{variant}.img")))
                    .unwrap();
            output.write_all(disk.as_slice()).unwrap();
            output.sync_all().unwrap();
        }
    }
}

#[test]
fn invalid_snapshot_attribute_names_and_non_files_are_readonly_refusals() {
    let mut disk = metadata_fixture(true);
    let bytes = disk.as_slice().to_vec();
    for name in ["".to_string(), "bad\0name".to_string(), "X".repeat(128)] {
        assert!(
            hfs_bridge::engine::snapshot_device(&mut disk, "/Transfer/hello.txt", &[&name])
                .is_err()
        );
    }
    assert!(hfs_bridge::engine::snapshot_device(&mut disk, "/Transfer", &[]).is_err());
    assert_eq!(disk.as_slice(), bytes);
}

#[test]
fn journaled_move_preserves_mac_metadata() {
    metadata_move(true);
}
#[test]
fn plain_move_preserves_mac_metadata() {
    metadata_move(false);
}

#[test]
fn file_and_directory_moves_keep_cnids_children_and_valences() {
    let mut disk = base(true);
    let mut fs = HfsPlus::open(&mut disk).unwrap();
    let folder = fs.catalog_record("/Transfer").unwrap();
    let file = fs.catalog_record("/Transfer/hello.txt").unwrap();
    fs.rename(&mut disk, "/Transfer", "/Destination/Archive")
        .unwrap();
    fs.flush(&mut disk).unwrap();
    let mut fs = HfsPlus::open(&mut disk).unwrap();
    assert_eq!(folder, fs.catalog_record("/Destination/Archive").unwrap());
    assert_eq!(
        file,
        fs.catalog_record("/Destination/Archive/hello.txt").unwrap()
    );
    assert_eq!(
        volume::be32(&fs.catalog_record("/Destination").unwrap(), 4),
        1
    );
    assert_eq!(
        read(&mut fs, &mut disk, "/Destination/Archive/hello.txt"),
        DATA
    );
    fs.rename(&mut disk, "/Destination/Archive/hello.txt", "/moved.bin")
        .unwrap();
    fs.flush(&mut disk).unwrap();
    let fs = HfsPlus::open(&mut disk).unwrap();
    assert_eq!(file, fs.catalog_record("/moved.bin").unwrap());
    assert_eq!(
        volume::be32(&fs.catalog_record("/Destination/Archive").unwrap(), 4),
        1
    );
    assert!(fs.catalog_record("/Transfer").is_err());
}
#[test]
fn hfs_case_only_rename_accepts_alias_and_preserves_identity() {
    let mut disk = base(false);
    let mut fs = HfsPlus::open(&mut disk).unwrap();
    let before = fs.catalog_record("/Transfer/hello.txt").unwrap();
    fs.rename(&mut disk, "/transfer/HELLO.txt", "/TRANSFER/Hello.TXT")
        .unwrap();
    fs.flush(&mut disk).unwrap();
    let mut fs = HfsPlus::open(&mut disk).unwrap();
    assert_eq!(before, fs.catalog_record("/Transfer/Hello.TXT").unwrap());
    let entries = fs
        .list(&mut disk, std::path::Path::new("/Transfer"))
        .unwrap();
    assert!(entries.iter().any(|e| e.name == "Hello.TXT"));
    assert!(!entries.iter().any(|e| e.name == "hello.txt"));
    fs.rename(&mut disk, "/Transfer/Hello.TXT", "/Transfer/Hello.TXT")
        .unwrap();
}
#[test]
fn collisions_cycles_and_bad_parents_are_rejected_without_staging_changes() {
    let mut disk = base(true);
    let mut fs = HfsPlus::open(&mut disk).unwrap();
    let before = disk.as_slice().to_vec();
    let record = fs.catalog_record("/Transfer").unwrap();
    let original_file = fs.catalog_record("/Transfer/hello.txt").unwrap();
    for (source, dest) in [
        ("/Transfer", "/Destination"),
        ("/Transfer", "/Transfer/Sub/loop"),
        ("/Transfer", "/Transfer/self"),
        ("/Transfer/hello.txt", "/missing/file"),
        ("/Transfer/hello.txt", "/Transfer/hello.txt/file"),
        ("/missing", "/new"),
        ("/", "/new"),
    ] {
        assert!(
            fs.rename(&mut disk, source, dest).is_err(),
            "{source} -> {dest}"
        );
        assert_eq!(disk.as_slice(), before);
        assert_eq!(fs.catalog_record("/Transfer").unwrap(), record);
        assert_eq!(
            fs.catalog_record("/Transfer/hello.txt").unwrap(),
            original_file
        );
    }
    fs.rename(&mut disk, "/Transfer/hello.txt", "/Destination/valid.txt")
        .unwrap();
    fs.flush(&mut disk).unwrap();
    let mut fs = HfsPlus::open(&mut disk).unwrap();
    assert_eq!(read(&mut fs, &mut disk, "/Destination/valid.txt"), DATA);
}
#[test]
fn finder_and_bsd_locked_entries_and_invalid_valence_are_refused() {
    for (field, parent) in [
        (56, None),
        (40, None),
        (41, None),
        (4, Some("/Transfer")),
        (40, Some("/Transfer")),
        (41, Some("/Destination")),
    ] {
        let mut disk = base(false);
        let fs = HfsPlus::open(&mut disk).unwrap();
        let record = fs
            .catalog_record(parent.unwrap_or("/Transfer/hello.txt"))
            .unwrap();
        let cnid = volume::be32(&record, 8);
        let mut bytes = disk.into_bytes();
        let body = record_offset(&bytes, cnid);
        match field {
            56 => put16(&mut bytes, body + 56, 0x1000),
            40 | 41 => bytes[body + field] = 2,
            4 => put32(&mut bytes, body + 4, 0),
            _ => unreachable!(),
        }
        let mut disk = MemoryBackend::from_bytes(bytes);
        let mut fs = HfsPlus::open(&mut disk).unwrap();
        let before = disk.as_slice().to_vec();
        let record = fs.catalog_record("/Transfer/hello.txt").unwrap();
        assert!(
            fs.rename(&mut disk, "/Transfer/hello.txt", "/Destination/moved")
                .is_err()
        );
        if parent == Some("/Transfer") && field == 40 {
            assert!(
                fs.rename(&mut disk, "/Transfer/hello.txt", "/Transfer/renamed")
                    .is_err()
            );
        }
        assert_eq!(record, fs.catalog_record("/Transfer/hello.txt").unwrap());
        assert_eq!(disk.as_slice(), before);
    }
}
#[test]
fn hfsx_distinguishes_case_and_keeps_both_file_ids() {
    let mut disk = base_with_case(false, true);
    let mut fs = HfsPlus::open(&mut disk).unwrap();
    let original = fs.catalog_record("/Transfer/hello.txt").unwrap();
    fs.create_file(
        &mut disk,
        "/Transfer/HELLO.txt",
        &mut &b"other"[..],
        5,
        0o644,
        0,
        0,
        0,
    )
    .unwrap();
    fs.flush(&mut disk).unwrap();
    let mut fs = HfsPlus::open(&mut disk).unwrap();
    assert!(
        fs.rename(&mut disk, "/Transfer/hello.txt", "/Transfer/HELLO.txt")
            .is_err()
    );
    fs.rename(&mut disk, "/Transfer/hello.txt", "/Transfer/Hello.txt")
        .unwrap();
    fs.flush(&mut disk).unwrap();
    let mut fs = HfsPlus::open(&mut disk).unwrap();
    assert_eq!(original, fs.catalog_record("/Transfer/Hello.txt").unwrap());
    assert_eq!(read(&mut fs, &mut disk, "/Transfer/HELLO.txt"), b"other");
    assert_eq!(read(&mut fs, &mut disk, "/Transfer/Hello.txt"), DATA);
    volume::require_engine_access(&volume::inspect(&mut disk).unwrap()).unwrap();
}
#[test]
fn modern_inline_attribute_layout_is_bounded_and_binary_safe() {
    let mut body = vec![0; 16];
    put32(&mut body, 0, 0x10);
    put32(&mut body, 12, ATTRIBUTE.len() as u32);
    body.extend_from_slice(ATTRIBUTE);
    let AttrRecord::Inline { data } = AttrRecord::decode(&body).unwrap() else {
        panic!("wrong type")
    };
    assert_eq!(data, ATTRIBUTE);
    assert!(AttrRecord::decode(&body[..body.len() - 1]).is_err());
    put32(&mut body, 12, u32::MAX);
    assert!(AttrRecord::decode(&body).is_err());
}

fn metadata_edit(journaled: bool) {
    let mut disk = metadata_fixture(journaled);
    let before = disk.as_slice().to_vec();
    let mut fs = HfsPlus::open(&mut disk).unwrap();
    let original = fs.catalog_record("/Transfer/hello.txt").unwrap();
    let cnid = volume::be32(&original, 8);
    {
        let mut handle = fs
            .open_file_rw(
                &mut disk,
                std::path::Path::new("/Transfer/hello.txt"),
                fstool::fs::OpenFlags::default(),
                None,
            )
            .unwrap();
        use std::io::{Seek, SeekFrom};
        handle.seek(SeekFrom::Start(3)).unwrap();
        handle.write_all(b"EDIT").unwrap();
        handle.set_len(8193).unwrap();
        handle.sync().unwrap();
    }
    let mut fs = HfsPlus::open(&mut disk).unwrap();
    let after = fs.catalog_record("/Transfer/hello.txt").unwrap();
    assert_eq!(&original[..88], &after[..88]);
    assert_eq!(&original[168..], &after[168..]);
    assert_eq!(&original[96..100], &after[96..100]);
    let mut expected = DATA.to_vec();
    expected[3..7].copy_from_slice(b"EDIT");
    expected.resize(8193, 0);
    assert_eq!(read(&mut fs, &mut disk, "/Transfer/hello.txt"), expected);
    let mut resource = Vec::new();
    fs.open_resource_fork_reader(&mut disk, "/Transfer/hello.txt")
        .unwrap()
        .read_to_end(&mut resource)
        .unwrap();
    assert_eq!(resource, RESOURCE);
    let vh = read_volume_header(&mut disk).unwrap();
    let attrs = Attributes::open(
        &mut disk,
        ForkReader::from_inline(&vh.attributes_file, vh.block_size, "attributes").unwrap(),
        false,
    )
    .unwrap();
    let AttrRecord::Inline { data } = attrs
        .lookup(&mut disk, cnid, "com.example.hfsbridge")
        .unwrap()
        .unwrap()
    else {
        panic!("wrong attribute type")
    };
    assert_eq!(data, ATTRIBUTE);
    let off = volume::be32(&before, 1024 + 352 + 16) as usize * 4096;
    assert_eq!(&before[off..off + 8192], &disk.as_slice()[off..off + 8192]);
    volume::require_engine_access(&volume::inspect(&mut disk).unwrap()).unwrap();
    if let Some(directory) = std::env::var_os("HFS_CRASH_ARTIFACT_DIR") {
        let mut file = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(std::path::Path::new(&directory).join(format!(
                "metadata-edited-{}.img",
                if journaled { "journaled" } else { "plain" }
            )))
            .unwrap();
        file.write_all(disk.as_slice()).unwrap();
        file.sync_all().unwrap();
    }
}
#[test]
fn journaled_file_edit_preserves_resource_fork_and_attributes() {
    metadata_edit(true);
}
#[test]
fn plain_file_edit_preserves_resource_fork_and_attributes() {
    metadata_edit(false);
}

#[test]
fn resource_edits_preserve_data_metadata_and_native_attributes() {
    use std::io::{Seek, SeekFrom};
    for journaled in [false, true] {
        let mut disk = metadata_fixture(journaled);
        let mut fs = HfsPlus::open(&mut disk).unwrap();
        let original = fs.catalog_record("/Transfer/hello.txt").unwrap();
        let attr_block = volume::be32(disk.as_slice(), 1024 + 352 + 16) as usize * 4096;
        let attribute_bytes = disk.as_slice()[attr_block..attr_block + 8192].to_vec();
        let free_before = volume::inspect(&mut disk).unwrap().header.free_blocks;
        let mut expected = RESOURCE.to_vec();
        {
            let mut file = fs
                .open_resource_fork_rw(&mut disk, std::path::Path::new("/TRANSFER/hello.txt"))
                .unwrap();
            file.seek(SeekFrom::Start(3)).unwrap();
            file.write_all(b"EDIT").unwrap();
            expected[3..7].copy_from_slice(b"EDIT");
            file.set_len(12291).unwrap();
            expected.resize(12291, 0);
            file.seek(SeekFrom::Start(8190)).unwrap();
            file.write_all(b"cross-block").unwrap();
            expected[8190..8201].copy_from_slice(b"cross-block");
            file.sync().unwrap();
            file.set_len(5).unwrap();
            file.set_len(8193).unwrap();
            expected.truncate(5);
            expected.resize(8193, 0);
            file.seek(SeekFrom::Start(8191)).unwrap();
            file.write_all(b"TAIL").unwrap();
            expected.resize(8195, 0);
            expected[8191..].copy_from_slice(b"TAIL");
            file.sync().unwrap();
        }
        let mut fs = HfsPlus::open(&mut disk).unwrap();
        assert_eq!(read(&mut fs, &mut disk, "/Transfer/hello.txt"), DATA);
        let after = fs.catalog_record("/Transfer/hello.txt").unwrap();
        assert_eq!(&after[..168], &original[..168]);
        assert_eq!(&after[176..180], &original[176..180]);
        let mut observed = Vec::new();
        fs.open_resource_fork_reader(&mut disk, "/Transfer/hello.txt")
            .unwrap()
            .read_to_end(&mut observed)
            .unwrap();
        assert_eq!(observed, expected);
        assert_eq!(
            &disk.as_slice()[attr_block..attr_block + 8192],
            attribute_bytes
        );
        let snap = hfs_bridge::engine::snapshot_device(
            &mut disk,
            "/Transfer/hello.txt",
            &["com.example.hfsbridge"],
        )
        .unwrap();
        assert_eq!(
            snap.attributes[0].1,
            Some(hfs_bridge::engine::sha256(&mut &ATTRIBUTE[..]).unwrap())
        );
        if let Some(directory) = std::env::var_os("HFS_CRASH_ARTIFACT_DIR") {
            let path =
                std::path::Path::new(&directory).join(format!("resource-edited-{journaled}.img"));
            let mut out = hfs_bridge::image::create_output(&path).unwrap();
            out.write_all(disk.as_slice()).unwrap();
            out.sync_all().unwrap();
        }
        {
            let mut file = fs
                .open_resource_fork_rw(&mut disk, std::path::Path::new("/Transfer/hello.txt"))
                .unwrap();
            file.set_len(0).unwrap();
            file.sync().unwrap();
        }
        let mut fs = HfsPlus::open(&mut disk).unwrap();
        assert_eq!(
            fs.resource_fork_size(&mut disk, "/Transfer/hello.txt")
                .unwrap(),
            None
        );
        assert_eq!(
            volume::inspect(&mut disk).unwrap().header.free_blocks,
            free_before + 1
        );
        assert_eq!(read(&mut fs, &mut disk, "/Transfer/hello.txt"), DATA);
        {
            let mut file = fs
                .open_resource_fork_rw(&mut disk, std::path::Path::new("/Transfer/hello.txt"))
                .unwrap();
            file.write_all(RESOURCE).unwrap();
            file.sync().unwrap();
        }
        if let Some(directory) = std::env::var_os("HFS_CRASH_ARTIFACT_DIR") {
            let path = std::path::Path::new(&directory)
                .join(format!("resource-recreated-{journaled}.img"));
            let mut out = hfs_bridge::image::create_output(&path).unwrap();
            out.write_all(disk.as_slice()).unwrap();
            out.sync_all().unwrap();
        }
    }
}

#[test]
fn resource_edit_refuses_shared_unallocated_and_protected_forks_before_writes() {
    for kind in 0..5 {
        let mut bytes = metadata_fixture(true).into_bytes();
        let mut disk = MemoryBackend::from_bytes(bytes.clone());
        let fs = HfsPlus::open(&mut disk).unwrap();
        let id = volume::be32(&fs.catalog_record("/Transfer/hello.txt").unwrap(), 8);
        let body = record_offset(&bytes, id);
        match kind {
            0 => {
                let data = bytes[body + 88..body + 168].to_vec();
                bytes[body + 168..body + 248].copy_from_slice(&data);
            }
            1 => {
                let block = volume::be32(&bytes, body + 184) as usize;
                let map = volume::be32(&bytes, 1152) as usize * 4096;
                bytes[map + block / 8] &= !(0x80 >> (block % 8));
            }
            2 => bytes[body + 41] |= 0x20,
            3 => bytes[body + 3] |= 1,
            4 => bytes[body + 40] |= 2,
            _ => unreachable!(),
        }
        let before = bytes.clone();
        let mut disk = MemoryBackend::from_bytes(bytes);
        let mut fs = HfsPlus::open(&mut disk).unwrap();
        assert!(
            fs.open_resource_fork_rw(&mut disk, std::path::Path::new("/Transfer/hello.txt"))
                .is_err()
        );
        assert_eq!(disk.as_slice(), before);
    }
}

#[test]
fn cleanup_metadata_preserves_live_resource_forks_then_reclaims_them() {
    use fstool::block::BlockDevice;
    use hfs_bridge::windows::{Access, Adapter, OpenRequest};
    use std::{
        io::{self, Seek, SeekFrom},
        sync::{Arc, Mutex},
    };
    #[derive(Clone)]
    struct Capture(Arc<Mutex<MemoryBackend>>);
    impl Read for Capture {
        fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
            self.0.lock().unwrap().read(bytes)
        }
    }
    impl Seek for Capture {
        fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
            self.0.lock().unwrap().seek(position)
        }
    }
    impl Write for Capture {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().write(bytes)
        }
        fn flush(&mut self) -> io::Result<()> {
            self.0.lock().unwrap().flush()
        }
    }
    impl BlockDevice for Capture {
        fn block_size(&self) -> u32 {
            512
        }
        fn total_size(&self) -> u64 {
            self.0.lock().unwrap().as_slice().len() as u64
        }
        fn sync(&mut self) -> fstool::Result<()> {
            self.0.lock().unwrap().sync()
        }
    }
    for journaled in [false, true] {
        let mut original = metadata_fixture(journaled);
        let fs = HfsPlus::open(&mut original).unwrap();
        let record = fs.catalog_record("/Transfer/hello.txt").unwrap();
        let cnid = volume::be32(&record, 8);
        let other = volume::be32(&fs.catalog_record("/Destination").unwrap(), 8);
        // Independently add a second inline record belonging to another node.
        let mut bytes = original.into_bytes();
        let other_body = record_offset(&bytes, other);
        bytes[other_body + 3] |= 4;
        let attr_start = volume::be32(&bytes, 1024 + 352 + 16) as usize * 4096;
        let leaf = attr_start + 4096;
        let end = be16(&bytes, leaf + 4092) as usize;
        let target = bytes[leaf + 14..leaf + end].to_vec();
        let mut neighbor = target.clone();
        neighbor[4..8].copy_from_slice(&other.to_be_bytes());
        let mut records = [target, neighbor];
        records.sort_by_key(|record| volume::be32(record, 4));
        bytes[leaf + 14..leaf + 4096].fill(0);
        put16(&mut bytes, leaf + 10, 2);
        put32(&mut bytes, attr_start + 20, 2);
        let mut position = 14;
        for (index, record) in records.iter().enumerate() {
            put16(&mut bytes, leaf + 4096 - 2 * (index + 1), position as u16);
            bytes[leaf + position..leaf + position + record.len()].copy_from_slice(record);
            position += record.len();
        }
        put16(&mut bytes, leaf + 4090, position as u16);
        original = MemoryBackend::from_bytes(bytes);
        let resource_block = volume::be32(&record, 184);
        let disk = Capture(Arc::new(Mutex::new(original.clone())));
        let state = Arc::clone(&disk.0);
        let mut adapter = Adapter::from_device(disk).unwrap();
        let file = adapter
            .open(
                r"\Transfer\hello.txt",
                OpenRequest {
                    access: Access::ALL,
                    ..Default::default()
                },
            )
            .unwrap();
        adapter.cleanup(file, true).unwrap();
        for phase in 0..2 {
            if phase == 1 {
                adapter.write(file, 3, b"EDIT", false, false).unwrap();
                adapter.set_size(file, 8193).unwrap();
            }
            let mut snapshot = state.lock().unwrap().clone();
            let path = format!("/.hfs-bridge-orphans-v1/{cnid:08X}");
            let fs = HfsPlus::open(&mut snapshot).unwrap();
            let held = fs.catalog_record(&path).unwrap();
            if phase == 0 {
                assert_eq!(held, record);
            }
            assert_eq!(&held[32..88], &record[32..88]);
            assert_eq!(&held[168..], &record[168..]);
            let mut resource = Vec::new();
            fs.open_resource_fork_reader(&mut snapshot, &path)
                .unwrap()
                .read_to_end(&mut resource)
                .unwrap();
            assert_eq!(resource, RESOURCE);
            let vh = read_volume_header(&mut snapshot).unwrap();
            let attrs = Attributes::open(
                &mut snapshot,
                ForkReader::from_inline(&vh.attributes_file, vh.block_size, "held attributes")
                    .unwrap(),
                false,
            )
            .unwrap();
            let AttrRecord::Inline { data } = attrs
                .lookup(&mut snapshot, cnid, "com.example.hfsbridge")
                .unwrap()
                .unwrap()
            else {
                panic!("wrong attribute type")
            };
            assert_eq!(data, ATTRIBUTE);
            assert!(
                attrs
                    .lookup(&mut snapshot, other, "com.example.hfsbridge")
                    .unwrap()
                    .is_some()
            );
            if let Some(directory) = std::env::var_os("HFS_DEFERRED_ARTIFACT_DIR")
                .or_else(|| std::env::var_os("HFS_CRASH_ARTIFACT_DIR"))
            {
                let path = std::path::Path::new(&directory).join(format!(
                    "cleanup-metadata-{phase}-{}.img",
                    if journaled { "journaled" } else { "plain" }
                ));
                let mut file = hfs_bridge::image::create_output(&path).unwrap();
                file.write_all(snapshot.as_slice()).unwrap();
                file.sync_all().unwrap();
            }
        }
        adapter.close(file).unwrap();
        let mut snapshot = state.lock().unwrap().clone();
        let fs = HfsPlus::open(&mut snapshot).unwrap();
        assert!(fs.catalog_record_cnid(cnid).is_err());
        let vh = read_volume_header(&mut snapshot).unwrap();
        let attrs = Attributes::open(
            &mut snapshot,
            ForkReader::from_inline(&vh.attributes_file, vh.block_size, "reclaimed attributes")
                .unwrap(),
            false,
        )
        .unwrap();
        assert!(
            attrs
                .lookup(&mut snapshot, cnid, "com.example.hfsbridge")
                .unwrap()
                .is_none()
        );
        let AttrRecord::Inline { data } = attrs
            .lookup(&mut snapshot, other, "com.example.hfsbridge")
            .unwrap()
            .unwrap()
        else {
            panic!("wrong retained attribute type")
        };
        assert_eq!(data, ATTRIBUTE);
        let bitmap = volume::be32(snapshot.as_slice(), 1024 + 112 + 16) as usize * 4096;
        assert_eq!(
            snapshot.as_slice()[bitmap + resource_block as usize / 8]
                & (0x80 >> (resource_block % 8)),
            0,
            "resource allocation leaked"
        );
        if let Some(directory) = std::env::var_os("HFS_DEFERRED_ARTIFACT_DIR")
            .or_else(|| std::env::var_os("HFS_CRASH_ARTIFACT_DIR"))
        {
            let path = std::path::Path::new(&directory).join(format!(
                "cleanup-metadata-reclaimed-{}.img",
                if journaled { "journaled" } else { "plain" }
            ));
            let mut file = hfs_bridge::image::create_output(&path).unwrap();
            file.write_all(snapshot.as_slice()).unwrap();
            file.sync_all().unwrap();
        }
    }
}

#[test]
fn malformed_attribute_deletion_is_refused_before_cleanup_or_engine_mutation() {
    use hfs_bridge::windows::{Access, Adapter, OpenRequest};
    for variant in 0..3 {
        let disk = metadata_fixture(true);
        let mut bytes = disk.into_bytes();
        let tree = volume::be32(&bytes, 1024 + 352 + 16) as usize * 4096;
        match variant {
            0 => put32(&mut bytes, tree + 36, 3), // Larger declared tree.
            1 => {
                let leaf = tree + 4096;
                let key_length = be16(&bytes, leaf + 14) as usize + 2;
                let body = leaf + 14 + key_length;
                bytes[body..leaf + 4092].fill(0);
                put32(&mut bytes, body, 0x20);
                // Nonempty logical value with no allocated blocks is malformed.
                bytes[body + 8..body + 16].copy_from_slice(&1u64.to_be_bytes());
                put16(&mut bytes, leaf + 4092, (14 + key_length + 88) as u16);
            }
            2 => bytes[tree + 248] = 0xe0, // Unexpected allocated node bit.
            _ => unreachable!(),
        }
        let before = bytes.clone();
        let mut disk = MemoryBackend::from_bytes(bytes);
        let mut fs = HfsPlus::open(&mut disk).unwrap();
        let body = fs.catalog_record("/Transfer/hello.txt").unwrap();
        // Establish the engine's ordinary no-change flush baseline separately.
        let mut control = MemoryBackend::from_bytes(before.clone());
        HfsPlus::open(&mut control)
            .unwrap()
            .flush(&mut control)
            .unwrap();
        assert!(fs.remove(&mut disk, "/Transfer/hello.txt").is_err());
        assert_eq!(fs.catalog_record("/Transfer/hello.txt").unwrap(), body);
        assert!(
            disk.as_slice() == before,
            "variant {variant} changed bytes during refusal"
        );
        fs.flush(&mut disk).unwrap();
        assert!(
            disk.as_slice() == control.as_slice(),
            "variant {variant} staged a change before refusal"
        );
        let mut adapter = Adapter::from_device(disk).unwrap();
        let opened = adapter.open(
            r"\Transfer\hello.txt",
            OpenRequest {
                access: Access::ALL,
                ..Default::default()
            },
        );
        if variant == 1 {
            // This malformed non-target value is discovered by deletion's
            // complete extent audit, rather than the basic-flag name lookup.
            let file = opened.unwrap();
            assert!(adapter.can_delete(file).is_err());
            assert!(adapter.cleanup(file, true).is_err());
            adapter.close(file).unwrap();
        } else {
            // Invalid tree structure is now detected by basic-flag lookup at
            // open, before a deletion handle can be acquired.
            assert!(opened.is_err(), "variant {variant} opened a corrupt tree");
        }
        assert!(adapter.failure().is_none());
        assert!(
            adapter.shutdown().unwrap().as_slice() == control.as_slice(),
            "variant {variant} staged a cleanup before refusal"
        );
    }
}
