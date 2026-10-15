//! Compression bytes from Apple's pinned reference encoder; HFS catalog flags
//! and resource tables are encoded independently of the engine's read path.
use fstool::{
    block::MemoryBackend,
    fs::{
        Filesystem,
        hfs_plus::{FormatOpts, HfsPlus},
    },
};
use hfs_bridge::{
    volume,
    windows::{Access, Adapter, OpenRequest, Status},
};
use std::io::{Read, Seek, SeekFrom};
#[path = "support/attribute_wire.rs"]
#[allow(dead_code)]
mod attribute_wire;
#[path = "support/catalog_wire.rs"]
#[allow(dead_code)]
mod catalog_wire;
#[path = "support/fault_disk.rs"]
mod faults;
#[path = "compression/named.rs"]
mod named;

fn le_header(kind: u32, size: u64) -> Vec<u8> {
    [b"fpmc".as_slice(), &kind.to_le_bytes(), &size.to_le_bytes()].concat()
}
fn resource(kind: u32, first: &[u8], last: &[u8]) -> Vec<u8> {
    if kind != 4 {
        return [
            &12u32.to_le_bytes()[..],
            &(12 + first.len() as u32).to_le_bytes(),
            &(12 + first.len() as u32 + last.len() as u32).to_le_bytes(),
            first,
            last,
        ]
        .concat();
    }
    let data_len = 24 + first.len() as u32 + last.len() as u32;
    let mut bytes = [
        &256u32.to_be_bytes()[..],
        &(256 + data_len).to_be_bytes(),
        &data_len.to_be_bytes(),
        &50u32.to_be_bytes(),
    ]
    .concat();
    bytes.resize(256, 0);
    bytes.extend((data_len - 4).to_be_bytes());
    bytes.extend(2u32.to_le_bytes());
    bytes.extend(20u32.to_le_bytes());
    bytes.extend((first.len() as u32).to_le_bytes());
    bytes.extend((20 + first.len() as u32).to_le_bytes());
    bytes.extend((last.len() as u32).to_le_bytes());
    bytes.extend(first);
    bytes.extend(last);
    // A native resource map is required even when the decoder only needs the
    // data table. cmpf, resource ID 1, no name, data offset 0 (libarchive layout).
    let mut map = vec![0; 50];
    map[24..28].copy_from_slice(&[0, 28, 0, 50]);
    map[30..34].copy_from_slice(b"cmpf");
    map[34..40].copy_from_slice(&[0, 0, 0, 10, 0, 1]);
    map[40..42].copy_from_slice(&[0xff, 0xff]);
    bytes.extend(map);
    bytes
}
fn payload(kind: u32) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let (plain, encoded, rf) = match kind {
        1 => (b"hello".to_vec(), b"hello".to_vec(), Vec::new()),
        3 => (
            b"hello".to_vec(),
            vec![
                0x78, 0x9c, 0xcb, 0x48, 0xcd, 0xc9, 0xc9, 7, 0, 6, 0x2c, 2, 0x15,
            ],
            Vec::new(),
        ),
        7 => (
            vec![0x41; 1024],
            include_bytes!("fixtures/compression/apple-1024-constant.lzvn").to_vec(),
            Vec::new(),
        ),
        9 => (b"hello".to_vec(), b"\xcchello".to_vec(), Vec::new()),
        11 => (
            (0..65536).map(|i| (i % 251) as u8).collect(),
            include_bytes!("fixtures/compression/apple-65536-ramp.lzfse").to_vec(),
            Vec::new(),
        ),
        4 | 8 | 10 => {
            let marker = match kind {
                4 => 0xff,
                8 => 6,
                _ => 0xcc,
            };
            let mut first = vec![marker];
            first.extend(vec![0x31; 65536]);
            let mut last = vec![marker];
            last.extend(b"tail");
            let mut plain = vec![0x31; 65536];
            plain.extend(b"tail");
            (plain, Vec::new(), resource(kind, &first, &last))
        }
        12 => {
            let mut plain = (0..65536).map(|i| (i % 251) as u8).collect::<Vec<_>>();
            plain.extend(vec![0x41; 1024]);
            (
                plain,
                Vec::new(),
                resource(
                    kind,
                    include_bytes!("fixtures/compression/apple-65536-ramp.lzfse"),
                    include_bytes!("fixtures/compression/apple-1024-constant.lzfse"),
                ),
            )
        }
        13 => (
            vec![0x41; 1024],
            include_bytes!("fixtures/compression/apple-1024-constant.zbm").to_vec(),
            Vec::new(),
        ),
        14 => {
            let mut plain = (0..65536).map(|i| (i % 251) as u8).collect::<Vec<_>>();
            plain.extend(vec![0x41; 1024]);
            (
                plain,
                Vec::new(),
                resource(
                    kind,
                    include_bytes!("fixtures/compression/apple-65536-ramp.zbm"),
                    include_bytes!("fixtures/compression/apple-1024-constant.zbm"),
                ),
            )
        }
        _ => unreachable!(),
    };
    let mut attr = le_header(kind, plain.len() as u64);
    attr.extend(encoded);
    (plain, attr, rf)
}
#[test]
fn namespace_dates_and_private_records_preserve_compressed_rename_storage() {
    use fstool::fs::hfs_plus::CatalogUpdate;
    let mut cases = 0;
    for kind in [3, 8, 13, 14] {
        for journaled in [false, true] {
            for sensitive in [false, true] {
                let (mut d, plain) = fixture(kind, journaled, sensitive, kind == 3 || kind == 13);
                let mut fs = HfsPlus::open(&mut d).unwrap();
                let original = fs.catalog_record("/compressed").unwrap();
                let cnid = volume::be32(&original, 8);
                let encoding = fs
                    .inline_attribute(&mut d, cnid, "com.apple.decmpfs")
                    .unwrap();
                let before = d.as_slice().to_vec();
                fs.remove(&mut d, "/ordinary").unwrap();
                fs.rename(&mut d, "/compressed", "/moved").unwrap();
                let updates = [
                    CatalogUpdate {
                        cnid,
                        times: [None, None, None, Some(3_800_000_003)],
                        attributes: None,
                    },
                    CatalogUpdate {
                        cnid: 2,
                        times: [None, None, Some(3_800_000_002), Some(3_800_000_003)],
                        attributes: None,
                    },
                ];
                fs.set_namespace_metadata_with_publication(
                    &mut d,
                    &updates,
                    &[
                        (
                            2,
                            "org.hfsbridge.windows.time-generation",
                            Some(b"compressed namespace"),
                        ),
                        (cnid, "org.hfsbridge.windows.times", Some(b"new precision")),
                    ],
                )
                .unwrap();
                assert_eq!(d.as_slice(), before);
                fs.flush(&mut d).unwrap();
                let body = fs.catalog_record("/moved").unwrap();
                assert_eq!(&body[..20], &original[..20]);
                assert_eq!(&body[24..], &original[24..]);
                assert_eq!(volume::be32(&body, 20), 3_800_000_003);
                assert_eq!(
                    fs.inline_attribute(&mut d, cnid, "com.apple.decmpfs")
                        .unwrap(),
                    encoding
                );
                let mut data = Vec::new();
                fs.open_file_reader(&mut d, "/moved")
                    .unwrap()
                    .read_to_end(&mut data)
                    .unwrap();
                assert_eq!(data, plain);
                for fork in [88, 168] {
                    for extent in 0..8 {
                        let start = volume::be32(&original, fork + 16 + extent * 8) as usize * 4096;
                        let size = volume::be32(&original, fork + 20 + extent * 8) as usize * 4096;
                        assert_eq!(
                            &d.as_slice()[start..start + size],
                            &before[start..start + size]
                        );
                    }
                }
                if journaled
                    && matches!(kind, 13 | 14)
                    && let Some(dir) = std::env::var_os("HFS_NAMESPACE_IMAGES")
                {
                    let dir = std::path::Path::new(&dir);
                    std::fs::create_dir_all(dir).unwrap();
                    let name = format!("namespace-compressed-{kind}-{sensitive}");
                    std::fs::write(dir.join(format!("{name}.img")), d.as_slice()).unwrap();
                    std::fs::write(dir.join(format!("{name}.expected.bin")), &plain).unwrap();
                }
                cases += 1;
            }
        }
    }
    println!("NAMESPACE_COMPRESSED: {cases} encoded-storage preservation cases");
}

fn catalog_flag(bytes: &mut [u8], cnid: u32) {
    let cat = volume::be32(bytes, 1312) as usize * 4096;
    let node_size = volume::be16(bytes, cat + 32) as usize;
    let mut leaf = volume::be32(bytes, cat + 24);
    let mut found = 0;
    while leaf != 0 {
        let node = cat + leaf as usize * node_size;
        for i in 0..volume::be16(bytes, node + 10) as usize {
            let key = node + volume::be16(bytes, node + node_size - 2 * (i + 1)) as usize;
            let body = key + 2 + volume::be16(bytes, key) as usize;
            if volume::be16(bytes, body) == 2 && volume::be32(bytes, body + 8) == cnid {
                bytes[body + 41] |= 0x20;
                found += 1;
            }
        }
        leaf = volume::be32(bytes, node);
    }
    assert_eq!(found, 1);
}
fn compression_name(bytes: &mut [u8], cnid: u32) {
    let tree = volume::be32(bytes, 1392) as usize * 4096;
    let size = volume::be16(bytes, tree + 32) as usize;
    let original = "com.a0000.decmpfs"
        .encode_utf16()
        .flat_map(u16::to_be_bytes)
        .collect::<Vec<_>>();
    let replacement = "com.apple.decmpfs"
        .encode_utf16()
        .flat_map(u16::to_be_bytes)
        .collect::<Vec<_>>();
    assert_eq!(original.len(), replacement.len());
    let mut leaf = volume::be32(bytes, tree + 24);
    let mut found = 0;
    while leaf != 0 {
        let node = tree + leaf as usize * size;
        for i in 0..volume::be16(bytes, node + 10) as usize {
            let key = node + volume::be16(bytes, node + size - 2 * (i + 1)) as usize;
            if volume::be32(bytes, key + 4) == cnid
                && volume::be16(bytes, key + 12) as usize * 2 == original.len()
                && bytes[key + 14..key + 14 + original.len()] == original
            {
                bytes[key + 14..key + 14 + replacement.len()].copy_from_slice(&replacement);
                found += 1;
            }
        }
        leaf = volume::be32(bytes, node);
    }
    assert_eq!(found, 1);
}
fn sensitive_folder_counts(bytes: &mut [u8]) {
    let cat = volume::be32(bytes, 1312) as usize * 4096;
    let size = volume::be16(bytes, cat + 32) as usize;
    let mut leaf = volume::be32(bytes, cat + 24);
    let mut folders = Vec::new();
    let mut children = std::collections::BTreeMap::<u32, u32>::new();
    while leaf != 0 {
        let node = cat + leaf as usize * size;
        for i in 0..volume::be16(bytes, node + 10) as usize {
            let key = node + volume::be16(bytes, node + size - 2 * (i + 1)) as usize;
            let body = key + 2 + volume::be16(bytes, key) as usize;
            if volume::be16(bytes, body) == 1 {
                let id = volume::be32(bytes, body + 8);
                let parent = volume::be32(bytes, key + 2);
                folders.push((body, id));
                *children.entry(parent).or_default() += 1;
            }
        }
        leaf = volume::be32(bytes, node);
    }
    assert!(!folders.is_empty());
    for (body, id) in folders {
        let flags = volume::be16(bytes, body + 2) | 0x10;
        bytes[body + 2..body + 4].copy_from_slice(&flags.to_be_bytes());
        bytes[body + 84..body + 88]
            .copy_from_slice(&children.get(&id).copied().unwrap_or(0).to_be_bytes());
    }
}
fn fixture(
    kind: u32,
    journal: bool,
    sensitive: bool,
    user_resource: bool,
) -> (MemoryBackend, Vec<u8>) {
    fixture_with_named(kind, journal, sensitive, user_resource, false)
}
fn fixture_with_named(
    kind: u32,
    journal: bool,
    sensitive: bool,
    user_resource: bool,
    named: bool,
) -> (MemoryBackend, Vec<u8>) {
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
        "/compressed",
        &mut &b""[..],
        0,
        0o644,
        501,
        20,
        0,
    )
    .unwrap();
    fs.create_file(
        &mut disk,
        "/ordinary",
        &mut &b"untouched"[..],
        9,
        0o644,
        501,
        20,
        0,
    )
    .unwrap();
    let cnid = volume::be32(&fs.catalog_record("/compressed").unwrap(), 8);
    let (plain, attr, rf) = payload(kind);
    if !rf.is_empty() || user_resource {
        let bytes = if user_resource {
            b"user resource".as_slice()
        } else {
            rf.as_slice()
        };
        let mut handle = fs
            .open_resource_fork_rw(&mut disk, std::path::Path::new("/compressed"))
            .unwrap();
        std::io::Write::write_all(&mut handle, bytes).unwrap();
        handle.sync().unwrap();
    }
    fs.set_inline_attribute(&mut disk, cnid, "com.a0000.decmpfs", Some(&attr))
        .unwrap();
    fs.flush(&mut disk).unwrap();
    fs.set_inline_attribute(&mut disk, cnid, "com.example.note", Some(b"keep"))
        .unwrap();
    if named {
        fs.flush(&mut disk).unwrap();
        let store = hfs_bridge::named_streams::Store {
            next_id: 2,
            streams: vec![hfs_bridge::named_streams::Stream {
                id: 1,
                name: "prior".into(),
                data: b"old stream".to_vec(),
                allocation: 4096,
            }],
        };
        let bytes = hfs_bridge::named_streams::encode(&store).unwrap();
        fs.set_inline_attribute(
            &mut disk,
            cnid,
            hfs_bridge::named_streams::ATTRIBUTE,
            Some(&bytes),
        )
        .unwrap();
    }
    fs.flush(&mut disk).unwrap();
    drop(fs);
    let mut bytes = disk.into_bytes();
    compression_name(&mut bytes, cnid);
    catalog_flag(&mut bytes, cnid);
    if sensitive {
        bytes[1024..1026].copy_from_slice(b"HX");
        bytes[1026..1028].copy_from_slice(&5u16.to_be_bytes());
        let cat = volume::be32(&bytes, 1312) as usize * 4096;
        bytes[cat + 51] = 0xbc;
        sensitive_folder_counts(&mut bytes);
        let alt = bytes.len() - 1024;
        let header = bytes[1024..1536].to_vec();
        bytes[alt..alt + 512].copy_from_slice(&header);
    }
    (MemoryBackend::from_bytes(bytes), plain)
}
fn retain(bytes: &[u8], name: &str) {
    if let Some(directory) = std::env::var_os("HFS_COMPRESSION_ARTIFACT_DIR") {
        std::fs::create_dir_all(&directory).unwrap();
        use std::io::Write;
        let mut output = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(std::path::PathBuf::from(directory).join(name))
            .unwrap();
        output.write_all(bytes).unwrap();
        output.sync_all().unwrap();
    }
}
#[test]
fn lzbitmap_images_for_independent_native_validation() {
    for kind in [13, 14] {
        for journal in [false, true] {
            for sensitive in [false, true] {
                let user_resource = kind == 13;
                let (disk, mut plain) = fixture(kind, journal, sensitive, user_resource);
                let baseline = disk.into_bytes();
                let name = format!("lzbitmap-{kind}-{journal}-{sensitive}");
                retain(&baseline, &format!("{name}.img"));
                retain(&plain, &format!("{name}.expected.bin"));
                let device = faults::Disk::new(&baseline);
                let observer = device.clone();
                let mut adapter = Adapter::from_device(device).unwrap();
                let handle = adapter
                    .open(
                        "\\compressed",
                        OpenRequest {
                            access: Access::ALL,
                            ..Default::default()
                        },
                    )
                    .unwrap();
                adapter
                    .write(handle, 65530, b"LZBITMAP-Windows-conversion", false, false)
                    .unwrap();
                let replacement = b"LZBITMAP-Windows-conversion";
                plain.resize(plain.len().max(65530 + replacement.len()), 0);
                plain[65530..65530 + replacement.len()].copy_from_slice(replacement);
                adapter.close(handle).unwrap();
                adapter.shutdown().unwrap();
                let converted = observer.0.lock().unwrap().durable.clone();
                verify_compressed_recovery(converted.clone(), &[], &plain, user_resource);
                retain(&converted, &format!("{name}-converted.img"));
                retain(&plain, &format!("{name}-converted.expected.bin"));
            }
        }
    }
}
#[test]
fn compressed_replacement_preflight_decodes_all_formats_without_mutation() {
    for kind in [1, 3, 4, 7, 8, 9, 10, 11, 12, 13, 14] {
        for user_resource in [false, true]
            .into_iter()
            .filter(|user| !*user || matches!(kind, 1 | 3 | 7 | 9 | 11 | 13))
        {
            let (mut disk, plain) = fixture(kind, true, false, user_resource);
            let before = disk.as_slice().to_vec();
            let fs = HfsPlus::open(&mut disk).unwrap();
            let cnid = volume::be32(&fs.catalog_record("/compressed").unwrap(), 8);
            fs.validate_compressed_replacement(&mut disk, cnid, plain.len() as u64)
                .unwrap();
            assert!(
                fs.validate_compressed_replacement(&mut disk, cnid, u64::MAX)
                    .is_err()
            );
            assert!(disk.as_slice() == before);
        }
    }
}
#[test]
fn compressed_replacement_preflight_rejects_shared_unallocated_or_locked_storage() {
    for defect in 0..6 {
        let (mut disk, _) = fixture(if defect == 5 { 12 } else { 8 }, true, false, false);
        let fs = HfsPlus::open(&mut disk).unwrap();
        let body = fs.catalog_record("/compressed").unwrap();
        let ordinary = fs.catalog_record("/ordinary").unwrap();
        let cnid = volume::be32(&body, 8);
        drop(fs);
        let mut bytes = disk.into_bytes();
        let cat = volume::be32(&bytes, 1312) as usize * 4096;
        let size = volume::be16(&bytes, cat + 32) as usize;
        let mut leaf = volume::be32(&bytes, cat + 24);
        let mut target = None;
        let mut sibling = None;
        while leaf != 0 {
            let node = cat + leaf as usize * size;
            for i in 0..volume::be16(&bytes, node + 10) as usize {
                let key = node + volume::be16(&bytes, node + size - 2 * (i + 1)) as usize;
                let at = key + 2 + volume::be16(&bytes, key) as usize;
                if volume::be16(&bytes, at) == 2 {
                    if volume::be32(&bytes, at + 8) == cnid {
                        target = Some(at);
                    }
                    if volume::be32(&bytes, at + 8) == volume::be32(&ordinary, 8) {
                        sibling = Some(at);
                    }
                }
            }
            leaf = volume::be32(&bytes, node);
        }
        match defect {
            0..=2 => {
                let block = match defect {
                    0 => volume::be32(&body, 184),
                    1 => volume::be32(&ordinary, 104),
                    _ => volume::be32(&bytes, 1312),
                } as usize;
                let bitmap = volume::be32(&bytes, 1152) as usize * 4096;
                bytes[bitmap + block / 8] &= !(0x80 >> (block % 8));
            }
            3 => {
                bytes[target.unwrap() + 41] |= 2;
            }
            4 => {
                bytes[sibling.unwrap() + 88..sibling.unwrap() + 168]
                    .copy_from_slice(&body[168..248]);
            }
            _ => {
                let resource = volume::be32(&body, 184) as usize * 4096;
                let last = u32::from_le_bytes(bytes[resource + 4..resource + 8].try_into().unwrap())
                    as usize;
                bytes[resource + last] ^= 0xff; // Corrupt the final LZFSE unit.
            }
        }
        let before = bytes.clone();
        let mut disk = MemoryBackend::from_bytes(bytes);
        let mut fs = HfsPlus::open(&mut disk).unwrap();
        assert!(
            fs.validate_compressed_replacement(&mut disk, cnid, 37)
                .is_err(),
            "accepted ownership defect {defect}"
        );
        assert!(
            fs.set_basic_metadata_with_publication(
                &mut disk,
                cnid,
                BASIC_TIMES,
                Some(0x22),
                &[(2, BASIC_ROOT, Some(b"refused"))]
            )
            .is_err()
        );
        if defect != 3 {
            assert!(
                fs.set_namespace_metadata_with_publication(
                    &mut disk,
                    &[fstool::fs::hfs_plus::CatalogUpdate {
                        cnid,
                        times: BASIC_TIMES,
                        attributes: None
                    }],
                    &[(2, BASIC_ROOT, Some(b"refused"))],
                )
                .is_err(),
                "namespace accepted ownership defect {defect}"
            );
        }
        assert!(!fs.requires_reopen());
        assert!(disk.as_slice() == before);
    }
}
#[test]
fn compressed_replacement_publishes_ordinary_data_and_keeps_user_metadata() {
    for (kind, journal, sensitive) in
        [1, 3, 4, 7, 8, 9, 10, 11, 12, 13, 14]
            .into_iter()
            .flat_map(|kind| {
                [(false, false), (false, true), (true, false), (true, true)]
                    .map(|(journal, sensitive)| (kind, journal, sensitive))
            })
    {
        for size in [0, 70019] {
            let user_resource = matches!(kind, 1 | 3 | 7 | 9 | 11 | 13);
            let (mut disk, _) = fixture(kind, journal, sensitive, user_resource);
            let mut fs = HfsPlus::open(&mut disk).unwrap();
            let original = fs.catalog_record("/compressed").unwrap();
            let cnid = volume::be32(&original, 8);
            let payload = (0..size).map(|i| (i % 239) as u8).collect::<Vec<_>>();
            fs.replace_compressed_data(
                &mut disk,
                std::path::Path::new("/compressed"),
                &mut payload.as_slice(),
                payload.len() as u64,
            )
            .unwrap();
            drop(fs);
            let mut fs = HfsPlus::open(&mut disk).unwrap();
            let body = fs.catalog_record("/compressed").unwrap();
            let mut expected_body = original[..88].to_vec();
            expected_body[41] &= !0x20;
            assert_eq!(&body[..88], expected_body);
            assert!(
                fs.inline_attribute(&mut disk, cnid, "com.apple.decmpfs")
                    .unwrap()
                    .is_none()
            );
            assert_eq!(
                fs.inline_attribute(&mut disk, cnid, "com.example.note")
                    .unwrap()
                    .unwrap(),
                b"keep"
            );
            let mut actual = Vec::new();
            fs.open_file_ro(&mut disk, std::path::Path::new("/compressed"))
                .unwrap()
                .read_to_end(&mut actual)
                .unwrap();
            assert_eq!(actual, payload);
            let mut resource = Vec::new();
            if user_resource {
                fs.open_resource_fork_reader(&mut disk, "/compressed")
                    .unwrap()
                    .read_to_end(&mut resource)
                    .unwrap();
            } else {
                assert!(
                    fs.open_resource_fork_reader(&mut disk, "/compressed")
                        .is_err()
                );
            }
            assert_eq!(
                resource,
                if user_resource {
                    b"user resource".to_vec()
                } else {
                    Vec::new()
                }
            );
            retain(
                disk.as_slice(),
                &format!("converted-{kind}-{size}-{journal}-{sensitive}.img"),
            );
        }
    }
}
#[test]
fn compressed_replacement_failed_input_never_publishes_or_retries() {
    for extra in [false, true] {
        let (mut disk, plain) = fixture(8, true, false, false);
        let mut fs = HfsPlus::open(&mut disk).unwrap();
        let original = fs.catalog_record("/compressed").unwrap();
        let payload = vec![7; 70019];
        let declared = if extra { 70018 } else { 70020 };
        assert!(
            fs.replace_compressed_data(
                &mut disk,
                std::path::Path::new("/compressed"),
                &mut payload.as_slice(),
                declared
            )
            .is_err()
        );
        assert!(fs.flush(&mut disk).is_err());
        drop(fs);
        let mut fs = HfsPlus::open(&mut disk).unwrap();
        assert_eq!(fs.catalog_record("/compressed").unwrap(), original);
        let mut actual = Vec::new();
        fs.open_file_ro(&mut disk, std::path::Path::new("/compressed"))
            .unwrap()
            .read_to_end(&mut actual)
            .unwrap();
        assert_eq!(actual, plain);
    }
}

#[test]
fn cli_compressed_edits_stream_old_bytes_gaps_and_inputs_without_changing_source() {
    use hfs_bridge::engine::{self, FileEdit};
    use std::io::Write;
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::current_dir()
        .unwrap()
        .join("artifacts/milestone-21")
        .join(format!("cli-conversion-{}-{nonce}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    let input_bytes = (0..70019).map(|i| (i % 233) as u8).collect::<Vec<_>>();
    let input = root.join("input.bin");
    std::fs::write(&input, &input_bytes).unwrap();
    let patch = root.join("patch.bin");
    let patch_bytes = b"independent-patch-oracle";
    std::fs::write(&patch, patch_bytes).unwrap();
    let empty = root.join("empty.bin");
    std::fs::write(&empty, []).unwrap();
    let mut manifest = std::fs::File::create(root.join("expected.tsv")).unwrap();
    for kind in [1, 3, 4, 7, 8, 9, 10, 11, 12, 13, 14] {
        let (disk, plain) = fixture(
            kind,
            true,
            kind % 2 == 0,
            matches!(kind, 1 | 3 | 7 | 9 | 11 | 13),
        );
        let source = root.join(format!("source-{kind}.img"));
        std::fs::write(&source, disk.as_slice()).unwrap();
        let cases = [
            ("overwrite", FileEdit::Overwrite(&input)),
            ("empty", FileEdit::Truncate(0)),
            ("shrink", FileEdit::Truncate(plain.len() as u64 / 2)),
            ("grow", FileEdit::Truncate(plain.len() as u64 + 70019)),
            (
                "patch",
                FileEdit::Patch {
                    source: &patch,
                    offset: 13,
                },
            ),
            (
                "cross",
                FileEdit::Patch {
                    source: &patch,
                    offset: 65530,
                },
            ),
            (
                "sparse",
                FileEdit::Patch {
                    source: &patch,
                    offset: plain.len() as u64 + 31,
                },
            ),
            (
                "noop",
                FileEdit::Patch {
                    source: &empty,
                    offset: u64::MAX,
                },
            ),
        ];
        for (label, edit) in cases {
            let name = format!("cli-converted-{kind}-{label}.img");
            let output = root.join(&name);
            engine::edit_file(&source, &output, 0, None, "/compressed", edit).unwrap();
            let mut expected = plain.clone();
            match edit {
                FileEdit::Overwrite(_) => expected = input_bytes.clone(),
                FileEdit::Truncate(size) => expected.resize(size as usize, 0),
                FileEdit::Patch { offset, .. } if label != "noop" => {
                    let start = offset as usize;
                    expected.resize(expected.len().max(start + patch_bytes.len()), 0);
                    expected[start..start + patch_bytes.len()].copy_from_slice(patch_bytes);
                }
                FileEdit::Patch { .. } => {}
            }
            let mut device = hfs_bridge::image::Image::read_only(&output, 0, None).unwrap();
            let fs = engine::open_checked(&mut device).unwrap();
            let mut actual = Vec::new();
            fs.open_file_reader(&mut device, "/compressed")
                .unwrap()
                .read_to_end(&mut actual)
                .unwrap();
            assert_eq!(actual, expected, "kind {kind} / {label}");
            assert_eq!(std::fs::read(&source).unwrap(), disk.as_slice());
            if label == "noop" {
                assert_eq!(
                    std::fs::read(&output).unwrap(),
                    disk.as_slice(),
                    "empty patch converted a compressed file"
                );
            }
            writeln!(
                manifest,
                "{name}\t{}",
                engine::sha256(&mut expected.as_slice()).unwrap()
            )
            .unwrap();
        }
    }
    manifest.sync_all().unwrap();
    println!("CLI_CONVERSION_ARTIFACT_DIR: {}", root.display());
}
#[test]
fn compressed_conversion_is_atomic_across_selected_sector_persistence_states() {
    let mut checks = 0;
    let mut replay_checks = 0;
    for kind in [3, 4, 7, 8, 11, 12, 13, 14] {
        for size in [0, 8193] {
            let user_resource = matches!(kind, 3 | 7 | 11 | 13);
            let (disk, old_data) = fixture(kind, true, kind % 2 == 0, user_resource);
            let baseline = disk.into_bytes();
            let jib = volume::be32(&baseline, 1036) as usize * 4096;
            let journal = volume::be64(&baseline, jib + 36) as usize;
            let payload = vec![0x73; size];
            let mut disk = faults::Disk::new(&baseline);
            let observer = disk.clone();
            let mut fs = HfsPlus::open(&mut disk).unwrap();
            observer.arm(None);
            fs.replace_compressed_data(
                &mut disk,
                std::path::Path::new("/compressed"),
                &mut payload.as_slice(),
                size as u64,
            )
            .unwrap();
            let calls = observer.0.lock().unwrap().calls;
            assert!(calls > 10);
            drop(fs);
            let mut pending = None;
            for stop in 0..calls {
                let mut disk = faults::Disk::new(&baseline);
                let observer = disk.clone();
                let mut fs = HfsPlus::open(&mut disk).unwrap();
                observer.arm(Some(stop));
                assert!(
                    fs.replace_compressed_data(
                        &mut disk,
                        std::path::Path::new("/compressed"),
                        &mut payload.as_slice(),
                        size as u64
                    )
                    .is_err()
                );
                let calls = observer.0.lock().unwrap().calls;
                assert!(fs.flush(&mut disk).is_err());
                drop(fs);
                assert_eq!(observer.0.lock().unwrap().calls, calls);
                for policy in 0..6 {
                    let bytes = observer.snapshot(policy, journal);
                    let mut inspect = faults::Disk::new(&bytes);
                    if matches!(
                        volume::inspect(&mut inspect).unwrap().journal,
                        volume::Journal::Pending { .. }
                    ) {
                        pending.get_or_insert_with(|| bytes.clone());
                        inspect.arm(Some(0));
                        assert!(Adapter::from_device(inspect.clone()).is_err());
                        assert_eq!(
                            inspect.0.lock().unwrap().calls,
                            0,
                            "production replayed a conversion journal"
                        );
                    }
                    verify_compressed_recovery(bytes, &old_data, &payload, user_resource);
                    checks += 1;
                }
            }
            let pending = pending.expect("no pending conversion journal observed");
            let mut replay = faults::Disk::new(&pending);
            HfsPlus::open(&mut replay).unwrap();
            let count = replay.0.lock().unwrap().calls;
            assert!(count > 0);
            for stop in 0..count {
                let mut interrupted = faults::Disk::new(&pending);
                interrupted.arm(Some(stop));
                assert!(HfsPlus::open(&mut interrupted).is_err());
                for policy in 0..6 {
                    verify_compressed_recovery(
                        interrupted.snapshot(policy, journal),
                        &old_data,
                        &payload,
                        user_resource,
                    );
                    replay_checks += 1;
                }
            }
        }
    }
    println!(
        "COMPRESSED_CONVERSION_MATRIX: {checks} commit + {replay_checks} replay persistence checks; 16 scenarios; no failure retried"
    );
}

fn verify_compressed_recovery(
    bytes: Vec<u8>,
    old_data: &[u8],
    payload: &[u8],
    user_resource: bool,
) {
    let mut recovered = MemoryBackend::from_bytes(bytes);
    let fs = HfsPlus::open(&mut recovered).unwrap(); // Test-only journal replay.
    let body = fs.catalog_record("/compressed").unwrap();
    let cnid = volume::be32(&body, 8);
    let compressed = body[41] & 0x20 != 0;
    let mut actual = Vec::new();
    fs.open_file_reader(&mut recovered, "/compressed")
        .unwrap()
        .read_to_end(&mut actual)
        .unwrap();
    assert_eq!(actual, if compressed { old_data } else { payload });
    assert_eq!(
        fs.inline_attribute(&mut recovered, cnid, "com.apple.decmpfs")
            .unwrap()
            .is_some(),
        compressed
    );
    assert_eq!(
        fs.inline_attribute(&mut recovered, cnid, "com.example.note")
            .unwrap()
            .unwrap(),
        b"keep"
    );
    if compressed {
        fs.validate_compressed_replacement(&mut recovered, cnid, payload.len() as u64)
            .unwrap();
    } else {
        assert_eq!(volume::be64(&body, 168), if user_resource { 13 } else { 0 });
    }
    if user_resource {
        let mut resource = Vec::new();
        fs.open_resource_fork_reader(&mut recovered, "/compressed")
            .unwrap()
            .read_to_end(&mut resource)
            .unwrap();
        assert_eq!(resource, b"user resource");
    }
    drop(fs);
    catalog_wire::audit(recovered.as_slice());
    attribute_wire::audit_initialized(recovered.as_slice());
}
#[test]
fn engine_decodes_inline_resource_and_random_seeks_without_mutation() {
    for journal in [false, true] {
        for sensitive in [false, true] {
            for kind in [1, 3, 4, 7, 8, 9, 10, 11, 12, 13, 14] {
                let (mut disk, plain) = fixture(kind, journal, sensitive, false);
                let before = disk.as_slice().to_vec();
                let mut fs = HfsPlus::open(&mut disk).unwrap();
                let mut file = fs
                    .open_file_ro(&mut disk, std::path::Path::new("/compressed"))
                    .unwrap();
                assert_eq!(file.len(), plain.len() as u64);
                for at in [0, 1, 4, 65534, 65536, plain.len(), plain.len() + 19] {
                    file.seek(SeekFrom::Start(at as u64)).unwrap();
                    let mut actual = [0x71; 17];
                    let got = file.read(&mut actual).unwrap();
                    let want = plain.len().saturating_sub(at).min(17);
                    assert_eq!(got, want);
                    assert_eq!(
                        &actual[..got],
                        &plain[at.min(plain.len())..at.min(plain.len()) + want]
                    );
                    assert!(actual[got..].iter().all(|b| *b == 0x71));
                }
                assert!(file.seek(SeekFrom::End(-1 - (plain.len() as i64))).is_err());
                file.seek(SeekFrom::Start(0)).unwrap();
                let mut actual = Vec::new();
                file.read_to_end(&mut actual).unwrap();
                assert_eq!(actual, plain);
                drop(file);
                drop(fs);
                assert!(
                    disk.as_slice() == before,
                    "read-only engine changed image bytes"
                );
                retain(
                    disk.as_slice(),
                    &format!("compressed-{kind}-{journal}-{sensitive}.img"),
                );
                retain(
                    &plain,
                    &format!("compressed-{kind}-{journal}-{sensitive}.expected.bin"),
                );
            }
        }
    }
}
#[test]
fn windows_reads_decoded_size_and_hides_compression_storage() {
    for kind in [1, 3, 4, 7, 8, 9, 10, 11, 12, 13, 14] {
        let (disk, plain) = fixture(kind, true, false, false);
        let mut disk = disk;
        let before = hfs_bridge::engine::snapshot_device(
            &mut disk,
            "/compressed",
            &["com.apple.decmpfs", "com.example.note"],
        )
        .unwrap();
        let ordinary = hfs_bridge::engine::snapshot_device(&mut disk, "/ordinary", &[]).unwrap();
        let mut adapter = Adapter::from_device(disk).unwrap();
        let request = OpenRequest {
            access: Access::READ,
            ..Default::default()
        };
        let handle = adapter.open("\\compressed", request).unwrap();
        assert_eq!(adapter.file_info(handle).unwrap().size, plain.len() as u64);
        let mut actual = vec![0; plain.len() + 11];
        let got = adapter.read(handle, 0, &mut actual).unwrap();
        assert_eq!(&actual[..got], plain);
        let names = adapter.extended_attributes(handle).unwrap();
        assert_eq!(names.len(), 1);
        assert_eq!(
            hfs_bridge::ea::changes(&hfs_bridge::ea::encode(&names).unwrap(), &[]).unwrap()[0].name,
            "com.example.note"
        );
        assert!(
            !adapter
                .streams(handle)
                .unwrap()
                .iter()
                .any(|(name, _)| *name == "AFP_Resource")
        );
        assert_eq!(
            adapter
                .open("\\compressed:AFP_Resource", request)
                .unwrap_err()
                .status,
            Status::NotFound
        );
        let writer = adapter
            .open(
                "\\compressed",
                OpenRequest {
                    access: Access::ALL,
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(adapter.file_info(writer).unwrap().attributes & 1, 0);
        adapter.close(writer).unwrap();
        assert!(adapter.failure().is_none());
        adapter.close(handle).unwrap();
        let mut disk = adapter.shutdown().unwrap();
        // The mounted adapter flushes volume housekeeping at shutdown. Compare
        // file metadata, decoded data, resources and attributes independently.
        assert_eq!(
            hfs_bridge::engine::snapshot_device(
                &mut disk,
                "/compressed",
                &["com.apple.decmpfs", "com.example.note"]
            )
            .unwrap(),
            before
        );
        assert_eq!(
            hfs_bridge::engine::snapshot_device(&mut disk, "/ordinary", &[]).unwrap(),
            ordinary
        );
        let fs = HfsPlus::open(&mut disk).unwrap();
        let id = volume::be32(&fs.catalog_record("/compressed").unwrap(), 8);
        assert!(
            fs.inline_attribute(&mut disk, id, "com.apple.decmpfs")
                .unwrap()
                .is_some()
        );
    }
}
#[test]
fn inline_compression_keeps_an_ordinary_user_resource_visible() {
    let (mut disk, plain) = fixture(7, true, false, true);
    let fs = HfsPlus::open(&mut disk).unwrap();
    let mut content = Vec::new();
    fs.open_resource_fork_reader(&mut disk, "/compressed")
        .unwrap()
        .read_to_end(&mut content)
        .unwrap();
    assert_eq!(content, b"user resource");
    drop(fs);
    let mut adapter = Adapter::from_device(disk).unwrap();
    let req = OpenRequest {
        access: Access::READ,
        ..Default::default()
    };
    let data = adapter.open("\\compressed", req).unwrap();
    assert_eq!(adapter.file_info(data).unwrap().size, plain.len() as u64);
    let resource = adapter.open("\\compressed:AFP_Resource", req).unwrap();
    let mut bytes = [0; 40];
    let got = adapter.read(resource, 0, &mut bytes).unwrap();
    assert_eq!(&bytes[..got], b"user resource");
    adapter.close(resource).unwrap();
    adapter.close(data).unwrap();
    adapter.shutdown().unwrap();
}

#[test]
fn windows_compressed_writes_resize_allocation_and_overwrite_preserve_identity_and_user_forks() {
    for kind in [1, 3, 4, 7, 8, 9, 10, 11, 12, 13, 14] {
        for operation in 0..10 {
            let resource = matches!(kind, 1 | 3 | 7 | 9 | 11 | 13);
            let (mut disk, plain) = fixture(kind, true, kind % 2 == 0, resource);
            let fs = HfsPlus::open(&mut disk).unwrap();
            let before = fs.catalog_record("/compressed").unwrap();
            let mut adapter = Adapter::from_device(disk).unwrap();
            let request = OpenRequest {
                access: Access::ALL,
                ..Default::default()
            };
            let handle = adapter.open("\\compressed", request).unwrap();
            let reader = adapter
                .open(
                    "\\compressed",
                    OpenRequest {
                        access: Access::READ,
                        ..Default::default()
                    },
                )
                .unwrap();
            if resource {
                assert_eq!(
                    adapter
                        .open("\\compressed:AFP_Resource", request)
                        .unwrap_err()
                        .status,
                    Status::AccessDenied
                );
            }
            let mut expected = plain.clone();
            match operation {
                0..=2 => {
                    let offset = [13, 65530, plain.len() + 31][operation];
                    let patch = b"Windows independent patch";
                    adapter
                        .write(handle, offset as u64, patch, false, false)
                        .unwrap();
                    expected.resize(expected.len().max(offset + patch.len()), 0);
                    expected[offset..offset + patch.len()].copy_from_slice(patch);
                }
                3 => {
                    adapter
                        .write(handle, u64::MAX, b"append", true, false)
                        .unwrap();
                    expected.extend_from_slice(b"append");
                }
                4 => {
                    adapter.set_size(handle, 13).unwrap();
                    expected.resize(13, 0);
                }
                5 => {
                    let size = plain.len() + 70019;
                    adapter.set_size(handle, size as u64).unwrap();
                    expected.resize(size, 0);
                }
                6 => {
                    let value = vec![0x46; 70019];
                    adapter
                        .overwrite_with_ea(
                            handle,
                            0x20,
                            true,
                            8192,
                            &[hfs_bridge::ea::Change {
                                name: "com.example.new".into(),
                                value: Some(value.clone()),
                            }],
                        )
                        .unwrap();
                    adapter.write(handle, 0, b"new", false, false).unwrap();
                    expected = b"new".to_vec();
                }
                7 => {
                    adapter
                        .set_allocation_size(
                            handle,
                            (plain.len() as u64).div_ceil(4096) * 4096 + 8192,
                        )
                        .unwrap();
                }
                8 => {
                    adapter.set_allocation_size(handle, 4096).unwrap();
                    expected.truncate(4096);
                }
                9 => {
                    assert_eq!(
                        adapter.write(handle, u64::MAX, b"", false, false).unwrap(),
                        0
                    );
                    assert_eq!(
                        adapter
                            .write(handle, plain.len() as u64 + 3, b"ignored", false, true)
                            .unwrap(),
                        0
                    );
                    adapter.set_size(handle, plain.len() as u64).unwrap();
                }
                _ => unreachable!(),
            }
            assert_eq!(
                adapter.file_info(reader).unwrap().cnid,
                volume::be32(&before, 8)
            );
            assert_eq!(
                adapter.file_info(reader).unwrap().size,
                expected.len() as u64
            );
            let mut actual = vec![0; expected.len() + 1];
            let count = adapter.read(reader, 0, &mut actual).unwrap();
            assert_eq!(&actual[..count], expected);
            adapter.close(reader).unwrap();
            adapter.close(handle).unwrap();
            let mut disk = adapter.shutdown().unwrap();
            verify_compressed_recovery(disk.as_slice().to_vec(), &plain, &expected, resource);
            let fs = HfsPlus::open(&mut disk).unwrap();
            let after = fs.catalog_record("/compressed").unwrap();
            assert_eq!(&after[8..16], &before[8..16]);
            assert_eq!(&after[32..40], &before[32..40]);
            assert_eq!(&after[42..56], &before[42..56]);
            assert_eq!(&after[60..88], &before[60..88]);
            assert_eq!(after[41] & 32 != 0, operation == 9);
            if operation == 6 {
                assert_eq!(
                    fs.inline_attribute(&mut disk, volume::be32(&before, 8), "com.example.new")
                        .unwrap()
                        .unwrap(),
                    vec![0x46; 70019]
                );
            }
            if operation == 9 {
                assert_eq!(after, before);
            }
            let mut untouched = Vec::new();
            fs.open_file_reader(&mut disk, "/ordinary")
                .unwrap()
                .read_to_end(&mut untouched)
                .unwrap();
            assert_eq!(untouched, b"untouched");
        }
    }
}

#[test]
fn windows_compressed_callbacks_never_acknowledge_failed_conversion_or_retry() {
    let mut checks = 0;
    for kind in [3, 8, 13, 14] {
        let user_resource = matches!(kind, 3 | 13);
        let (disk, old) = fixture(kind, true, false, user_resource);
        let baseline = disk.into_bytes();
        let jib = volume::be32(&baseline, 1036) as usize * 4096;
        let journal = volume::be64(&baseline, jib + 36) as usize;
        for operation in 0..4 {
            let allocation = (old.len() as u64).div_ceil(4096) * 4096 + 8192;
            let constructor_value = vec![0x46; 70019];
            let mut constructor_finder = [0; 32];
            constructor_finder[..8].copy_from_slice(b"NEWWTYPE");
            constructor_finder[16] = 0x91; // Private bytes must not be copied.
            constructor_finder[24] = 0x31;
            constructor_finder[28] = 0x92;
            let changes = [
                hfs_bridge::ea::Change {
                    name: "com.example.new".into(),
                    value: Some(constructor_value.clone()),
                },
                hfs_bridge::ea::Change {
                    name: "com.apple.FinderInfo".into(),
                    value: Some(constructor_finder.to_vec()),
                },
            ];
            let perform =
                |adapter: &mut Adapter<faults::Disk>, handle| -> hfs_bridge::windows::Result<()> {
                    match operation {
                        0 => adapter
                            .write(handle, 65530, b"fault-checked Windows patch", false, false)
                            .map(|_| ()),
                        1 => adapter.set_size(handle, 13),
                        2 => adapter.set_allocation_size(handle, allocation),
                        3 => adapter.overwrite_with_ea(handle, 0x20, true, 8192, &changes),
                        _ => unreachable!(),
                    }
                };
            let mut expected = old.clone();
            match operation {
                0 => {
                    let patch = b"fault-checked Windows patch";
                    expected.resize(expected.len().max(65530 + patch.len()), 0);
                    expected[65530..65530 + patch.len()].copy_from_slice(patch);
                }
                1 => expected.resize(13, 0),
                2 => {}
                3 => expected.clear(),
                _ => unreachable!(),
            }
            let disk = faults::Disk::new(&baseline);
            let observer = disk.clone();
            let mut adapter = Adapter::from_device(disk).unwrap();
            let request = OpenRequest {
                access: Access::ALL,
                ..Default::default()
            };
            let handle = adapter.open("\\compressed", request).unwrap();
            observer.arm(None);
            perform(&mut adapter, handle).unwrap();
            let calls = observer.0.lock().unwrap().calls;
            assert!(calls > 10);
            let committed = observer.0.lock().unwrap().durable.clone();
            assert_eq!(
                volume::be32(&committed, 1092),
                volume::be32(&baseline, 1092) + 1,
                "write/resize/allocation/overwrite must publish only once"
            );
            verify_compressed_recovery(committed.clone(), &old, &expected, user_resource);
            if operation == 3 {
                verify_compressed_constructor_recovery(
                    &committed,
                    &constructor_value,
                    &constructor_finder,
                );
            }
            retain(
                &committed,
                &format!("windows-converted-{kind}-{operation}.img"),
            );
            retain(
                &expected,
                &format!("windows-converted-{kind}-{operation}.expected.bin"),
            );
            drop(adapter);
            for stop in 0..calls {
                let disk = faults::Disk::new(&baseline);
                let observer = disk.clone();
                let mut adapter = Adapter::from_device(disk).unwrap();
                let handle = adapter.open("\\compressed", request).unwrap();
                observer.arm(Some(stop));
                assert!(perform(&mut adapter, handle).is_err());
                assert!(adapter.failure().is_some());
                let calls = observer.0.lock().unwrap().calls;
                assert_eq!(
                    perform(&mut adapter, handle).unwrap_err().status,
                    Status::FailedVolume
                );
                assert!(adapter.close(handle).is_err());
                assert!(adapter.shutdown().is_err());
                assert_eq!(observer.0.lock().unwrap().calls, calls);
                for policy in 0..6 {
                    let snapshot = observer.snapshot(policy, journal);
                    if operation == 3 {
                        verify_compressed_constructor_recovery(
                            &snapshot,
                            &constructor_value,
                            &constructor_finder,
                        );
                    }
                    verify_compressed_recovery(snapshot, &old, &expected, user_resource);
                    checks += 1;
                }
            }
        }
    }
    println!(
        "WINDOWS_COMPRESSED_CONVERSION_FAULTS: {checks} selected persistence checks; 16 callback scenarios; no failure acknowledged or retried"
    );
}

fn verify_compressed_constructor_recovery(bytes: &[u8], value: &[u8], finder: &[u8; 32]) {
    let mut disk = MemoryBackend::from_bytes(bytes.to_vec());
    let fs = HfsPlus::open(&mut disk).unwrap();
    let body = fs.catalog_record("/compressed").unwrap();
    let cnid = volume::be32(&body, 8);
    let compressed = body[41] & 32 != 0;
    let new = fs
        .inline_attribute(&mut disk, cnid, "com.example.new")
        .unwrap();
    if compressed {
        assert!(new.is_none());
    } else {
        assert_eq!(new.unwrap(), value);
        assert_eq!(
            fstool::fs::hfs_plus::attributes::public_finder_info(body[48..80].try_into().unwrap()),
            fstool::fs::hfs_plus::attributes::public_finder_info(finder)
        );
        assert!(body[64..72].iter().chain(&body[76..80]).all(|b| *b == 0));
    }
}

#[test]
fn compressed_constructor_refusals_write_nothing_and_leave_the_adapter_usable() {
    use hfs_bridge::ea::Change;
    let (disk, _) = fixture(8, true, false, false);
    let baseline = disk.into_bytes();
    let cases = [
        vec![Change {
            name: "com.apple.decmpfs".into(),
            value: None,
        }],
        vec![Change {
            name: "com.apple.FinderInfo".into(),
            value: Some(vec![0; 31]),
        }],
        vec![
            Change {
                name: "com.example.note".into(),
                value: Some(vec![1]),
            },
            Change {
                name: "com.example.note".into(),
                value: None,
            },
        ],
        vec![Change {
            name: "com.apple.system.private".into(),
            value: Some(vec![1]),
        }],
        vec![Change {
            name: "com.apple.ResourceFork".into(),
            value: Some(vec![1]),
        }],
        vec![Change {
            name: "".into(),
            value: Some(vec![1]),
        }],
        vec![Change {
            name: "com.example.new".into(),
            value: Some(vec![0x46; 70019]),
        }],
    ];
    for (index, changes) in cases.iter().enumerate() {
        let disk = faults::Disk::new(&baseline);
        let observer = disk.clone();
        let mut adapter = Adapter::from_device(disk).unwrap();
        let request = OpenRequest {
            access: Access::ALL,
            ..Default::default()
        };
        let handle = adapter.open("\\compressed", request).unwrap();
        let allocation = if index == cases.len() - 1 {
            adapter.volume_info().unwrap().free_bytes
        } else {
            8192
        };
        observer.arm(None);
        assert!(
            adapter
                .overwrite_with_ea(handle, 0x20, true, allocation, changes)
                .is_err()
        );
        assert!(
            adapter.failure().is_none(),
            "preflight refusal poisoned a healthy adapter"
        );
        assert_eq!(observer.0.lock().unwrap().calls, 0);
        assert_eq!(observer.snapshot(1, 0), baseline);
        let other = adapter.open("\\ordinary", request).unwrap();
        adapter
            .write(other, 0, b"still usable", false, false)
            .unwrap();
        adapter.close(other).unwrap();
        adapter.close(handle).unwrap();
        adapter.shutdown().unwrap();
    }
}

#[test]
fn unsupported_codec_does_not_hide_ordinary_siblings_or_expose_storage() {
    for kind in [99u32, 100, 999] {
        let (disk, plain) = fixture(12, true, false, false);
        let mut bytes = disk.into_bytes();
        let base = volume::be32(&bytes, 1392) as usize * 4096;
        let length = volume::be64(&bytes, 1376) as usize;
        let positions = bytes[base..base + length]
            .windows(4)
            .enumerate()
            .filter_map(|(at, value)| (value == b"fpmc").then_some(base + at))
            .collect::<Vec<_>>();
        assert_eq!(positions.len(), 1);
        bytes[positions[0] + 4..positions[0] + 8].copy_from_slice(&kind.to_le_bytes());
        let mut adapter = Adapter::from_device(MemoryBackend::from_bytes(bytes)).unwrap();
        let request = OpenRequest {
            access: Access::READ,
            ..Default::default()
        };
        let root = adapter.open("\\", request).unwrap();
        let list = adapter.read_directory(root).unwrap();
        assert!(list.iter().any(|entry| entry.name == "ordinary"));
        assert_eq!(
            list.iter()
                .find(|entry| entry.name == "compressed")
                .unwrap()
                .info
                .size,
            plain.len() as u64
        );
        let handle = adapter.open("\\compressed", request).unwrap();
        assert_eq!(
            adapter.read(handle, 0, &mut [0; 20]).unwrap_err().status,
            Status::Unsupported
        );
        assert_eq!(
            adapter
                .open(
                    "\\compressed",
                    OpenRequest {
                        access: Access::ALL,
                        ..Default::default()
                    }
                )
                .unwrap_err()
                .status,
            Status::AccessDenied
        );
        let mut metadata_access = Access::READ;
        metadata_access.metadata = true;
        assert_eq!(
            adapter
                .open(
                    "\\compressed",
                    OpenRequest {
                        access: metadata_access,
                        ..Default::default()
                    }
                )
                .unwrap_err()
                .status,
            Status::AccessDenied
        );
        let mut rename_access = Access::READ;
        rename_access.delete = true;
        assert_eq!(
            adapter
                .open(
                    "\\compressed",
                    OpenRequest {
                        access: rename_access,
                        ..Default::default()
                    }
                )
                .unwrap_err()
                .status,
            Status::AccessDenied
        );
        if kind != 13 {
            assert!(
                !adapter
                    .streams(handle)
                    .unwrap()
                    .iter()
                    .any(|(name, _)| *name == "AFP_Resource")
            );
        }
        let ordinary = adapter.open("\\ordinary", request).unwrap();
        let mut content = [0; 20];
        let count = adapter.read(ordinary, 0, &mut content).unwrap();
        assert_eq!(&content[..count], b"untouched");
        assert!(adapter.failure().is_none());
        adapter.close(ordinary).unwrap();
        adapter.close(handle).unwrap();
        adapter.close(root).unwrap();
        adapter.shutdown().unwrap();
    }
}

#[test]
fn windows_compressed_basic_metadata_and_move_preserve_encoded_storage() {
    use hfs_bridge::windows::BasicTimes;
    let time = (11_644_473_600u64 + 1_700_000_100) * 10_000_000;
    for kind in [1, 3, 4, 7, 8, 9, 10, 11, 12, 13, 14] {
        for journaled in [false, true] {
            for sensitive in [false, true] {
                let user_resource = matches!(kind, 1 | 3 | 7 | 9 | 11 | 13);
                let (mut disk, plain) = fixture(kind, journaled, sensitive, user_resource);
                let mut fs = HfsPlus::open(&mut disk).unwrap();
                fs.create_dir(&mut disk, "/Destination", 0o755, 501, 20, 0)
                    .unwrap();
                fs.flush(&mut disk).unwrap();
                let before = fs.catalog_record("/compressed").unwrap();
                let cnid = volume::be32(&before, 8);
                let compression = fs
                    .inline_attribute(&mut disk, cnid, "com.apple.decmpfs")
                    .unwrap()
                    .unwrap();
                let bytes = disk.as_slice().to_vec();
                let mut adapter = Adapter::from_device(disk).unwrap();
                let mut access = Access::READ;
                access.metadata = true;
                access.delete = true;
                let handle = adapter
                    .open(
                        "\\compressed",
                        OpenRequest {
                            access,
                            ..Default::default()
                        },
                    )
                    .unwrap();
                let reader = adapter
                    .open(
                        "\\compressed",
                        OpenRequest {
                            access: Access::READ,
                            ..Default::default()
                        },
                    )
                    .unwrap();
                adapter
                    .set_basic_info(
                        handle,
                        BasicTimes {
                            creation: Some(time),
                            access: Some(time),
                            write: Some(time),
                            change: Some(time),
                        },
                        Some(0x22),
                    )
                    .unwrap();
                adapter
                    .rename(handle, "\\Destination\\Renamed Ω.bin")
                    .unwrap();
                assert_eq!(adapter.file_info(reader).unwrap().cnid, cnid);
                let mut actual = vec![0; plain.len() + 1];
                let count = adapter.read(reader, 0, &mut actual).unwrap();
                assert_eq!(&actual[..count], plain);
                adapter.can_delete(handle).unwrap();
                adapter.close(reader).unwrap();
                adapter.close(handle).unwrap();
                let mut disk = adapter.shutdown().unwrap();
                let fs = HfsPlus::open(&mut disk).unwrap();
                assert!(fs.catalog_record("/compressed").is_err());
                let after = fs.catalog_record("/Destination/Renamed Ω.bin").unwrap();
                for range in [8..12, 32..56, 60..248] {
                    assert_eq!(&after[range.clone()], &before[range]);
                }
                assert_ne!(after[41] & 32, 0);
                for offset in [12, 16, 24] {
                    assert_eq!(volume::be32(&after, offset), 3_782_844_900);
                }
                assert_ne!(volume::be16(&after, 56) & 0x4000, 0);
                assert_eq!(
                    fs.inline_attribute(&mut disk, cnid, "com.apple.decmpfs")
                        .unwrap()
                        .unwrap(),
                    compression
                );
                assert_eq!(
                    fs.inline_attribute(&mut disk, cnid, "com.example.note")
                        .unwrap()
                        .unwrap(),
                    b"keep"
                );
                // Full allocated fork ranges, including compressed resource storage,
                // remain byte-identical. These fixtures use inline extents only.
                for fork in [88, 168] {
                    for i in 0..8 {
                        let start = volume::be32(&before, fork + 16 + i * 8) as usize * 4096;
                        let length = volume::be32(&before, fork + 20 + i * 8) as usize * 4096;
                        assert_eq!(
                            &disk.as_slice()[start..start + length],
                            &bytes[start..start + length]
                        );
                    }
                }
                if kind == 8 && journaled && !sensitive {
                    retain(disk.as_slice(), "compressed-metadata-move-type8.img");
                }
            }
        }
    }
}

#[test]
fn windows_compressed_metadata_refusals_leave_no_writes_and_keep_adapter_healthy() {
    use hfs_bridge::windows::BasicTimes;
    let (disk, _) = fixture(8, true, false, false);
    let bytes = disk.into_bytes();
    let device = faults::Disk::new(&bytes);
    let observer = device.clone();
    let mut adapter = Adapter::from_device(device).unwrap();
    let mut access = Access::READ;
    access.metadata = true;
    access.delete = true;
    let handle = adapter
        .open(
            "\\compressed",
            OpenRequest {
                access,
                ..Default::default()
            },
        )
        .unwrap();
    observer.arm(None);
    assert_eq!(
        adapter
            .set_basic_info(
                handle,
                BasicTimes {
                    creation: Some(u64::MAX),
                    ..Default::default()
                },
                None
            )
            .unwrap_err()
            .status,
        Status::InvalidParameter
    );
    assert_eq!(
        adapter
            .set_basic_info(handle, BasicTimes::default(), Some(0x800))
            .unwrap_err()
            .status,
        Status::Unsupported
    );
    assert_eq!(
        adapter.rename(handle, "\\ordinary").unwrap_err().status,
        Status::Collision
    );
    adapter.can_delete(handle).unwrap();
    let ordinary = adapter
        .open(
            "\\ordinary",
            OpenRequest {
                access: Access::ALL,
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(
        adapter
            .rename_with_replace(ordinary, "\\compressed", true)
            .unwrap_err()
            .status,
        Status::SharingViolation
    );
    let mut ea_access = Access::READ;
    ea_access.write_ea = true;
    assert_eq!(
        adapter
            .open(
                "\\compressed",
                OpenRequest {
                    access: ea_access,
                    ..Default::default()
                }
            )
            .unwrap_err()
            .status,
        Status::AccessDenied
    );
    assert!(adapter.failure().is_none());
    assert_eq!(observer.0.lock().unwrap().calls, 0);
    assert_eq!(observer.snapshot(1, 0), bytes);
    adapter.close(ordinary).unwrap();
    adapter.close(handle).unwrap();
    adapter.shutdown().unwrap();
}

#[test]
fn windows_compressed_metadata_publication_failures_preserve_complete_records_and_payloads() {
    use hfs_bridge::windows::BasicTimes;
    let time = (11_644_473_600u64 + 1_700_000_100) * 10_000_000;
    let mut checks = 0;
    for kind in [3, 8] {
        let (mut disk, plain) = fixture(kind, true, false, kind == 3);
        let fs = HfsPlus::open(&mut disk).unwrap();
        let before = fs.catalog_record("/compressed").unwrap();
        let cnid = volume::be32(&before, 8);
        let compression = fs
            .inline_attribute(&mut disk, cnid, "com.apple.decmpfs")
            .unwrap()
            .unwrap();
        let baseline = disk.into_bytes();
        let jib = volume::be32(&baseline, 1036) as usize * 4096;
        let journal = volume::be64(&baseline, jib + 36) as usize;
        for rename in [false, true] {
            let perform = |adapter: &mut Adapter<faults::Disk>, handle| {
                if rename {
                    adapter.rename(handle, "\\renamed")
                } else {
                    adapter.set_basic_info(
                        handle,
                        BasicTimes {
                            creation: Some(time),
                            access: Some(time),
                            write: Some(time),
                            change: Some(time),
                        },
                        Some(0x22),
                    )
                }
            };
            let verify = |bytes: Vec<u8>| {
                let mut disk = MemoryBackend::from_bytes(bytes);
                let fs = HfsPlus::open(&mut disk).unwrap();
                let old = fs.catalog_record("/compressed");
                let new = fs.catalog_record("/renamed");
                assert!(old.is_ok() ^ new.is_ok());
                let path = if old.is_ok() {
                    "/compressed"
                } else {
                    "/renamed"
                };
                let body = fs.catalog_record(path).unwrap();
                assert_eq!(&body[32..56], &before[32..56]);
                assert_eq!(&body[60..248], &before[60..248]);
                assert_eq!(
                    fs.inline_attribute(&mut disk, cnid, "com.apple.decmpfs")
                        .unwrap()
                        .unwrap(),
                    compression
                );
                let mut actual = Vec::new();
                fs.open_file_reader(&mut disk, path)
                    .unwrap()
                    .read_to_end(&mut actual)
                    .unwrap();
                assert_eq!(actual, plain);
                if !rename {
                    let dates = [12, 16, 20, 24].map(|offset| volume::be32(&body, offset));
                    let original = [12, 16, 20, 24].map(|offset| volume::be32(&before, offset));
                    assert!(dates == original || dates == [3_782_844_900; 4]);
                    assert_eq!(volume::be16(&body, 56) & 0x4000 != 0, dates != original);
                }
            };
            let device = faults::Disk::new(&baseline);
            let observer = device.clone();
            let mut adapter = Adapter::from_device(device).unwrap();
            let request = OpenRequest {
                access: Access::ALL,
                ..Default::default()
            };
            let handle = adapter.open("\\compressed", request).unwrap();
            observer.arm(None);
            perform(&mut adapter, handle).unwrap();
            let calls = observer.0.lock().unwrap().calls;
            verify(observer.0.lock().unwrap().durable.clone());
            drop(adapter);
            for stop in 0..calls {
                let device = faults::Disk::new(&baseline);
                let observer = device.clone();
                let mut adapter = Adapter::from_device(device).unwrap();
                let handle = adapter.open("\\compressed", request).unwrap();
                observer.arm(Some(stop));
                assert!(perform(&mut adapter, handle).is_err());
                assert!(adapter.failure().is_some());
                let failed_calls = observer.0.lock().unwrap().calls;
                assert_eq!(
                    perform(&mut adapter, handle).unwrap_err().status,
                    Status::FailedVolume
                );
                assert!(adapter.close(handle).is_err());
                assert!(adapter.shutdown().is_err());
                assert_eq!(observer.0.lock().unwrap().calls, failed_calls);
                for policy in 0..6 {
                    verify(observer.snapshot(policy, journal));
                    checks += 1;
                }
            }
        }
    }
    println!(
        "COMPRESSED_METADATA_FAULTS: {checks} selected persistence checks;4 scenarios; no failure acknowledged or retried"
    );
}

#[test]
fn compressed_deletion_replacement_and_orphan_recovery_reclaim_encoded_storage() {
    let mut cases = 0;
    for kind in [1, 3, 4, 7, 8, 9, 10, 11, 12, 13, 14] {
        for journaled in [false, true] {
            for sensitive in [false, true] {
                for operation in 0..3 {
                    let (mut disk, plain) = fixture(
                        kind,
                        journaled,
                        sensitive,
                        matches!(kind, 1 | 3 | 7 | 9 | 11 | 13),
                    );
                    let mut fs = HfsPlus::open(&mut disk).unwrap();
                    fs.create_file(
                        &mut disk,
                        "/replacement",
                        &mut &b"new contents"[..],
                        12,
                        0o644,
                        501,
                        20,
                        0,
                    )
                    .unwrap();
                    fs.flush(&mut disk).unwrap();
                    let original = fs.catalog_record("/compressed").unwrap();
                    let cnid = volume::be32(&original, 8);
                    let released = u64::from(volume::be32(&original, 100))
                        + u64::from(volume::be32(&original, 180));
                    let replacement = volume::be32(&fs.catalog_record("/replacement").unwrap(), 8);
                    let baseline = disk.into_bytes();
                    let free = volume::be32(&baseline, 1072);
                    let device = faults::Disk::new(&baseline);
                    let observer = device.clone();
                    let mut adapter = Adapter::from_device(device).unwrap();
                    let handle = adapter
                        .open(
                            "\\compressed",
                            OpenRequest {
                                access: Access::ALL,
                                ..Default::default()
                            },
                        )
                        .unwrap();
                    let reader = adapter
                        .open(
                            "\\compressed",
                            OpenRequest {
                                access: Access::READ,
                                ..Default::default()
                            },
                        )
                        .unwrap();
                    if operation == 2 {
                        adapter.close(reader).unwrap();
                        adapter.close(handle).unwrap();
                        let source = adapter
                            .open(
                                "\\replacement",
                                OpenRequest {
                                    access: Access::ALL,
                                    ..Default::default()
                                },
                            )
                            .unwrap();
                        adapter
                            .rename_with_replace(source, "\\compressed", true)
                            .unwrap();
                        adapter.close(source).unwrap();
                        adapter.shutdown().unwrap();
                    } else {
                        adapter.can_delete(handle).unwrap();
                        adapter.cleanup(handle, true).unwrap();
                        assert_eq!(
                            adapter
                                .open("\\compressed", OpenRequest::default())
                                .unwrap_err()
                                .status,
                            Status::DeletePending
                        );
                        let mut bytes = vec![0; plain.len() + 1];
                        let count = adapter.read(reader, 0, &mut bytes).unwrap();
                        assert_eq!(&bytes[..count], plain);
                        if operation == 0 {
                            adapter.close(handle).unwrap();
                            assert_eq!(adapter.file_info(reader).unwrap().cnid, cnid);
                            adapter.close(reader).unwrap();
                            adapter.shutdown().unwrap();
                        } else {
                            // Simulate process termination after durable cleanup, with
                            // both contexts still open; reopening reclaims the orphan.
                            drop(adapter);
                            Adapter::from_device(observer.clone())
                                .unwrap()
                                .shutdown()
                                .unwrap();
                        }
                    }
                    let bytes = observer.0.lock().unwrap().durable.clone();
                    catalog_wire::audit(&bytes);
                    let attributes = attribute_wire::audit_initialized(&bytes);
                    assert!(
                        attributes
                            .iter()
                            .all(|record| volume::be32(record, 4) != cnid)
                    );
                    assert_eq!(
                        u64::from(volume::be32(&bytes, 1072)),
                        u64::from(free) + released
                    );
                    let mut disk = MemoryBackend::from_bytes(bytes);
                    let fs = HfsPlus::open(&mut disk).unwrap();
                    assert!(fs.catalog_record("/.hfs-bridge-orphans-v1").is_err());
                    let mut untouched = Vec::new();
                    fs.open_file_reader(&mut disk, "/ordinary")
                        .unwrap()
                        .read_to_end(&mut untouched)
                        .unwrap();
                    assert_eq!(untouched, b"untouched");
                    if operation == 2 {
                        assert!(fs.catalog_record("/replacement").is_err());
                        let body = fs.catalog_record("/compressed").unwrap();
                        assert_eq!(volume::be32(&body, 8), replacement);
                        assert_eq!(body[41] & 32, 0);
                        let mut actual = Vec::new();
                        fs.open_file_reader(&mut disk, "/compressed")
                            .unwrap()
                            .read_to_end(&mut actual)
                            .unwrap();
                        assert_eq!(actual, b"new contents");
                    } else {
                        assert!(fs.catalog_record("/compressed").is_err());
                    }
                    cases += 1;
                }
            }
        }
    }
    println!("COMPRESSED_DELETION_CASES: {cases} codec/volume/lifetime combinations");
}

#[test]
fn compressed_deletion_failures_recover_without_acknowledgement_or_retry() {
    let request = OpenRequest {
        access: Access::ALL,
        ..Default::default()
    };
    let mut checks = 0;
    for kind in [3, 8] {
        let (mut disk, plain) = fixture(kind, true, false, kind == 3);
        let mut fs = HfsPlus::open(&mut disk).unwrap();
        fs.create_file(
            &mut disk,
            "/replacement",
            &mut &b"new contents"[..],
            12,
            0o644,
            501,
            20,
            0,
        )
        .unwrap();
        fs.flush(&mut disk).unwrap();
        let original = fs.catalog_record("/compressed").unwrap();
        let cnid = volume::be32(&original, 8);
        let released = volume::be32(&original, 100) + volume::be32(&original, 180);
        let replacement = volume::be32(&fs.catalog_record("/replacement").unwrap(), 8);
        let baseline = disk.into_bytes();
        let free = volume::be32(&baseline, 1072);
        let jib = volume::be32(&baseline, 1036) as usize * 4096;
        let journal = volume::be64(&baseline, jib + 36) as usize;
        for operation in 0..4 {
            let verify = |bytes: Vec<u8>| {
                let mut disk = MemoryBackend::from_bytes(bytes);
                // Test-only replay precedes normal production clean-open checks.
                drop(HfsPlus::open(&mut disk).unwrap());
                let mut disk = Adapter::from_device(disk).unwrap().shutdown().unwrap();
                let fs = HfsPlus::open(&mut disk).unwrap();
                assert!(fs.catalog_record("/.hfs-bridge-orphans-v1").is_err());
                let current = fs.catalog_record("/compressed").ok();
                let old = current
                    .as_ref()
                    .is_some_and(|body| volume::be32(body, 8) == cnid);
                if operation == 1 || operation == 3 {
                    assert!(!old);
                }
                if let Some(body) = &current {
                    let mut payload = Vec::new();
                    fs.open_file_reader(&mut disk, "/compressed")
                        .unwrap()
                        .read_to_end(&mut payload)
                        .unwrap();
                    if old {
                        assert_eq!(body, &original);
                        assert_eq!(payload, plain);
                    } else {
                        assert_eq!(operation, 2);
                        assert_eq!(volume::be32(body, 8), replacement);
                        assert_eq!(body[41] & 32, 0);
                        assert_eq!(payload, b"new contents");
                    }
                } else {
                    assert_ne!(operation, 2);
                }
                assert_eq!(
                    fs.catalog_record("/replacement").is_ok(),
                    operation != 2 || old
                );
                let mut untouched = Vec::new();
                fs.open_file_reader(&mut disk, "/ordinary")
                    .unwrap()
                    .read_to_end(&mut untouched)
                    .unwrap();
                assert_eq!(untouched, b"untouched");
                let bytes = disk.as_slice();
                assert_eq!(
                    volume::be32(bytes, 1072),
                    free + if old { 0 } else { released }
                );
                catalog_wire::audit(bytes);
                let attrs = attribute_wire::audit_initialized(bytes);
                assert_eq!(
                    attrs
                        .iter()
                        .filter(|record| volume::be32(record, 4) == cnid)
                        .count(),
                    if old { 2 } else { 0 }
                );
            };
            let prepare = || {
                let device = faults::Disk::new(&baseline);
                let observer = device.clone();
                let mut adapter = Adapter::from_device(device).unwrap();
                let path = if operation == 2 {
                    "\\replacement"
                } else {
                    "\\compressed"
                };
                let handle = adapter.open(path, request).unwrap();
                if operation == 1 || operation == 3 {
                    adapter.cleanup(handle, true).unwrap();
                }
                (adapter, observer, handle)
            };
            let perform = |adapter: &mut Adapter<faults::Disk>, handle| match operation {
                0 => adapter.cleanup(handle, true),
                1 => adapter.close(handle),
                2 => adapter.rename_with_replace(handle, "\\compressed", true),
                _ => unreachable!(),
            };
            let (mut adapter, observer, handle) = prepare();
            let pending = observer.0.lock().unwrap().durable.clone();
            observer.arm(None);
            if operation == 3 {
                drop(adapter);
                drop(Adapter::from_device(observer.clone()).unwrap());
            } else {
                perform(&mut adapter, handle).unwrap();
                drop(adapter);
            }
            let calls = observer.0.lock().unwrap().calls;
            verify(observer.0.lock().unwrap().durable.clone());
            for stop in 0..calls {
                let observer = if operation == 3 {
                    let observer = faults::Disk::new(&pending);
                    observer.arm(Some(stop));
                    assert!(Adapter::from_device(observer.clone()).is_err());
                    observer
                } else {
                    let (mut adapter, observer, handle) = prepare();
                    observer.arm(Some(stop));
                    assert!(perform(&mut adapter, handle).is_err());
                    assert!(adapter.failure().is_some());
                    let after = observer.0.lock().unwrap().calls;
                    assert_eq!(
                        adapter.flush(None).unwrap_err().status,
                        Status::FailedVolume
                    );
                    assert!(adapter.shutdown().is_err());
                    assert_eq!(observer.0.lock().unwrap().calls, after);
                    observer
                };
                for policy in 0..6 {
                    verify(observer.snapshot(policy, journal));
                    checks += 1;
                }
            }
        }
    }
    println!(
        "COMPRESSED_DELETION_FAULTS: {checks} selected persistence checks;8 scenarios; no failure acknowledged or retried"
    );
}

#[test]
fn compressed_reclamation_refuses_shared_storage_before_any_write() {
    for kind in [3, 8] {
        let (mut disk, _) = fixture(kind, true, false, kind == 3);
        let fs = HfsPlus::open(&mut disk).unwrap();
        let target = fs.catalog_record("/compressed").unwrap();
        let other = fs.catalog_record("/ordinary").unwrap();
        let mut bytes = disk.into_bytes();
        let start = volume::be32(&bytes, 1312) as usize * 4096;
        let end = start + volume::be64(&bytes, 1296) as usize;
        let matches = bytes[start..end]
            .windows(target.len())
            .enumerate()
            .filter_map(|(offset, body)| (body == target).then_some(start + offset))
            .collect::<Vec<_>>();
        assert_eq!(matches.len(), 1);
        let offset = matches[0];
        bytes[offset + 168..offset + 248].copy_from_slice(&other[88..168]);
        let device = faults::Disk::new(&bytes);
        let observer = device.clone();
        let mut adapter = Adapter::from_device(device).unwrap();
        let request = OpenRequest {
            access: Access::ALL,
            ..Default::default()
        };
        let target = adapter.open("\\compressed", request).unwrap();
        observer.arm(None);
        assert_eq!(
            adapter.can_delete(target).unwrap_err().status,
            Status::IoError
        );
        assert_eq!(
            adapter.cleanup(target, true).unwrap_err().status,
            Status::IoError
        );
        adapter.close(target).unwrap();
        let other = adapter.open("\\ordinary", request).unwrap();
        assert_eq!(
            adapter
                .rename_with_replace(other, "\\compressed", true)
                .unwrap_err()
                .status,
            Status::IoError
        );
        assert!(adapter.failure().is_none());
        assert_eq!(observer.0.lock().unwrap().calls, 0);
        assert_eq!(observer.snapshot(1, 0), bytes);
        adapter.close(other).unwrap();
    }
}

const RELATED_MARKER: &str = "org.hfsbridge.test.conversion";
const RELATED_VALUE: &[u8] = b"one conversion publication";

#[test]
fn compressed_patch_and_resize_compose_catalog_fields_and_related_records() {
    use fstool::fs::hfs_plus::{CatalogUpdate, PublicationMetadata};
    for kind in [3, 8, 13, 14] {
        for resize in [false, true] {
            let (mut d, old) = fixture(kind, true, false, matches!(kind, 3 | 13));
            let before = d.as_slice().to_vec();
            let mut fs = HfsPlus::open(&mut d).unwrap();
            let cnid = volume::be32(&fs.catalog_record("/compressed").unwrap(), 8);
            let apply = |fs: &mut HfsPlus, d: &mut dyn fstool::block::BlockDevice, bad: bool| {
                let updates = [CatalogUpdate {
                    cnid,
                    times: [
                        Some(3_800_000_000),
                        Some(3_800_000_001),
                        Some(3_800_000_002),
                        Some(3_800_000_003),
                    ],
                    attributes: Some(if bad { 0x8000 } else { 0x23 }),
                }];
                let metadata = PublicationMetadata {
                    related: &[(2, RELATED_MARKER, Some(RELATED_VALUE))],
                    catalog: &updates,
                    ..Default::default()
                };
                if resize {
                    fs.resize_compressed_with_publication(
                        d,
                        std::path::Path::new("/compressed"),
                        13,
                        metadata,
                    )
                } else {
                    fs.patch_compressed_with_publication(
                        d,
                        std::path::Path::new("/compressed"),
                        37,
                        b"catalog publication",
                        metadata,
                    )
                }
            };
            assert!(apply(&mut fs, &mut d, true).is_err());
            fs.flush(&mut d).unwrap();
            assert!(d.as_slice() == before);
            apply(&mut fs, &mut d, false).unwrap();
            let body = fs.catalog_record("/compressed").unwrap();
            for (offset, value) in [
                (12, 3_800_000_000),
                (24, 3_800_000_001),
                (16, 3_800_000_002),
                (20, 3_800_000_003),
            ] {
                assert_eq!(volume::be32(&body, offset), value);
            }
            assert_eq!(volume::be16(&body, 2) & 1, 1);
            assert_eq!(volume::be16(&body, 56) & 0x4000, 0x4000);
            assert_eq!(
                fs.inline_attribute(&mut d, 2, RELATED_MARKER).unwrap(),
                Some(RELATED_VALUE.to_vec())
            );
            assert_eq!(
                volume::be32(d.as_slice(), 1092),
                volume::be32(&before, 1092) + 1
            );
            let mut expected = old.clone();
            if resize {
                expected.resize(13, 0);
            } else {
                expected.resize(expected.len().max(56), 0);
                expected[37..56].copy_from_slice(b"catalog publication");
            }
            let mut actual = Vec::new();
            fs.open_file_reader(&mut d, "/compressed")
                .unwrap()
                .read_to_end(&mut actual)
                .unwrap();
            assert_eq!(actual, expected);
            retain(d.as_slice(), &format!("publication-{kind}-{resize}.img"));
            retain(
                &expected,
                &format!("publication-{kind}-{resize}.expected.bin"),
            );
        }
    }
}
fn related_conversion(
    fs: &mut HfsPlus,
    d: &mut dyn fstool::block::BlockDevice,
) -> fstool::Result<()> {
    let cnid = volume::be32(&fs.catalog_record("/compressed")?, 8);
    let other = volume::be32(&fs.catalog_record("/ordinary")?, 8);
    fs.replace_compressed_with_related_attributes(
        d,
        std::path::Path::new("/compressed"),
        &mut vec![0x54; 9001].as_slice(),
        9001,
        16384,
        &[("com.example.large", Some(&vec![0x55; 7003]))],
        &[
            (2, RELATED_MARKER, Some(RELATED_VALUE)),
            (cnid, RELATED_MARKER, Some(b"entry precision")),
            (other, RELATED_MARKER, Some(b"other precision")),
        ],
    )
}
fn retain_related(bytes: &[u8], name: &str) {
    if let Some(dir) = std::env::var_os("HFS_RELATED_ARTIFACT_DIR") {
        use std::io::Write;
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
struct RelatedConversionState {
    header: Vec<u8>,
    bodies: Vec<Vec<u8>>,
    data: Vec<Vec<u8>>,
    values: Vec<Option<Vec<u8>>>,
}
fn related_observe(d: &mut dyn fstool::block::BlockDevice) -> RelatedConversionState {
    let fs = HfsPlus::open(d).unwrap();
    let mut header = [0; 1536];
    d.read_at(0, &mut header).unwrap();
    let mut state = RelatedConversionState {
        header: header[1064..1096].to_vec(),
        bodies: Vec::new(),
        data: Vec::new(),
        values: vec![fs.inline_attribute(d, 2, RELATED_MARKER).unwrap()],
    };
    for path in ["/compressed", "/ordinary"] {
        let body = fs.catalog_record(path).unwrap();
        let cnid = volume::be32(&body, 8);
        let mut data = Vec::new();
        fs.open_file_reader(d, path)
            .unwrap()
            .read_to_end(&mut data)
            .unwrap();
        state.data.push(data);
        let mut resource = Vec::new();
        if volume::be64(&body, 168) != 0
            && !fs
                .compressed_info(d, cnid)
                .unwrap()
                .is_some_and(|(_, hidden)| hidden)
        {
            fs.open_resource_fork_reader(d, path)
                .unwrap()
                .read_to_end(&mut resource)
                .unwrap();
        }
        state.data.push(resource);
        for name in [
            RELATED_MARKER,
            "com.example.note",
            "com.example.large",
            "com.apple.decmpfs",
        ] {
            state
                .values
                .push(fs.inline_attribute(d, cnid, name).unwrap());
        }
        state.bodies.push(body);
    }
    state.bodies.push(fs.catalog_record_cnid(2).unwrap());
    state
}
#[test]
fn related_compression_records_publish_with_data_and_resource_retirement() {
    for kind in [3, 8] {
        for journaled in [false, true] {
            for sensitive in [false, true] {
                let (mut d, _) = fixture(kind, journaled, sensitive, kind == 3);
                let before = d.as_slice().to_vec();
                let mut fs = HfsPlus::open(&mut d).unwrap();
                let cnid = volume::be32(&fs.catalog_record("/compressed").unwrap(), 8);
                related_conversion(&mut fs, &mut d).unwrap();
                let result = related_observe(&mut d);
                assert_eq!(result.data[0], vec![0x54; 9001]);
                assert_eq!(
                    result.data[1],
                    if kind == 3 {
                        b"user resource".to_vec()
                    } else {
                        vec![]
                    }
                );
                assert_eq!(result.data[2], b"untouched");
                assert_eq!(result.values[0], Some(RELATED_VALUE.to_vec()));
                assert_eq!(result.values[1], Some(b"entry precision".to_vec()));
                assert_eq!(result.values[2], Some(b"keep".to_vec()));
                assert_eq!(result.values[3], Some(vec![0x55; 7003]));
                assert_eq!(result.values[4], None);
                assert_eq!(result.values[5], Some(b"other precision".to_vec()));
                let body = fs.catalog_record_cnid(cnid).unwrap();
                assert_eq!(body[41] & 0x20, 0);
                assert_eq!(volume::be32(&body, 100), 4);
                let old_fs = HfsPlus::open(&mut MemoryBackend::from_bytes(before.clone())).unwrap();
                let old_body = old_fs.catalog_record_cnid(cnid).unwrap();
                assert_eq!(&body[12..40], &old_body[12..40]);
                let retired = if kind == 3 {
                    0
                } else {
                    volume::be32(&old_body, 180)
                };
                assert_eq!(
                    volume::be32(d.as_slice(), 1072),
                    volume::be32(&before, 1072) + retired - 6
                );
                retain_related(
                    d.as_slice(),
                    &format!("conversion-{kind}-{journaled}-{sensitive}.img"),
                );
                let after = d.as_slice().to_vec();
                fs.flush(&mut d).unwrap();
                assert!(d.as_slice() == after);
            }
        }
    }
}
#[test]
fn related_compression_preflight_refuses_without_consuming_input_or_mutating() {
    for kind in [3, 8] {
        let (d, _) = fixture(kind, true, false, kind == 3);
        let before = d.into_bytes();
        for variant in 0..9 {
            let mut d = MemoryBackend::from_bytes(before.clone());
            let mut fs = HfsPlus::open(&mut d).unwrap();
            let cnid = volume::be32(&fs.catalog_record("/compressed").unwrap(), 8);
            let other = volume::be32(&fs.catalog_record("/ordinary").unwrap(), 8);
            let mut related = vec![(2, RELATED_MARKER, Some(RELATED_VALUE))];
            let big = vec![0; 3803];
            match variant {
                0 => related.push((999999, RELATED_MARKER, Some(RELATED_VALUE))),
                1 => related.push((cnid, "com.example.large", None)),
                2 => related.push((cnid, "com.apple.decmpfs", None)),
                3 => related.push((cnid, "com.apple.FinderInfo", None)),
                4 => related.push((other, "com.apple.system.Security", None)),
                5 => related.push((other, RELATED_MARKER, Some(&big))),
                6 => related.extend(std::iter::repeat_n((2, "extra", None), 16)),
                7 | 8 => {}
                _ => unreachable!(),
            }
            // Each data size alone fits; the large attribute makes their sum
            // exceed free storage. No conversion input may be read on refusal.
            let free = volume::be32(&before, 1072) as u64 * 4096;
            let size = if variant == 7 { free } else { 1 };
            let allocation = if variant == 8 { 1 } else { 0 };
            let value = vec![0x55; 7003];
            let attrs = [("com.example.large", Some(value.as_slice()))];
            assert!(
                fs.validate_compressed_replacement_with_related_attributes(
                    &mut d, cnid, size, allocation, &attrs, &related
                )
                .is_err()
            );
            let mut input = std::io::Cursor::new(vec![1]);
            assert!(
                fs.replace_compressed_with_related_attributes(
                    &mut d,
                    std::path::Path::new("/compressed"),
                    &mut input,
                    size,
                    allocation,
                    &attrs,
                    &related
                )
                .is_err()
            );
            assert_eq!(input.position(), 0);
            fs.flush(&mut d).unwrap();
            assert!(d.as_slice() == before, "{kind}/{variant}");
            related_conversion(&mut fs, &mut d).unwrap();
        }
    }
}
fn related_attempt(bytes: &[u8], failure: Option<usize>) -> (bool, faults::Disk) {
    let mut d = faults::Disk::new(bytes);
    let mut fs = HfsPlus::open(&mut d).unwrap();
    d.arm(failure);
    let pass = related_conversion(&mut fs, &mut d).is_ok();
    if !pass {
        let count = d.0.lock().unwrap().calls;
        assert!(fs.flush(&mut d).is_err());
        assert_eq!(d.0.lock().unwrap().calls, count);
    }
    (pass, d)
}
#[test]
fn related_compression_recovery_keeps_root_records_and_payloads_in_one_commit() {
    let mut commits = 0;
    let mut replays = 0;
    for kind in [3, 8] {
        for sensitive in [false, true] {
            let (d, _) = fixture(kind, true, sensitive, kind == 3);
            let before = d.into_bytes();
            let info = volume::be32(&before, 1036) as usize * 4096;
            let journal = volume::be64(&before, info + 36) as usize;
            let old = related_observe(&mut MemoryBackend::from_bytes(before.clone()));
            let (pass, complete) = related_attempt(&before, None);
            assert!(pass);
            let new = related_observe(&mut MemoryBackend::from_bytes(
                complete.0.lock().unwrap().durable.clone(),
            ));
            let count = complete.0.lock().unwrap().calls;
            let mut pending = None;
            for failure in 0..count {
                let (pass, d) = related_attempt(&before, Some(failure));
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
                        let guarded = faults::Disk::new(&bytes);
                        guarded.arm(Some(0));
                        assert!(hfs_bridge::engine::open_checked(&mut guarded.clone()).is_err());
                        assert_eq!(guarded.0.lock().unwrap().calls, 0);
                    }
                    let got = related_observe(&mut MemoryBackend::from_bytes(bytes));
                    assert!(
                        got == old || got == new,
                        "partial conversion {kind}/{sensitive}/{failure}/{policy}"
                    );
                    commits += 1;
                }
            }
            let pending = pending.unwrap();
            retain_related(
                &pending,
                &format!("conversion-pending-{kind}-{sensitive}.img"),
            );
            let mut replay = faults::Disk::new(&pending);
            HfsPlus::open(&mut replay).unwrap();
            let count = replay.0.lock().unwrap().calls;
            for failure in 0..count {
                let mut d = faults::Disk::new(&pending);
                d.arm(Some(failure));
                assert!(HfsPlus::open(&mut d).is_err());
                for policy in 0..6 {
                    assert_eq!(
                        related_observe(&mut MemoryBackend::from_bytes(
                            d.snapshot(policy, journal)
                        )),
                        new
                    );
                    replays += 1;
                }
            }
        }
    }
    println!(
        "CONVERSION_RELATED_MATRIX: {commits} commit + {replays} replay snapshots; 4 scenarios"
    );
}

// Metadata-only transactions never remove decmpfs or replace encoded storage.
const BASIC_TIMES: [Option<u32>; 4] = [
    Some(3_800_000_000),
    Some(3_800_000_001),
    Some(3_800_000_002),
    Some(3_800_000_003),
];
const BASIC_ROOT: &str = "org.hfsbridge.windows.time-generation";
const BASIC_ENTRY: &str = "org.hfsbridge.windows.times";
fn basic_stage(fs: &mut HfsPlus, d: &mut dyn fstool::block::BlockDevice, cnid: u32) {
    fs.set_basic_metadata_with_publication(
        d,
        cnid,
        BASIC_TIMES,
        Some(0x22),
        &[
            (2, BASIC_ROOT, Some(b"root-generation")),
            (cnid, BASIC_ENTRY, Some(b"entry-precision")),
        ],
    )
    .unwrap();
}
fn retain_basic(bytes: &[u8], name: &str) {
    if let Some(dir) = std::env::var_os("HFS_BASIC_METADATA_ARTIFACT_DIR") {
        use std::io::Write;
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
struct BasicMetadataState {
    body: Vec<u8>,
    root: Vec<u8>,
    values: Vec<Option<Vec<u8>>>,
    counter: u32,
    free: u32,
}
fn basic_observe(bytes: Vec<u8>, expected: &[u8]) -> BasicMetadataState {
    let mut d = MemoryBackend::from_bytes(bytes);
    let fs = HfsPlus::open(&mut d).unwrap();
    let body = fs.catalog_record("/compressed").unwrap();
    let cnid = volume::be32(&body, 8);
    let mut plain = Vec::new();
    fs.open_file_reader(&mut d, "/compressed")
        .unwrap()
        .read_to_end(&mut plain)
        .unwrap();
    assert_eq!(plain, expected);
    let values = [
        (2, BASIC_ROOT),
        (cnid, BASIC_ENTRY),
        (cnid, "com.apple.decmpfs"),
        (cnid, "com.example.note"),
    ]
    .into_iter()
    .map(|(id, name)| fs.inline_attribute(&mut d, id, name).unwrap())
    .collect();
    BasicMetadataState {
        body,
        root: fs.catalog_record_cnid(2).unwrap(),
        values,
        counter: volume::be32(d.as_slice(), 1092),
        free: volume::be32(d.as_slice(), 1072),
    }
}
#[test]
fn basic_metadata_records_preserve_all_compression_forms_and_clear_catalog_locks() {
    let mut count = 0;
    for kind in [1, 3, 4, 7, 8, 9, 10, 11, 12, 13, 14] {
        for journaled in [false, true] {
            for sensitive in [false, true] {
                for locked in [false, true] {
                    let (mut d, plain) = fixture(
                        kind,
                        journaled,
                        sensitive,
                        matches!(kind, 1 | 3 | 7 | 9 | 11 | 13),
                    );
                    let mut fs = HfsPlus::open(&mut d).unwrap();
                    let cnid = volume::be32(&fs.catalog_record("/compressed").unwrap(), 8);
                    if locked {
                        fs.set_catalog_windows_info(cnid, [None; 4], Some(1))
                            .unwrap();
                        fs.flush(&mut d).unwrap();
                    }
                    let before = d.as_slice().to_vec();
                    let original = fs.catalog_record("/compressed").unwrap();
                    let compression = fs
                        .inline_attribute(&mut d, cnid, "com.apple.decmpfs")
                        .unwrap();
                    basic_stage(&mut fs, &mut d, cnid);
                    assert!(d.as_slice() == before);
                    fs.flush(&mut d).unwrap();
                    let mut fs = HfsPlus::open(&mut d).unwrap();
                    let body = fs.catalog_record("/compressed").unwrap();
                    assert_eq!(
                        volume::be32(d.as_slice(), 1092),
                        volume::be32(&before, 1092) + 1
                    );
                    assert_eq!(body[41] & 32, 32);
                    assert_eq!(volume::be16(&body, 2) & 1, 0);
                    assert_eq!(&body[32..56], &original[32..56]);
                    assert_eq!(&body[60..], &original[60..]);
                    assert_eq!(
                        fs.inline_attribute(&mut d, cnid, "com.apple.decmpfs")
                            .unwrap(),
                        compression
                    );
                    for (offset, want) in [12, 24, 16, 20].into_iter().zip(BASIC_TIMES) {
                        assert_eq!(volume::be32(&body, offset), want.unwrap());
                    }
                    for fork in [88, 168] {
                        for i in 0..8 {
                            let start = volume::be32(&original, fork + 16 + i * 8) as usize * 4096;
                            let size = volume::be32(&original, fork + 20 + i * 8) as usize * 4096;
                            assert_eq!(
                                &d.as_slice()[start..start + size],
                                &before[start..start + size]
                            );
                        }
                    }
                    basic_observe(d.as_slice().to_vec(), &plain);
                    if !locked && matches!(kind, 3 | 8 | 13 | 14) {
                        retain_basic(
                            d.as_slice(),
                            &format!("basic-{kind}-{journaled}-{sensitive}.img"),
                        );
                        retain_basic(
                            &plain,
                            &format!("basic-{kind}-{journaled}-{sensitive}.expected.bin"),
                        );
                    }
                    let committed = d.as_slice().to_vec();
                    fs.set_basic_metadata_with_publication(&mut d, cnid, [None; 4], None, &[])
                        .unwrap();
                    fs.flush(&mut d).unwrap();
                    assert!(d.as_slice() == committed);
                    // Basic flags can relock, but do not turn this into a public EA API.
                    fs.set_basic_metadata_with_publication(
                        &mut d,
                        cnid,
                        [None; 4],
                        Some(0x23),
                        &[],
                    )
                    .unwrap();
                    fs.flush(&mut d).unwrap();
                    assert!(
                        fs.set_inline_attribute(&mut d, cnid, "user", Some(b"refused"))
                            .is_err()
                    );
                    count += 1;
                }
            }
        }
    }
    println!("BASIC_COMPRESSED_SUCCESS: {count} codec/volume/lock combinations");
}
#[test]
fn basic_metadata_refusals_are_pure_and_do_not_allocate_decoded_replacements() {
    for kind in [3, 8, 13, 14] {
        let (mut d, _) = fixture(kind, true, false, matches!(kind, 3 | 13));
        let mut fs = HfsPlus::open(&mut d).unwrap();
        let cnid = volume::be32(&fs.catalog_record("/compressed").unwrap(), 8);
        let before = d.as_slice().to_vec();
        let huge = vec![0; 3803];
        let names = (0..17)
            .map(|_| (cnid, BASIC_ENTRY, None))
            .collect::<Vec<_>>();
        let cases = vec![
            vec![(cnid, "com.apple.decmpfs", None)],
            vec![(cnid, "user", Some(&b"no"[..]))],
            vec![(2, BASIC_ENTRY, None)],
            vec![(cnid, BASIC_ROOT, None)],
            vec![(cnid, BASIC_ENTRY, None), (cnid, BASIC_ENTRY, None)],
            vec![(cnid, BASIC_ENTRY, Some(huge.as_slice()))],
            names,
            vec![(cnid, "org.hfsbridge.windows.attributes", Some(&b"no"[..]))],
        ];
        for related in cases {
            assert!(
                fs.set_basic_metadata_with_publication(
                    &mut d,
                    cnid,
                    BASIC_TIMES,
                    Some(0x22),
                    &related
                )
                .is_err()
            );
            assert!(!fs.requires_reopen());
            fs.flush(&mut d).unwrap();
            assert!(d.as_slice() == before);
        }
        assert!(
            fs.set_basic_metadata_with_publication(&mut d, cnid, BASIC_TIMES, Some(0x10), &[])
                .is_err()
        );
        fs.flush(&mut d).unwrap();
        assert!(d.as_slice() == before);
        // Leave no free blocks: metadata-only dates still fit their existing
        // catalog nodes; a decoded-size reservation would incorrectly refuse.
        let free = volume::be32(d.as_slice(), 1072) as u64 * 4096;
        fs.set_data_allocation(
            &mut d,
            std::path::Path::new("/ordinary"),
            free + 4096,
            false,
        )
        .unwrap();
        assert_eq!(volume::be32(d.as_slice(), 1072), 0);
        fs.set_basic_metadata_with_publication(&mut d, cnid, BASIC_TIMES, Some(0x22), &[])
            .unwrap();
        fs.flush(&mut d).unwrap();
        assert_eq!(
            volume::be32(&fs.catalog_record("/compressed").unwrap(), 12),
            3_800_000_000
        );
    }
}
#[test]
fn basic_metadata_records_and_catalog_recover_without_converting_storage() {
    let mut commits = 0;
    let mut replays = 0;
    for kind in [3, 8, 13, 14] {
        let (d, plain) = fixture(kind, true, false, matches!(kind, 3 | 13));
        let before = d.into_bytes();
        let jib = volume::be32(&before, 1036) as usize * 4096;
        let journal = volume::be64(&before, jib + 36) as usize;
        let old = basic_observe(before.clone(), &plain);
        let attempt = |failure| {
            let mut d = faults::Disk::new(&before);
            let mut fs = HfsPlus::open(&mut d).unwrap();
            let cnid = volume::be32(&fs.catalog_record("/compressed").unwrap(), 8);
            basic_stage(&mut fs, &mut d, cnid);
            d.arm(failure);
            let pass = fs.flush(&mut d).is_ok();
            if !pass {
                let calls = d.0.lock().unwrap().calls;
                assert!(fs.requires_reopen());
                assert!(fs.flush(&mut d).is_err());
                assert_eq!(d.0.lock().unwrap().calls, calls);
            }
            (pass, d)
        };
        let (pass, d) = attempt(None);
        assert!(pass);
        let new = basic_observe(d.0.lock().unwrap().durable.clone(), &plain);
        assert_ne!(old, new);
        let calls = d.0.lock().unwrap().calls;
        let mut pending = None;
        for failure in 0..calls {
            let (pass, d) = attempt(Some(failure));
            assert!(!pass);
            for policy in 0..6 {
                let snapshot = d.snapshot(policy, journal);
                if matches!(
                    volume::inspect(&mut MemoryBackend::from_bytes(snapshot.clone()))
                        .unwrap()
                        .journal,
                    volume::Journal::Pending { .. }
                ) {
                    pending.get_or_insert_with(|| snapshot.clone());
                }
                let actual = basic_observe(snapshot, &plain);
                assert!(actual == old || actual == new, "partial basic publication");
                commits += 1;
            }
        }
        let pending = pending.unwrap();
        retain_basic(&pending, &format!("basic-pending-{kind}.img"));
        retain_basic(&plain, &format!("basic-pending-{kind}.expected.bin"));
        let mut d = faults::Disk::new(&pending);
        HfsPlus::open(&mut d).unwrap();
        let calls = d.0.lock().unwrap().calls;
        for failure in 0..calls {
            let mut d = faults::Disk::new(&pending);
            d.arm(Some(failure));
            assert!(HfsPlus::open(&mut d).is_err());
            for policy in 0..6 {
                assert_eq!(basic_observe(d.snapshot(policy, journal), &plain), new);
                replays += 1;
            }
        }
    }
    println!("BASIC_COMPRESSED_MATRIX: {commits} commit + {replays} replay snapshots; 4 scenarios");
}
