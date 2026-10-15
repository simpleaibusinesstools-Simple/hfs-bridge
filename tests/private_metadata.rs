//! Independent malformed tree fixtures and public-transport preservation checks.
use fstool::{
    block::{BlockDevice, MemoryBackend},
    fs::hfs_plus::{FormatOpts, HfsPlus},
};
use hfs_bridge::{
    attribute_archive as archive, ea,
    named_streams::{self, ATTRIBUTE as STREAMS},
    timestamps::{GENERATION_ATTRIBUTE as GENERATION, TIMES_ATTRIBUTE as TIMES},
    volume,
    windows::{Access, Adapter, Kind, OpenRequest, Status},
};
use std::io::{self, Cursor, Read, Seek, SeekFrom, Write};
#[path = "support/fault_disk.rs"]
mod fault;
#[path = "support/attribute_wire.rs"]
#[allow(dead_code)]
mod wire;
fn all() -> OpenRequest {
    OpenRequest {
        access: Access::ALL,
        ..Default::default()
    }
}
fn fixture(journaled: bool) -> (Vec<u8>, u32) {
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
        &mut &b"data"[..],
        4,
        0o644,
        501,
        20,
        1_700_000_000,
    )
    .unwrap();
    fs.flush(&mut d).unwrap();
    let cnid = volume::be32(&fs.catalog_record("/file").unwrap(), 8);
    (d.into_bytes(), cnid)
}
struct ReadProbe {
    bytes: Cursor<Vec<u8>>,
    reads: Vec<(u64, usize)>,
    writes: usize,
    fail: bool,
}
impl Read for ReadProbe {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.reads.push((self.bytes.position(), buf.len()));
        if self.fail {
            return Err(io::Error::other("injected read failure"));
        }
        self.bytes.read(buf)
    }
}
impl Seek for ReadProbe {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.bytes.seek(pos)
    }
}
impl Write for ReadProbe {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> {
        self.writes += 1;
        Err(io::Error::other("unexpected write"))
    }
    fn flush(&mut self) -> io::Result<()> {
        self.writes += 1;
        Err(io::Error::other("unexpected sync"))
    }
}
impl BlockDevice for ReadProbe {
    fn block_size(&self) -> u32 {
        512
    }
    fn total_size(&self) -> u64 {
        self.bytes.get_ref().len() as u64
    }
    fn sync(&mut self) -> fstool::Result<()> {
        Ok(self.flush()?)
    }
}
fn probe(bytes: Vec<u8>) -> ReadProbe {
    ReadProbe {
        bytes: Cursor::new(bytes),
        reads: vec![],
        writes: 0,
        fail: false,
    }
}
fn fork_record(cnid: u32, name: &str) -> Vec<u8> {
    let mut rec = wire::record(cnid, name, &[]);
    let key_len = 2 + wire::u16be(&rec, 0) as usize;
    rec.truncate(key_len);
    rec.extend_from_slice(&0x20u32.to_be_bytes());
    rec.extend_from_slice(&[0; 4]);
    let mut fork = [0; 80];
    fork[..8].copy_from_slice(&u64::MAX.to_be_bytes());
    fork[12..16].copy_from_slice(&u32::MAX.to_be_bytes());
    fork[16..20].copy_from_slice(&1000u32.to_be_bytes());
    fork[20..24].copy_from_slice(&u32::MAX.to_be_bytes());
    rec.extend_from_slice(&fork);
    rec
}
#[test]
fn private_inline_reader_rejects_untrusted_bodies_without_value_reads() {
    let (base, cnid) = fixture(false);
    for variant in 0..9 {
        let mut bytes = base.clone();
        let mut record = wire::record(cnid, TIMES, &[7; 112]);
        let body = 2 + wire::u16be(&record, 0) as usize;
        match variant {
            0 => {}
            1 => record = wire::record(cnid, TIMES, &[7; 3802]),
            2 => record = fork_record(cnid, TIMES),
            3 => wire::p32(&mut record, body + 12, u32::MAX),
            4 => record[body + 4] = 1,
            5 => wire::p32(&mut record, body, 0x30),
            6 => record.truncate(body + 2),
            7 => record = wire::record(cnid, "Org.hfsbridge.windows.times", &[7; 112]),
            8 => record = wire::record(cnid, TIMES, &[7; 111]),
            _ => unreachable!(),
        }
        let tree = wire::install(&mut bytes, vec![record], 4, 2, false);
        let mut d = probe(bytes.clone());
        let fs = HfsPlus::open(&mut d).unwrap();
        d.reads.clear();
        let result = fs.fixed_inline_attribute(&mut d, cnid, TIMES, 112).unwrap();
        assert_eq!(
            result,
            (variant == 0).then(|| vec![7; 112]),
            "variant {variant}"
        );
        assert!(d.reads.len() <= 2);
        assert!(
            d.reads.iter().all(|&(off, len)| off >= tree as u64
                && off + len as u64 <= (tree + 4 * wire::NS) as u64)
        );
        assert_eq!(d.writes, 0);
        assert_eq!(d.bytes.get_ref(), &bytes);
    }
    println!(
        "PRIVATE_VALUE_BOUNDS: 9 independently encoded value/name variants; no payload reads or writes"
    );
}
#[test]
fn private_inline_reader_bounds_descent_and_propagates_structure_and_io_errors() {
    let (base, cnid) = fixture(false);
    for variant in 0..11 {
        let mut bytes = base.clone();
        let records = vec![
            wire::record(cnid, TIMES, &[7; 112]),
            wire::record(cnid, "z", &[8; 80]),
        ];
        let tree = wire::install(&mut bytes, records, 8, 2, false);
        let root = tree + volume::be32(&bytes, tree + 16) as usize * wire::NS;
        match variant {
            0 => wire::p16(&mut bytes, tree + 14, u16::MAX),
            1 => wire::p32(&mut bytes, tree + 16, 8),
            2 => bytes[root + 9] = 1,
            3 => wire::p16(&mut bytes, root + 10, u16::MAX),
            4 => {
                let record = wire::records(&bytes[root..root + wire::NS])[0];
                let key_len = 2 + wire::u16be(record, 0) as usize;
                wire::p32(
                    &mut bytes,
                    root + 14 + key_len,
                    ((root - tree) / wire::NS) as u32,
                );
            }
            5 => wire::p32(&mut bytes, tree + 36, 9),
            6 => wire::p16(&mut bytes, tree + 32, 256),
            7 => wire::p16(&mut bytes, root + wire::NS - 4, 14),
            8 => bytes[root + 16] = 1,
            9 => wire::p32(&mut bytes, tree + 16, 0),
            10 => {}
            _ => unreachable!(),
        }
        let mut d = probe(bytes);
        let fs = HfsPlus::open(&mut d).unwrap();
        d.reads.clear();
        d.fail = variant == 10;
        assert!(
            fs.fixed_inline_attribute(&mut d, cnid, TIMES, 112).is_err(),
            "variant {variant}"
        );
        assert!(d.reads.len() <= 3);
        assert!(d.reads.iter().all(|&(_, len)| len <= 4096));
        assert_eq!(d.writes, 0);
        assert!(!fs.requires_reopen());
    }
    println!("PRIVATE_TREE_BOUNDS: 11 structural/IO defects rejected within three reads");
}
#[test]
fn private_inline_reader_uses_relocated_writer_tree_and_refuses_pending_plan() {
    for journaled in [false, true] {
        let (bytes, cnid) = fixture(journaled);
        let mut d = MemoryBackend::from_bytes(bytes);
        let mut fs = HfsPlus::open(&mut d).unwrap();
        assert_eq!(
            fs.fixed_inline_attribute(&mut d, cnid, TIMES, 112).unwrap(),
            None
        );
        for n in 1..=3 {
            fs.set_inline_attribute(&mut d, cnid, TIMES, Some(&[n; 112]))
                .unwrap();
            assert!(fs.fixed_inline_attribute(&mut d, cnid, TIMES, 112).is_err());
            fs.flush(&mut d).unwrap();
            assert_eq!(
                fs.fixed_inline_attribute(&mut d, cnid, TIMES, 112).unwrap(),
                Some(vec![n; 112])
            );
        }
        assert!(
            fs.fixed_inline_attribute(&mut d, cnid, TIMES, 3803)
                .is_err()
        );
        let before = d.as_slice().to_vec();
        fs.fixed_inline_attribute(&mut d, cnid, TIMES, 112).unwrap();
        fs.flush(&mut d).unwrap();
        assert_eq!(d.as_slice(), before);
    }
}
fn stored_streams() -> Vec<u8> {
    named_streams::encode(&named_streams::Store {
        next_id: 2,
        streams: vec![named_streams::Stream {
            id: 1,
            name: "Zone.Identifier".into(),
            data: vec![29; 20019],
            allocation: 24576,
        }],
    })
    .unwrap()
}
fn with_records(journaled: bool, large: bool) -> (Vec<u8>, u32) {
    let (bytes, cnid) = fixture(journaled);
    let mut d = MemoryBackend::from_bytes(bytes);
    let mut fs = HfsPlus::open(&mut d).unwrap();
    fs.set_attributes_batch_with_publication(
        &mut d,
        &[
            (cnid, TIMES, Some(&[4; 112])),
            (cnid, GENERATION, Some(&[5; 80])),
            (cnid, STREAMS, Some(&stored_streams())),
            (
                cnid,
                "Org.hfsbridge.windows.streams",
                Some(b"public stream variant"),
            ),
            (
                cnid,
                "Org.hfsbridge.windows.times",
                Some(b"ordinary case variant"),
            ),
            (cnid, "public", Some(b"old")),
        ],
        &[(2, GENERATION, Some(&[6; 80]))],
        &[],
    )
    .unwrap();
    fs.flush(&mut d).unwrap();
    if large {
        fs.set_inline_attribute(&mut d, cnid, "large", Some(&vec![9; 20019]))
            .unwrap();
        fs.flush(&mut d).unwrap();
    }
    (d.into_bytes(), cnid)
}
fn export(name: &str, bytes: &[u8]) {
    if let Some(directory) = std::env::var_os("HFS_PRIVATE_IMAGES") {
        let directory = std::path::Path::new(&directory);
        std::fs::create_dir_all(directory).unwrap();
        std::fs::write(directory.join(name), bytes).unwrap();
    }
}
#[test]
fn private_inline_reader_handles_sparse_multilevel_binary_keys_on_hfs_plus_and_x() {
    for sensitive in [false, true] {
        let (mut bytes, cnid) = fixture(false);
        let mut records = (0..120)
            .map(|n| wire::record(cnid, &format!("public-{n:03}"), &[n as u8; 112]))
            .collect::<Vec<_>>();
        records.push(wire::record(2, GENERATION, &[6; 80]));
        records.push(wire::record(cnid, TIMES, &[7; 112]));
        records.push(wire::record(cnid, "Org.hfsbridge.windows.times", &[8; 112]));
        wire::install(&mut bytes, records, 256, 3, true);
        if sensitive {
            bytes[1024..1026].copy_from_slice(b"HX");
            wire::p16(&mut bytes, 1026, 5);
            let catalog = volume::be32(&bytes, 1312) as usize * 4096;
            bytes[catalog + 51] = 0xbc;
            let header = bytes[1024..1536].to_vec();
            let alternate = bytes.len() - 1024;
            bytes[alternate..alternate + 512].copy_from_slice(&header);
        }
        let mut d = probe(bytes);
        let fs = HfsPlus::open(&mut d).unwrap();
        for (name, byte) in [
            (TIMES, 7),
            ("Org.hfsbridge.windows.times", 8),
            ("public-119", 119),
        ] {
            d.reads.clear();
            assert_eq!(
                fs.fixed_inline_attribute(&mut d, cnid, name, 112).unwrap(),
                Some(vec![byte; 112])
            );
            assert!(d.reads.len() <= 7);
        }
        assert_eq!(
            fs.fixed_inline_attribute(&mut d, 2, GENERATION, 80)
                .unwrap(),
            Some(vec![6; 80])
        );
        assert_eq!(
            fs.fixed_inline_attribute(&mut d, cnid, "ORG.hfsbridge.windows.times", 112)
                .unwrap(),
            None
        );
        assert_eq!(d.writes, 0);
    }
}
fn projected(records: &[(String, Option<Vec<u8>>)]) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let mut records = records.to_vec();
    records.sort_by_key(|(name, _)| name.encode_utf16().collect::<Vec<_>>());
    let mut bytes = b"HFSBXA1\0".to_vec();
    bytes.extend_from_slice(&(records.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&1u32.to_le_bytes());
    bytes.extend_from_slice(&0u64.to_le_bytes());
    for (name, value) in records {
        let units = name.encode_utf16().collect::<Vec<_>>();
        bytes.extend_from_slice(&(units.len() as u16).to_le_bytes());
        bytes.extend_from_slice(&u16::from(value.is_none()).to_le_bytes());
        let value = value.unwrap_or_default();
        bytes.extend_from_slice(&(value.len() as u32).to_le_bytes());
        bytes.extend(units.into_iter().flat_map(u16::to_le_bytes));
        bytes.extend(value);
    }
    let size = bytes.len() + 32;
    bytes[16..24].copy_from_slice(&(size as u64).to_le_bytes());
    bytes.extend_from_slice(&Sha256::digest(&bytes));
    bytes
}
#[test]
fn projected_archives_cannot_smuggle_private_values_or_delete_existing_private_records() {
    for journaled in [false, true] {
        let (bytes, cnid) = with_records(journaled, true);
        export(&format!("private-source-{journaled}.img"), &bytes);
        let disk = fault::Disk::new(&bytes);
        let mut a = Adapter::from_device(disk.clone()).unwrap();
        let h = a.open("\\file", all()).unwrap();
        let supplied = [ea::Change {
            name: "new-small".into(),
            value: Some(b"supplied".to_vec()),
        }];
        a.overwrite_with_ea(h, 0x80, true, 0, &supplied).unwrap();
        // An actual unnamed-file overwrite now legitimately deletes ordinary
        // streams. Subsequent public EA/archive imports must preserve that new
        // private state and may neither inject records nor reset its next ID.
        let overwritten_streams = named_streams::encode(&named_streams::Store {
            next_id: 2,
            streams: vec![],
        })
        .unwrap();
        a.write(h, 0, b"data", false, false).unwrap();
        let stream = a.open("\\file:HFSB_Attributes", all()).unwrap();
        disk.arm(None);
        for name in [
            TIMES,
            GENERATION,
            STREAMS,
            hfs_bridge::links::KIND_ATTRIBUTE,
        ] {
            for value in [None, Some(vec![0; 112])] {
                a.set_size(stream, 0).unwrap();
                let bad = projected(&[
                    ("aaa-public".into(), Some(b"must not stage".to_vec())),
                    (name.into(), value),
                ]);
                assert_eq!(
                    a.write(stream, 0, &bad, false, false).unwrap_err().status,
                    Status::AccessDenied
                );
            }
        }
        assert_eq!(disk.0.lock().unwrap().calls, 0);
        a.set_size(stream, 0).unwrap();
        let good = projected(&[
            ("new-small".into(), None),
            ("new-large".into(), Some(vec![8; 20019])),
        ]);
        a.write(stream, 0, &good, false, false).unwrap();
        a.close(stream).unwrap();
        a.close(h).unwrap();
        a.shutdown().unwrap();
        let mut d = MemoryBackend::from_bytes(disk.snapshot(1, 0));
        assert_private_streams(&mut d, cnid, &overwritten_streams);
        let fs = HfsPlus::open(&mut d).unwrap();
        assert_eq!(
            fs.inline_attribute(&mut d, cnid, "new-small").unwrap(),
            Some(b"supplied".to_vec())
        );
        assert_eq!(
            fs.inline_attribute(&mut d, cnid, "new-large").unwrap(),
            Some(vec![8; 20019])
        );
        export(&format!("private-projected-{journaled}.img"), d.as_slice());
    }
}
fn assert_private(d: &mut MemoryBackend, cnid: u32) {
    assert_private_streams(d, cnid, &stored_streams());
}
fn assert_private_streams(d: &mut MemoryBackend, cnid: u32, expected: &[u8]) {
    let fs = HfsPlus::open(d).unwrap();
    assert_eq!(
        fs.inline_attribute(d, cnid, STREAMS).unwrap(),
        Some(expected.to_vec())
    );
    // Legitimate publication replaces invalid old timestamp placeholders with
    // valid records. It still must not alter the unrelated private file marker.
    assert_eq!(
        fs.fixed_inline_attribute(d, cnid, GENERATION, 80).unwrap(),
        Some(vec![5; 80])
    );
    let root = fs
        .fixed_inline_attribute(d, 2, GENERATION, 80)
        .unwrap()
        .unwrap();
    let entry = fs
        .fixed_inline_attribute(d, cnid, TIMES, 112)
        .unwrap()
        .unwrap();
    let generation = hfs_bridge::timestamps::Generation::decode(&root).unwrap();
    assert!(hfs_bridge::timestamps::PrecisionRecord::decode(&entry).is_some());
    assert!(generation.matches(hfs_bridge::timestamps::VolumeState {
        id: d.as_slice()[1128..1136].try_into().unwrap(),
        created: volume::be32(d.as_slice(), 1040),
        write_count: volume::be32(d.as_slice(), 1092),
    }));
    assert_eq!(&entry[24..40], &root[24..40]);
    assert_eq!(volume::be32(&entry, 20), cnid);
    let body = fs.catalog_record_cnid(cnid).unwrap();
    for (index, offset) in [12, 24, 16, 20].into_iter().enumerate() {
        assert_eq!(
            volume::be32(&entry, 48 + index * 4),
            volume::be32(&body, offset)
        );
    }
}
#[test]
fn public_transports_reject_private_creation_set_delete_and_overwrite_without_writes() {
    let (bytes, _) = with_records(true, false);
    let disk = fault::Disk::new(&bytes);
    let mut a = Adapter::from_device(disk.clone()).unwrap();
    let h = a.open("\\file", all()).unwrap();
    disk.arm(None);
    for name in [
        TIMES,
        GENERATION,
        STREAMS,
        hfs_bridge::links::KIND_ATTRIBUTE,
    ] {
        for value in [Some(vec![0; 112]), None] {
            let changes = [
                ea::Change {
                    name: "public".into(),
                    value: Some(b"must not stage".to_vec()),
                },
                ea::Change {
                    name: name.into(),
                    value: value.clone(),
                },
            ];
            assert_eq!(
                a.create_initialized_with_ea("\\bad", Kind::File, all(), None, 0, &changes)
                    .unwrap_err()
                    .status,
                Status::AccessDenied
            );
            assert_eq!(
                a.overwrite_with_ea(h, 0x80, true, 0, &changes)
                    .unwrap_err()
                    .status,
                Status::AccessDenied
            );
            let mut records =
                ea::records(&[("public".into(), b"must not stage".to_vec())]).unwrap();
            records.push(ea::Record {
                name: ea::alias(name).unwrap(),
                value: value
                    .as_ref()
                    .map_or(vec![], |v| ea::pack_value(name, v).unwrap()),
            });
            assert!(
                a.set_extended_attributes(h, &ea::encode(&records).unwrap())
                    .is_err()
            );
        }
    }
    assert_eq!(disk.0.lock().unwrap().calls, 0);
    assert!(a.failure().is_none());
    a.close(h).unwrap();
    a.shutdown().unwrap();
    assert_eq!(disk.snapshot(1, 0), bytes);
}
#[test]
fn public_enumeration_skips_huge_private_forks_before_value_reads() {
    let (mut bytes, cnid) = fixture(false);
    wire::install(
        &mut bytes,
        vec![
            fork_record(cnid, TIMES),
            fork_record(cnid, GENERATION),
            fork_record(cnid, STREAMS),
            wire::record(cnid, "public", b"ok"),
        ],
        8,
        2,
        false,
    );
    let mut a = Adapter::from_device(MemoryBackend::from_bytes(bytes.clone())).unwrap();
    let h = a.open("\\file", all()).unwrap();
    let records = a.extended_attributes(h).unwrap();
    assert_eq!(
        ea::changes(&ea::encode(&records).unwrap(), &[]).unwrap(),
        vec![ea::Change {
            name: "public".into(),
            value: Some(b"ok".to_vec())
        }]
    );
    // Public EA/archive projection still skips private forks. Ordinary stream
    // enumeration now decodes its own container and must reject this corruption.
    assert!(a.streams(h).is_err());
    assert_eq!(
        a.open("\\file:HFSB_Attributes", all()).unwrap_err().status,
        Status::NotFound
    );
    a.close(h).unwrap();
    assert_eq!(a.shutdown().unwrap().as_slice(), bytes);
}
#[test]
fn archive_replacement_and_deletion_preserve_private_records_and_exact_case() {
    for journaled in [false, true] {
        let (bytes, cnid) = with_records(journaled, true);
        let mut a = Adapter::from_device(MemoryBackend::from_bytes(bytes)).unwrap();
        let h = a.open("\\file", all()).unwrap();
        let stream = a.open("\\file:HFSB_Attributes", all()).unwrap();
        let mut buf = vec![0; a.file_info(stream).unwrap().size as usize];
        assert_eq!(a.read(stream, 0, &mut buf).unwrap(), buf.len());
        let snapshot = archive::decode_snapshot(&buf).unwrap();
        assert!(snapshot.projected);
        assert!(
            snapshot
                .records
                .iter()
                .all(|(n, _)| n != TIMES && n != GENERATION && n != STREAMS)
        );
        assert!(
            snapshot
                .records
                .iter()
                .any(|(n, _)| n == "Org.hfsbridge.windows.times")
        );
        assert!(
            snapshot
                .records
                .iter()
                .any(|(n, _)| n == "Org.hfsbridge.windows.streams")
        );
        for name in [
            TIMES,
            GENERATION,
            STREAMS,
            hfs_bridge::links::KIND_ATTRIBUTE,
        ] {
            a.set_size(stream, 0).unwrap();
            let bad = archive::encode(&[
                ("public".into(), b"must not stage".to_vec()),
                (name.into(), vec![9]),
            ])
            .unwrap();
            assert_eq!(
                a.write(stream, 0, &bad, false, false).unwrap_err().status,
                Status::AccessDenied
            );
        }
        a.set_size(stream, 0).unwrap();
        let good = archive::encode(&[
            (
                "Org.hfsbridge.windows.times".into(),
                b"case retained".to_vec(),
            ),
            ("replacement".into(), vec![8; 20019]),
        ])
        .unwrap();
        a.write(stream, 0, &good, false, false).unwrap();
        a.close(stream).unwrap();
        a.close(h).unwrap();
        let mut d = a.shutdown().unwrap();
        assert_private(&mut d, cnid);
        let fs = HfsPlus::open(&mut d).unwrap();
        assert_eq!(fs.inline_attribute(&mut d, cnid, "public").unwrap(), None);
        assert_eq!(
            fs.inline_attribute(&mut d, cnid, "Org.hfsbridge.windows.times")
                .unwrap(),
            Some(b"case retained".to_vec())
        );
        let mut a = Adapter::from_device(d).unwrap();
        let stream = a.open("\\file:HFSB_Attributes", all()).unwrap();
        a.cleanup(stream, true).unwrap();
        a.close(stream).unwrap();
        let mut d = a.shutdown().unwrap();
        assert_private(&mut d, cnid);
        if let Some(directory) = std::env::var_os("HFS_PRIVATE_IMAGES") {
            let directory = std::path::Path::new(&directory);
            std::fs::create_dir_all(directory).unwrap();
            std::fs::write(
                directory.join(format!("private-preserved-{journaled}.img")),
                d.as_slice(),
            )
            .unwrap();
        }
    }
}
