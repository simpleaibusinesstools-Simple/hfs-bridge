//! Private snapshots retain bounded lookup's fallback and never follow forks.
use fstool::{
    block::MemoryBackend,
    fs::hfs_plus::{FormatOpts, HfsPlus},
};
use hfs_bridge::volume;
#[allow(dead_code)]
#[path = "support/attribute_wire.rs"]
mod wire;

#[test]
fn indexed_fixed_values_match_bounded_reads_for_valid_and_malformed_bodies() {
    let mut disk = MemoryBackend::new(8 * 1024 * 1024);
    let mut fs = HfsPlus::format(&mut disk, &FormatOpts::default()).unwrap();
    let cnid = fs
        .create_file(&mut disk, "/file", &mut &b"data"[..], 4, 0o644, 501, 20, 0)
        .unwrap();
    fs.flush(&mut disk).unwrap();
    fs.set_inline_attribute(&mut disk, cnid, "test.fixed", Some(&[0x73; 80]))
        .unwrap();
    fs.flush(&mut disk).unwrap();
    let bytes = disk.into_bytes();
    let attr = volume::be32(&bytes, 1392) as usize * 4096;
    let leaf = attr + volume::be32(&bytes, attr + 24) as usize * wire::NS;
    let record = wire::records(&bytes[leaf..leaf + wire::NS])[0];
    assert_eq!(
        wire::order(record),
        (cnid, "test.fixed".encode_utf16().collect(), 0)
    );
    let body = record.as_ptr() as usize - bytes.as_ptr() as usize + 14 + 2 * "test.fixed".len();
    for case in 0..6 {
        let mut changed = bytes.clone();
        match case {
            0 => {}
            1 => changed[body + 4] = 1,
            2 => wire::p32(&mut changed, body + 12, u32::MAX),
            3 => wire::p32(&mut changed, body, 0x20), // Fork descriptor, never followed.
            4 => wire::p32(&mut changed, body, 0x7fffffff),
            5 => wire::p32(&mut changed, body + 12, 79),
            _ => unreachable!(),
        }
        let mut device = MemoryBackend::from_bytes(changed);
        let fs = HfsPlus::open(&mut device).unwrap();
        let index = fs.attribute_read_index(&mut device).unwrap();
        let expected = (case == 0).then(|| vec![0x73; 80]);
        assert_eq!(
            fs.fixed_inline_attribute(&mut device, cnid, "test.fixed", 80)
                .unwrap(),
            expected
        );
        assert_eq!(
            fs.indexed_fixed_inline_attribute(&index, cnid, "test.fixed", 80)
                .unwrap(),
            expected
        );
        assert_eq!(
            fs.indexed_fixed_inline_attribute(&index, cnid, "absent", 80)
                .unwrap(),
            None
        );
        assert!(
            fs.indexed_fixed_inline_attribute(&index, cnid, "test.fixed", 3803)
                .is_err()
        );
    }
}

#[test]
fn pending_metadata_refuses_snapshot_and_committed_fork_values_remain_optional() {
    let mut disk = MemoryBackend::new(8 * 1024 * 1024);
    let mut fs = HfsPlus::format(&mut disk, &FormatOpts::default()).unwrap();
    let cnid = fs
        .create_file(&mut disk, "/file", &mut &b"data"[..], 4, 0o644, 501, 20, 0)
        .unwrap();
    fs.flush(&mut disk).unwrap();
    fs.set_inline_attribute(&mut disk, cnid, "test.fork", Some(&vec![0x73; 4097]))
        .unwrap();
    fs.flush(&mut disk).unwrap();
    let index = fs.attribute_read_index(&mut disk).unwrap();
    assert_eq!(
        fs.fixed_inline_attribute(&mut disk, cnid, "test.fork", 80)
            .unwrap(),
        None
    );
    assert_eq!(
        fs.indexed_fixed_inline_attribute(&index, cnid, "test.fork", 80)
            .unwrap(),
        None
    );
    fs.set_catalog_times(cnid, [None, None, Some(3_800_000_000), None])
        .unwrap();
    assert!(!fs.metadata_is_committed());
    assert!(
        fs.indexed_fixed_inline_attribute(&index, cnid, "test.fork", 80)
            .is_err()
    );
    fs.flush(&mut disk).unwrap();
    let current = fs.attribute_read_index(&mut disk).unwrap();
    assert_eq!(
        fs.indexed_fixed_inline_attribute(&current, cnid, "test.fork", 80)
            .unwrap(),
        None
    );
}

#[test]
fn snapshot_keeps_the_bounded_readers_sixteen_level_limit() {
    let mut disk = MemoryBackend::new(8 * 1024 * 1024);
    let mut fs = HfsPlus::format(&mut disk, &FormatOpts::default()).unwrap();
    let cnid = fs
        .create_file(&mut disk, "/file", &mut &b"data"[..], 4, 0o644, 501, 20, 0)
        .unwrap();
    fs.flush(&mut disk).unwrap();
    fs.set_inline_attribute(&mut disk, cnid, "test.fixed", Some(&[0x73; 80]))
        .unwrap();
    fs.flush(&mut disk).unwrap();
    let base = disk.into_bytes();
    for depth in [16, 17] {
        let mut bytes = base.clone();
        let attr = wire::install(
            &mut bytes,
            vec![wire::record(cnid, "test.fixed", &[0x73; 80])],
            32,
            2,
            false,
        );
        let raw = wire::record(cnid, "test.fixed", &[]);
        let key_len = 2 + usize::from(wire::u16be(&raw, 0));
        for id in 2..=depth {
            let start = attr + id as usize * wire::NS;
            let node = &mut bytes[start..start + wire::NS];
            node.fill(0);
            node[8] = 0; // one index node at each height
            node[9] = id as u8;
            wire::p16(node, 10, 1);
            node[14..14 + key_len].copy_from_slice(&raw[..key_len]);
            wire::p32(node, 14 + key_len, id - 1);
            wire::p16(node, wire::NS - 2, 14);
            wire::p16(node, wire::NS - 4, (14 + key_len + 4) as u16);
            let map_offset = usize::from(wire::u16be(&bytes, attr + wire::NS - 6));
            bytes[attr + map_offset + id as usize / 8] |= 0x80 >> (id % 8);
        }
        wire::p16(&mut bytes, attr + 14, depth as u16);
        wire::p32(&mut bytes, attr + 16, depth);
        wire::p32(&mut bytes, attr + 40, 32 - (depth + 1));
        let mut device = MemoryBackend::from_bytes(bytes);
        let fs = HfsPlus::open(&mut device).unwrap();
        let index = fs.attribute_read_index(&mut device).unwrap();
        let direct = fs.fixed_inline_attribute(&mut device, cnid, "test.fixed", 80);
        let indexed = fs.indexed_fixed_inline_attribute(&index, cnid, "test.fixed", 80);
        if depth == 16 {
            assert_eq!(direct.unwrap(), Some(vec![0x73; 80]));
            assert_eq!(indexed.unwrap(), Some(vec![0x73; 80]));
        } else {
            assert!(direct.is_err());
            assert!(indexed.is_err());
        }
    }
}
