//! Independent catalog wire checker shared by structural and crash tests.
use hfs_bridge::volume;
use std::collections::{BTreeMap, BTreeSet};
fn u16be(bytes: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes(bytes[offset..offset + 2].try_into().unwrap())
}
pub fn fork(bytes: &[u8]) -> Vec<u8> {
    let length = volume::be64(bytes, 1296) as usize;
    let block = volume::be32(bytes, 1064) as usize;
    let mut result = Vec::new();
    for index in 0..8 {
        let start = volume::be32(bytes, 1312 + index * 8) as usize * block;
        let count = volume::be32(bytes, 1316 + index * 8) as usize * block;
        result.extend_from_slice(&bytes[start..start + count]);
    }
    result.truncate(length);
    result
}
pub fn records(node: &[u8]) -> Vec<&[u8]> {
    let count = u16be(node, 10) as usize;
    let offsets: Vec<_> = (0..=count)
        .map(|i| u16be(node, node.len() - 2 * (i + 1)) as usize)
        .collect();
    assert!(offsets[0] >= 14);
    assert!(offsets[count] <= node.len() - 2 * (count + 1));
    offsets
        .windows(2)
        .map(|pair| {
            assert!(pair[0] < pair[1]);
            &node[pair[0]..pair[1]]
        })
        .collect()
}
fn key(record: &[u8]) -> (u32, Vec<u16>) {
    let length = u16be(record, 6) as usize;
    assert_eq!(u16be(record, 0) as usize + 2, 8 + length * 2);
    (
        volume::be32(record, 2),
        (0..length)
            .map(|i| {
                let unit = u16be(record, 8 + i * 2);
                if (65..=90).contains(&unit) {
                    unit + 32
                } else {
                    unit
                }
            })
            .collect(),
    )
}
pub struct Audit {
    pub depth: u16,
    pub total: u32,
    pub free: u32,
    pub leaves: usize,
}
pub fn audit(bytes: &[u8]) -> Audit {
    let catalog = fork(bytes);
    let size = u16be(&catalog, 32) as usize;
    let header = records(&catalog[..size])[0];
    let total = volume::be32(header, 22);
    let free = volume::be32(header, 26);
    assert_eq!(catalog.len(), total as usize * size);
    let node = |id: u32| &catalog[id as usize * size..(id as usize + 1) * size];
    let mut seen = BTreeSet::from([0]);
    let mut bitmap = records(node(0))[2].to_vec();
    let mut map_id = volume::be32(node(0), 0);
    while map_id != 0 {
        assert!(map_id < total && seen.insert(map_id));
        assert_eq!(node(map_id)[8], 2);
        assert_eq!(volume::be32(node(map_id), 4), 0);
        let map = records(node(map_id));
        assert_eq!(map.len(), 1);
        assert_eq!(map[0].len(), size - 20);
        bitmap.extend_from_slice(map[0]);
        map_id = volume::be32(node(map_id), 0);
    }
    let used = |id: u32| bitmap[id as usize / 8] & (0x80 >> (id & 7)) != 0;
    assert_eq!((0..total).filter(|&id| !used(id)).count(), free as usize);
    let mut levels: BTreeMap<u8, Vec<u32>> = BTreeMap::new();
    let mut leaves = Vec::new();
    fn walk<'a>(
        id: u32,
        height: u8,
        catalog: &'a [u8],
        size: usize,
        seen: &mut BTreeSet<u32>,
        levels: &mut BTreeMap<u8, Vec<u32>>,
        leaves: &mut Vec<&'a [u8]>,
    ) -> Vec<u8> {
        assert!(seen.insert(id), "duplicate/cyclic tree node");
        let node = &catalog[id as usize * size..(id as usize + 1) * size];
        assert_eq!(node[9], height);
        assert_eq!(node[8], if height == 1 { 255 } else { 0 });
        levels.entry(height).or_default().push(id);
        let entries = records(node);
        assert!(!entries.is_empty());
        if height > 1 {
            assert!(entries.len() >= 2, "one-child index node");
        }
        assert!(entries.windows(2).all(|pair| key(pair[0]) < key(pair[1])));
        for record in &entries {
            let key_len = u16be(record, 0) as usize + 2;
            if height == 1 {
                leaves.push(record);
            } else {
                assert_eq!(record.len(), key_len + 4);
                let child = volume::be32(record, key_len);
                let first = walk(child, height - 1, catalog, size, seen, levels, leaves);
                assert_eq!(&record[..key_len], first);
            }
        }
        entries[0][..u16be(entries[0], 0) as usize + 2].to_vec()
    }
    let depth = u16be(header, 0);
    walk(
        volume::be32(header, 2),
        depth as u8,
        &catalog,
        size,
        &mut seen,
        &mut levels,
        &mut leaves,
    );
    assert_eq!(leaves.len(), volume::be32(header, 6) as usize);
    assert!(leaves.windows(2).all(|pair| key(pair[0]) < key(pair[1])));
    assert_eq!(levels[&1][0], volume::be32(header, 10));
    assert_eq!(*levels[&1].last().unwrap(), volume::be32(header, 14));
    for ids in levels.values() {
        for (index, &id) in ids.iter().enumerate() {
            assert_eq!(
                volume::be32(node(id), 4),
                if index == 0 { 0 } else { ids[index - 1] }
            );
            assert_eq!(
                volume::be32(node(id), 0),
                ids.get(index + 1).copied().unwrap_or(0)
            );
        }
    }
    assert_eq!(
        (0..total).filter(|&id| used(id)).collect::<BTreeSet<_>>(),
        seen
    );
    let mut children = BTreeMap::<u32, u32>::new();
    for record in &leaves {
        let body = &record[u16be(record, 0) as usize + 2..];
        if [1, 2].contains(&u16be(body, 0)) {
            *children.entry(volume::be32(record, 2)).or_default() += 1;
        }
    }
    for record in &leaves {
        let body = &record[u16be(record, 0) as usize + 2..];
        if u16be(body, 0) == 1 {
            assert_eq!(
                volume::be32(body, 4),
                children.get(&volume::be32(body, 8)).copied().unwrap_or(0)
            );
        }
    }
    Audit {
        depth,
        total,
        free,
        leaves: levels[&1].len(),
    }
}
