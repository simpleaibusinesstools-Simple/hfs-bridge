//! Independent attribute wire fixtures/audits, without engine tree encoders.
use hfs_bridge::volume;
use std::collections::{BTreeMap, BTreeSet};
pub const NS: usize = 4096;
const HEADER_BITS: usize = (NS - 256) * 8;
const MAP_BITS: usize = (NS - 20) * 8;
pub fn u16be(bytes: &[u8], off: usize) -> u16 {
    u16::from_be_bytes(bytes[off..off + 2].try_into().unwrap())
}
pub fn p16(bytes: &mut [u8], off: usize, n: u16) {
    bytes[off..off + 2].copy_from_slice(&n.to_be_bytes());
}
pub fn p32(bytes: &mut [u8], off: usize, n: u32) {
    bytes[off..off + 4].copy_from_slice(&n.to_be_bytes());
}
pub fn record(cnid: u32, name: &str, data: &[u8]) -> Vec<u8> {
    let name: Vec<_> = name.encode_utf16().collect();
    assert!(name.len() <= 127);
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&(12 + 2 * name.len() as u16).to_be_bytes());
    bytes.extend_from_slice(&0u16.to_be_bytes());
    bytes.extend_from_slice(&cnid.to_be_bytes());
    bytes.extend_from_slice(&0u32.to_be_bytes());
    bytes.extend_from_slice(&(name.len() as u16).to_be_bytes());
    for unit in name {
        bytes.extend_from_slice(&unit.to_be_bytes());
    }
    bytes.extend_from_slice(&0x10u32.to_be_bytes());
    bytes.extend_from_slice(&[0; 8]);
    bytes.extend_from_slice(&(data.len() as u32).to_be_bytes());
    bytes.extend_from_slice(data);
    if bytes.len() % 2 == 1 {
        bytes.push(0xa5);
    }
    bytes
}
pub fn order(record: &[u8]) -> (u32, Vec<u16>, u32) {
    let name = (0..u16be(record, 12) as usize)
        .map(|i| u16be(record, 14 + 2 * i))
        .collect();
    (volume::be32(record, 4), name, volume::be32(record, 8))
}
pub fn records(node: &[u8]) -> Vec<&[u8]> {
    let count = u16be(node, 10) as usize;
    let offsets: Vec<_> = (0..=count)
        .map(|i| u16be(node, NS - 2 * (i + 1)) as usize)
        .collect();
    assert!(offsets[0] >= 14);
    assert!(offsets[count] <= NS - 2 * (count + 1));
    offsets
        .windows(2)
        .map(|p| {
            assert!(p[0] < p[1] && p[0] % 2 == 0);
            &node[p[0]..p[1]]
        })
        .collect()
}
fn node(raw: &[Vec<u8>], height: u8, before: u32, after: u32) -> Vec<u8> {
    let mut bytes = vec![0; NS];
    p32(&mut bytes, 0, after);
    p32(&mut bytes, 4, before);
    bytes[8] = if height == 1 { 0xff } else { 0 };
    bytes[9] = height;
    p16(&mut bytes, 10, raw.len() as u16);
    let mut off = 14;
    for (i, record) in raw.iter().enumerate() {
        p16(&mut bytes, NS - 2 * (i + 1), off as u16);
        bytes[off..off + record.len()].copy_from_slice(record);
        off += record.len();
    }
    assert!(off <= NS - 2 * (raw.len() + 1));
    p16(&mut bytes, NS - 2 * (raw.len() + 1), off as u16);
    bytes
}
pub fn install(
    bytes: &mut [u8],
    mut raw: Vec<Vec<u8>>,
    capacity: u32,
    fanout: usize,
    sparse: bool,
) -> usize {
    raw.sort_by_key(|r| order(r));
    assert!(raw.windows(2).all(|p| order(&p[0]) < order(&p[1])));
    let count = raw.len() as u32;
    let maps: Vec<u32> = (HEADER_BITS..capacity as usize)
        .step_by(MAP_BITS)
        .map(|id| id as u32)
        .collect();
    let map_ids: BTreeSet<_> = maps.iter().copied().chain([0]).collect();
    let available: Vec<_> = (1..capacity).filter(|id| !map_ids.contains(id)).collect();
    let mut ids = if sparse {
        available.into_iter().rev().collect::<Vec<_>>()
    } else {
        available
    };
    let mut ids = ids.drain(..);
    let mut nodes = BTreeMap::new();
    let mut height = 1;
    let mut first = 0;
    let mut last = 0;
    let root;
    loop {
        // Deliberately underfilled leaves/index nodes exercise sparse legal trees.
        let chunks: Vec<_> = raw.chunks(if height == 1 { 1 } else { fanout }).collect();
        let level: Vec<_> = (0..chunks.len()).map(|_| ids.next().unwrap()).collect();
        if height == 1 {
            first = level[0];
            last = *level.last().unwrap();
        }
        let mut next = Vec::new();
        for (i, chunk) in chunks.iter().enumerate() {
            nodes.insert(
                level[i],
                node(
                    chunk,
                    height,
                    i.checked_sub(1).map_or(0, |p| level[p]),
                    level.get(i + 1).copied().unwrap_or(0),
                ),
            );
            let length = 2 + u16be(&chunk[0], 0) as usize;
            let mut index = chunk[0][..length].to_vec();
            index.extend_from_slice(&level[i].to_be_bytes());
            next.push(index);
        }
        if level.len() == 1 {
            root = level[0];
            break;
        }
        raw = next;
        height += 1;
    }
    let mut bitmap = vec![0; (NS - 256) + maps.len() * (NS - 20)];
    for id in map_ids.iter().chain(nodes.keys()) {
        bitmap[*id as usize / 8] |= 0x80 >> (*id % 8);
    }
    let mut header = vec![0; NS];
    p32(&mut header, 0, maps.first().copied().unwrap_or(0));
    header[8] = 1;
    p16(&mut header, 10, 3);
    p16(&mut header, 14, height as u16);
    for (off, n) in [
        (16, root),
        (20, count),
        (24, first),
        (28, last),
        (36, capacity),
        (40, capacity - map_ids.len() as u32 - nodes.len() as u32),
        (46, NS as u32),
        (52, 6),
    ] {
        p32(&mut header, off, n);
    }
    p16(&mut header, 32, NS as u16);
    p16(&mut header, 34, 266);
    header[51] = 0xbc;
    // Reserved/user bytes must survive deletion, not get regenerated.
    header[140..144].copy_from_slice(b"USER");
    for (i, off) in [14, 120, 248, NS - 8].into_iter().enumerate() {
        p16(&mut header, NS - 2 * (i + 1), off as u16);
    }
    header[248..NS - 8].copy_from_slice(&bitmap[..NS - 256]);
    nodes.insert(0, header);
    let mut start = NS - 256;
    for (i, id) in maps.iter().enumerate() {
        let mut map = vec![0; NS];
        p32(&mut map, 0, maps.get(i + 1).copied().unwrap_or(0));
        map[8] = 2;
        p16(&mut map, 10, 1);
        p16(&mut map, NS - 2, 14);
        p16(&mut map, NS - 4, (NS - 6) as u16);
        map[14..NS - 6].copy_from_slice(&bitmap[start..start + NS - 20]);
        start += NS - 20;
        nodes.insert(*id, map);
    }
    let bs = volume::be32(bytes, 1064) as usize;
    let blocks = (capacity as usize * NS).div_ceil(bs) as u32;
    let total = volume::be32(bytes, 1068);
    let allocation = volume::be32(bytes, 1152) as usize * bs;
    let mut run = 0;
    let mut block = 0;
    for id in 1..total - 1 {
        if bytes[allocation + id as usize / 8] & (0x80 >> (id % 8)) == 0 {
            run += 1;
        } else {
            run = 0;
        }
        if run == blocks {
            block = id + 1 - blocks;
            break;
        }
    }
    assert!(block > 0, "fixture reservation does not fit");
    for id in block..block + blocks {
        bytes[allocation + id as usize / 8] |= 0x80 >> (id % 8);
    }
    let free = volume::be32(bytes, 1072);
    p32(bytes, 1072, free - blocks);
    let fork = 1376;
    bytes[fork..fork + 80].fill(0);
    bytes[fork..fork + 8].copy_from_slice(&(capacity as u64 * NS as u64).to_be_bytes());
    p32(bytes, fork + 8, bs as u32);
    p32(bytes, fork + 12, blocks);
    p32(bytes, fork + 16, block);
    p32(bytes, fork + 20, blocks);
    let tree = block as usize * bs;
    for (id, node) in nodes {
        bytes[tree + id as usize * NS..tree + (id as usize + 1) * NS].copy_from_slice(&node);
    }
    let header = bytes[1024..1536].to_vec();
    let alternate = bytes.len() - 1024;
    bytes[alternate..alternate + 512].copy_from_slice(&header);
    tree
}
pub fn audit(bytes: &[u8]) -> Vec<Vec<u8>> {
    audit_reserved(bytes, b"USER")
}
#[allow(dead_code)]
pub fn audit_initialized(bytes: &[u8]) -> Vec<Vec<u8>> {
    audit_reserved(bytes, &[0; 4])
}
fn audit_reserved(bytes: &[u8], reserved: &[u8; 4]) -> Vec<Vec<u8>> {
    let bs = volume::be32(bytes, 1064) as usize;
    let tree = volume::be32(bytes, 1392) as usize * bs;
    let total = volume::be32(bytes, tree + 36);
    let get = |id: u32| &bytes[tree + id as usize * NS..tree + (id as usize + 1) * NS];
    let mut visited = BTreeSet::from([0]);
    let mut bitmap = records(get(0))[2].to_vec();
    let mut map = volume::be32(get(0), 0);
    while map != 0 {
        assert!(map < total && visited.insert(map));
        let node = get(map);
        assert_eq!(node[8], 2);
        bitmap.extend_from_slice(records(node)[0]);
        map = volume::be32(node, 0);
    }
    let root = volume::be32(get(0), 16);
    let mut raw = Vec::new();
    let mut levels = BTreeMap::new();
    fn walk<'a>(
        get: &impl Fn(u32) -> &'a [u8],
        id: u32,
        height: u8,
        visited: &mut BTreeSet<u32>,
        levels: &mut BTreeMap<u8, Vec<u32>>,
        raw: &mut Vec<Vec<u8>>,
    ) -> Vec<u8> {
        assert!(id > 0 && visited.insert(id));
        let node = get(id);
        assert_eq!(node[9], height);
        assert_eq!(node[8], if height == 1 { 0xff } else { 0 });
        levels.entry(height).or_default().push(id);
        let records = records(node);
        assert!(records.windows(2).all(|p| order(p[0]) < order(p[1])));
        for record in &records {
            let length = 2 + u16be(record, 0) as usize;
            if height == 1 {
                raw.push(record.to_vec());
            } else {
                assert_eq!(
                    walk(
                        get,
                        volume::be32(record, length),
                        height - 1,
                        visited,
                        levels,
                        raw
                    ),
                    record[..length]
                );
            }
        }
        let first = records[0];
        first[..2 + u16be(first, 0) as usize].to_vec()
    }
    if root != 0 {
        walk(
            &get,
            root,
            u16be(get(0), 14) as u8,
            &mut visited,
            &mut levels,
            &mut raw,
        );
    } else {
        assert_eq!(u16be(get(0), 14), 0);
    }
    assert!(raw.windows(2).all(|p| order(&p[0]) < order(&p[1])));
    assert_eq!(raw.len() as u32, volume::be32(get(0), 20));
    for level in levels.values() {
        for (i, id) in level.iter().enumerate() {
            assert_eq!(
                volume::be32(get(*id), 0),
                level.get(i + 1).copied().unwrap_or(0)
            );
            assert_eq!(
                volume::be32(get(*id), 4),
                i.checked_sub(1).map_or(0, |p| level[p])
            );
        }
    }
    let leaves = levels.get(&1);
    assert_eq!(
        volume::be32(get(0), 24),
        leaves.and_then(|v| v.first()).copied().unwrap_or(0)
    );
    assert_eq!(
        volume::be32(get(0), 28),
        leaves.and_then(|v| v.last()).copied().unwrap_or(0)
    );
    for id in 0..total {
        assert_eq!(
            bitmap[id as usize / 8] & (0x80 >> (id % 8)) != 0,
            visited.contains(&id)
        );
    }
    assert_eq!(total - visited.len() as u32, volume::be32(get(0), 40));
    assert_eq!(&get(0)[140..144], reserved);
    raw
}
