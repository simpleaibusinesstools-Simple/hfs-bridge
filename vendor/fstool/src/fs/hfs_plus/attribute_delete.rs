//! Checked attribute-record mutations in multi-level attribute trees.
//! Validate the entire live tree before planning; repack retained raw records
//! within its existing reservation, or relocate a complete grown tree using
//! the caller's checked copy-on-write allocation. Only changed nodes enter the
//! metadata batch when the tree remains in place.
//! Small-value editing refuses fork-backed targets; complete-chain replacement
//! requires caller-validated ownership and defers retirement until publication.
use super::{
    attributes::{AttrKey, AttrRecord},
    btree::{BTreeHeader, ForkReader, NodeDescriptor, read_node, record_bytes, record_offsets},
    catalog::UniStr,
    volume_header::{ExtentDescriptor, ForkData},
};
use crate::{Result, block::BlockDevice};
use std::{
    cmp::Ordering,
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

#[derive(Clone)]
pub(super) struct Plan {
    pub node_size: u32,
    pub nodes: BTreeMap<u32, Vec<u8>>,
    pub allocation: Option<Allocation>,
    pub retired: Vec<ExtentDescriptor>,
    /// Complete replacement fork, including zeroed free nodes. The caller must
    /// reserve fresh blocks and make this durable before publishing the fork.
    pub grown_tree: Option<Vec<u8>>,
}
/// Allocation is planned on a private bitmap. Payload remains staged until
/// flush; no read-only preflight writes to the device or modifies the writer.
#[derive(Clone)]
pub(super) struct Allocation {
    pub bitmap: Vec<u8>,
    pub free_blocks: u32,
    pub next_alloc: u32,
    pub attributes_file: ForkData,
    // Candidate payloads are immutable. Cloning a publication plan must not
    // duplicate every large attribute before staging and again during flush.
    // The shared bytes survive until the last plan owner has finished with them.
    pub payloads: Vec<(ExtentDescriptor, Arc<[u8]>)>,
}
struct MapPart {
    id: u32,
    offset: usize,
    start: usize,
    length: usize,
}
struct Tree {
    header: BTreeHeader,
    size: usize,
    bitmap: Vec<u8>,
    maps: Vec<MapPart>,
    originals: BTreeMap<u32, Vec<u8>>,
    visited: BTreeSet<u32>,
    levels: BTreeMap<u8, Vec<u32>>,
    records: Vec<Vec<u8>>,
    previous: Option<AttrKey>,
    removed: u32,
    leaf_records: u32,
}
fn invalid(message: &str) -> crate::Error {
    crate::Error::InvalidImage(format!("hfs+ attribute deletion: {message}"))
}
fn unsupported(message: &str) -> crate::Error {
    crate::Error::Unsupported(format!("hfs+ attribute deletion: {message}"))
}
fn offsets(node: &[u8], count: u16) -> Result<Vec<u16>> {
    let offsets = record_offsets(node, count)?;
    let boundary = node.len() - 2 * (usize::from(count) + 1);
    if usize::from(offsets[usize::from(count)]) > boundary
        || offsets.windows(2).any(|p| p[0] >= p[1] || p[0] % 2 != 0)
        || offsets.last().unwrap() % 2 != 0
    {
        return Err(invalid("overlapping, empty or unaligned records"));
    }
    Ok(offsets)
}
fn key(record: &[u8]) -> Result<AttrKey> {
    let key = AttrKey::decode(record)?;
    if record[2..4] != [0, 0]
        || key.file_id == 0
        || key.name.code_units.is_empty()
        || key.encoded_len + 4 > record.len()
    {
        return Err(invalid("attribute key/body"));
    }
    Ok(key)
}
impl Tree {
    fn used(&self, id: u32) -> bool {
        self.bitmap[id as usize / 8] & (0x80 >> (id & 7)) != 0
    }
    fn walk(
        &mut self,
        dev: &mut dyn BlockDevice,
        reader: &ForkReader,
        id: u32,
        height: u8,
        deleted: &BTreeSet<u32>,
    ) -> Result<Vec<u8>> {
        if id == 0 || id >= self.header.total_nodes || !self.used(id) || !self.visited.insert(id) {
            return Err(invalid("free, cyclic, shared or out-of-range child"));
        }
        let node = read_node(dev, reader, id, self.size as u32)?;
        let desc = NodeDescriptor::decode(&node)?;
        if desc.height != height
            || desc.kind != if height == 1 { -1 } else { 0 }
            || desc.num_records == 0
        {
            return Err(invalid("child descriptor/height"));
        }
        let offsets = offsets(&node, desc.num_records)?;
        self.levels.entry(height).or_default().push(id);
        let mut prior: Option<AttrKey> = None;
        let mut first = Vec::new();
        for index in 0..usize::from(desc.num_records) {
            let record = record_bytes(&node, &offsets, index);
            let decoded = key(record)?;
            if prior
                .as_ref()
                .is_some_and(|p| p.compare(&decoded, true) != Ordering::Less)
            {
                return Err(invalid("node key order"));
            }
            if index == 0 {
                first = record[..decoded.encoded_len].to_vec();
            }
            if height == 1 {
                if self
                    .previous
                    .as_ref()
                    .is_some_and(|p| p.compare(&decoded, true) != Ordering::Less)
                {
                    return Err(invalid("global leaf key order"));
                }
                self.leaf_records = self
                    .leaf_records
                    .checked_add(1)
                    .ok_or_else(|| invalid("record count overflow"))?;
                if deleted.contains(&decoded.file_id) {
                    if decoded.start_block != 0
                        || !matches!(
                            AttrRecord::decode(&record[decoded.encoded_len..])?,
                            AttrRecord::Inline { .. }
                        )
                    {
                        return Err(unsupported(
                            "fork-backed target values are not yet supported",
                        ));
                    }
                    self.removed += 1;
                } else {
                    // Includes unrecognized non-target bodies: their bytes are opaque.
                    self.records.push(record.to_vec());
                }
                self.previous = Some(decoded.clone());
            } else {
                if record.len() != decoded.encoded_len + 4 {
                    return Err(invalid("index pointer length"));
                }
                let child = u32::from_be_bytes(record[decoded.encoded_len..].try_into().unwrap());
                if self.walk(dev, reader, child, height - 1, deleted)?
                    != record[..decoded.encoded_len]
                {
                    return Err(invalid("index key differs from child's first key"));
                }
            }
            prior = Some(decoded);
        }
        self.originals.insert(id, node);
        Ok(first)
    }
    fn validate(&self) -> Result<()> {
        if self.leaf_records != self.header.leaf_records {
            return Err(invalid("leaf record count"));
        }
        for ids in self.levels.values() {
            for (index, id) in ids.iter().enumerate() {
                let desc = NodeDescriptor::decode(&self.originals[id])?;
                if desc.b_link != index.checked_sub(1).map_or(0, |i| ids[i])
                    || desc.f_link != ids.get(index + 1).copied().unwrap_or(0)
                {
                    return Err(invalid("sibling chain"));
                }
            }
        }
        let leaves = self.levels.get(&1);
        if self.header.first_leaf_node != leaves.and_then(|v| v.first()).copied().unwrap_or(0)
            || self.header.last_leaf_node != leaves.and_then(|v| v.last()).copied().unwrap_or(0)
            || (0..self.header.total_nodes).any(|id| self.used(id) != self.visited.contains(&id))
        {
            return Err(invalid("leaf endpoints or unreachable allocated node"));
        }
        Ok(())
    }
    fn repack(self) -> Result<Plan> {
        self.repack_with_growth(None)
    }
    fn repack_with_growth(mut self, capacity_limit: Option<u32>) -> Result<Plan> {
        let map_ids: BTreeSet<_> = self.maps.iter().map(|m| m.id).collect();
        let old_total = self.header.total_nodes;
        // Existing map records are retained verbatim except their bitmap.
        // Adding map records is a separate operation; refuse that geometry
        // before allocating or writing anything.
        let capacity = capacity_limit.map_or(old_total, |limit| {
            limit.min(u32::try_from(self.bitmap.len() * 8).unwrap_or(u32::MAX))
        });
        let mut ids = (1..capacity).filter(|id| !map_ids.contains(id));
        let mut nodes = BTreeMap::new();
        let mut height = 1u8;
        let mut records = std::mem::take(&mut self.records);
        let mut root = 0;
        let mut depth = 0;
        let mut first_leaf = 0;
        let mut last_leaf = 0;
        let retained_count = self.leaf_records - self.removed;
        while !records.is_empty() {
            let packed = pack(&records, self.size, height)?;
            if height > 1 && packed.len() >= records.len() && packed.len() > 1 {
                return Err(invalid("index packing did not reduce the level"));
            }
            let allocated: Vec<u32> = (0..packed.len())
                .map(|_| {
                    ids.next().ok_or_else(|| {
                        unsupported("repacked tree exceeds its existing node reservation")
                    })
                })
                .collect::<Result<_>>()?;
            if height == 1 {
                first_leaf = allocated[0];
                last_leaf = *allocated.last().unwrap();
            }
            let mut next = Vec::new();
            for (index, (mut node, mut first_key)) in packed.into_iter().enumerate() {
                let id = allocated[index];
                node[..4]
                    .copy_from_slice(&allocated.get(index + 1).copied().unwrap_or(0).to_be_bytes());
                node[4..8].copy_from_slice(
                    &index
                        .checked_sub(1)
                        .map_or(0, |i| allocated[i])
                        .to_be_bytes(),
                );
                if let Some(original) = self.originals.get(&id) {
                    node[12..14].copy_from_slice(&original[12..14]);
                }
                first_key.extend_from_slice(&id.to_be_bytes());
                next.push(first_key);
                nodes.insert(id, node);
            }
            if allocated.len() == 1 {
                root = allocated[0];
                depth = u16::from(height);
                break;
            }
            records = next;
            height = height
                .checked_add(1)
                .ok_or_else(|| invalid("tree depth overflow"))?;
        }
        let needed = map_ids.iter().chain(nodes.keys()).max().unwrap() + 1;
        let grown = needed > old_total;
        if grown {
            self.header.total_nodes = old_total.saturating_mul(2).max(needed).min(capacity);
        }
        let mut bitmap = vec![0; self.bitmap.len()];
        for id in map_ids.iter().chain(nodes.keys()) {
            bitmap[*id as usize / 8] |= 0x80 >> (*id & 7);
        }
        let free = self.header.total_nodes - (map_ids.len() + nodes.len()) as u32;
        // A retired B-tree node must be erased in the same metadata commit as
        // the map bit that frees it. Leaving its old descriptor/records behind
        // fails macOS fsck even though ordinary lookup no longer visits it.
        for id in &self.visited {
            if !map_ids.contains(id) && !nodes.contains_key(id) {
                nodes.insert(*id, vec![0; self.size]);
            }
        }
        let header = self.originals.get_mut(&0).unwrap();
        header[14..16].copy_from_slice(&depth.to_be_bytes());
        for (off, value) in [
            (16, root),
            (20, retained_count),
            (24, first_leaf),
            (28, last_leaf),
            (36, self.header.total_nodes),
            (40, free),
        ] {
            header[off..off + 4].copy_from_slice(&value.to_be_bytes());
        }
        for part in &self.maps {
            let mut bytes = self.originals[&part.id].clone();
            bytes[part.offset..part.offset + part.length]
                .copy_from_slice(&bitmap[part.start..part.start + part.length]);
            nodes.insert(part.id, bytes);
        }
        let grown_tree = if grown {
            let length = (self.header.total_nodes as usize)
                .checked_mul(self.size)
                .ok_or_else(|| unsupported("grown attribute tree length overflow"))?;
            let mut bytes = vec![0; length];
            for (id, node) in &nodes {
                let start = *id as usize * self.size;
                bytes[start..start + self.size].copy_from_slice(node);
            }
            nodes.clear();
            Some(bytes)
        } else {
            // Header is always included; the journal filters unchanged sectors.
            nodes.retain(|id, bytes| *id == 0 || self.originals.get(id) != Some(bytes));
            None
        };
        Ok(Plan {
            node_size: self.size as u32,
            nodes,
            allocation: None,
            retired: Vec::new(),
            grown_tree,
        })
    }
}
fn pack(records: &[Vec<u8>], size: usize, height: u8) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
    let mut result = Vec::new();
    let mut start = 0;
    while start < records.len() {
        let mut end = start;
        let mut used = 16;
        while end < records.len() && used + records[end].len() + 2 <= size {
            used += records[end].len() + 2;
            end += 1;
        }
        if end == start {
            return Err(invalid("record does not fit a node"));
        }
        let mut node = vec![0; size];
        node[8] = if height == 1 { 0xff } else { 0 };
        node[9] = height;
        node[10..12].copy_from_slice(&((end - start) as u16).to_be_bytes());
        let mut position = 14;
        for (index, record) in records[start..end].iter().enumerate() {
            let slot = size - 2 * (index + 1);
            node[slot..slot + 2].copy_from_slice(&(position as u16).to_be_bytes());
            node[position..position + record.len()].copy_from_slice(record);
            position += record.len();
        }
        let slot = size - 2 * (end - start + 1);
        node[slot..slot + 2].copy_from_slice(&(position as u16).to_be_bytes());
        let key_length = AttrKey::decode(&records[start])?.encoded_len;
        result.push((node, records[start][..key_length].to_vec()));
        start = end;
    }
    Ok(result)
}
pub(super) fn plan(
    dev: &mut dyn BlockDevice,
    fork: &ForkData,
    block_size: u32,
    deleted: &BTreeSet<u32>,
) -> Result<Option<Plan>> {
    if deleted.is_empty() || fork.total_blocks == 0 {
        return Ok(None);
    }
    let mut tree = load(dev, fork, block_size, &BTreeSet::new())?;
    let total_blocks = u32::try_from(dev.total_size() / u64::from(block_size))
        .map_err(|_| invalid("volume block count overflow"))?;
    let retired = remove_records(&mut tree, block_size, total_blocks, deleted)?;
    if tree.removed == 0 {
        return Ok(None);
    }
    let mut plan = tree.repack()?;
    plan.retired = retired;
    Ok(Some(plan))
}
fn remove_records(
    tree: &mut Tree,
    block_size: u32,
    total_blocks: u32,
    deleted: &BTreeSet<u32>,
) -> Result<Vec<ExtentDescriptor>> {
    let mut retired = Vec::new();
    let mut cursor = 0;
    while cursor < tree.records.len() {
        let primary = key(&tree.records[cursor])?;
        let mut end = cursor + 1;
        while end < tree.records.len() {
            let next = key(&tree.records[end])?;
            if next.file_id != primary.file_id || next.name.code_units != primary.name.code_units {
                break;
            }
            end += 1;
        }
        if deleted.contains(&primary.file_id) {
            let group = tree.records[cursor..end]
                .iter()
                .map(Vec::as_slice)
                .collect::<Vec<_>>();
            if let super::attribute_value::Value::Fork(reader) =
                super::attribute_value::decode(&group, block_size, total_blocks)?
            {
                retired.extend(reader.extents);
            }
        }
        cursor = end;
    }
    let mut retained = Vec::new();
    for record in std::mem::take(&mut tree.records) {
        if deleted.contains(&key(&record)?.file_id) {
            tree.removed += 1;
        } else {
            retained.push(record);
        }
    }
    tree.records = retained;
    Ok(retired)
}
fn load(
    dev: &mut dyn BlockDevice,
    fork: &ForkData,
    block_size: u32,
    deleted: &BTreeSet<u32>,
) -> Result<Tree> {
    let reader = ForkReader::from_inline(fork, block_size, "attribute deletion")?;
    let mut bootstrap = [0; 512];
    reader.read(dev, 0, &mut bootstrap)?;
    let header = BTreeHeader::decode(&bootstrap[14..120])?;
    let size = usize::from(header.node_size);
    if !(4096..=32768).contains(&size)
        || !matches!(header.key_compare_type, 0 | 0xbc)
        || header.max_key_length != 266
        || header.attributes & 6 != 6
    {
        return Err(unsupported(
            "unsupported attribute tree geometry/comparison",
        ));
    }
    if header.total_nodes == 0
        || header.free_nodes >= header.total_nodes
        || header.tree_depth > 255
        || u64::from(header.total_nodes) * size as u64 > fork.logical_size
        || fork.logical_size > u64::from(fork.total_blocks) * u64::from(block_size)
        || fork.logical_size > dev.total_size()
    {
        return Err(invalid("tree capacity/depth"));
    }
    let node = read_node(dev, &reader, 0, size as u32)?;
    let desc = NodeDescriptor::decode(&node)?;
    if desc.kind != 1 || desc.height != 0 || desc.b_link != 0 || desc.num_records != 3 {
        return Err(invalid("header descriptor"));
    }
    let offs = offsets(&node, 3)?;
    if offs[0] != 14 || usize::from(offs[1]) < 120 || usize::from(offs[3] - offs[2]) != size - 256 {
        return Err(invalid("header records/map size"));
    }
    let bitmap = record_bytes(&node, &offs, 2).to_vec();
    let mut tree = Tree {
        header,
        size,
        maps: vec![MapPart {
            id: 0,
            offset: usize::from(offs[2]),
            start: 0,
            length: bitmap.len(),
        }],
        bitmap,
        originals: BTreeMap::from([(0, node)]),
        visited: BTreeSet::from([0]),
        levels: BTreeMap::new(),
        records: Vec::new(),
        previous: None,
        removed: 0,
        leaf_records: 0,
    };
    let mut id = desc.f_link;
    while id != 0 {
        if id >= header.total_nodes || !tree.visited.insert(id) {
            return Err(invalid("out-of-range or cyclic map chain"));
        }
        let node = read_node(dev, &reader, id, size as u32)?;
        let desc = NodeDescriptor::decode(&node)?;
        if desc.kind != 2 || desc.height != 0 || desc.b_link != 0 || desc.num_records != 1 {
            return Err(invalid("map descriptor"));
        }
        let offs = offsets(&node, 1)?;
        let record = record_bytes(&node, &offs, 0);
        if record.len() != size - 20 {
            return Err(invalid("map record size"));
        }
        tree.maps.push(MapPart {
            id,
            offset: usize::from(offs[0]),
            start: tree.bitmap.len(),
            length: record.len(),
        });
        tree.bitmap.extend_from_slice(record);
        tree.originals.insert(id, node);
        id = desc.f_link;
    }
    if tree.bitmap.len() as u64 * 8 < u64::from(header.total_nodes)
        || tree.visited.iter().any(|&id| !tree.used(id))
        || (0..header.total_nodes).filter(|&id| !tree.used(id)).count()
            != header.free_nodes as usize
        || (header.total_nodes as usize..tree.bitmap.len() * 8)
            .any(|id| tree.bitmap[id / 8] & (0x80 >> (id & 7)) != 0)
    {
        return Err(invalid("node allocation map/free count"));
    }
    if header.root_node == 0 {
        if header.tree_depth != 0
            || header.leaf_records != 0
            || header.first_leaf_node != 0
            || header.last_leaf_node != 0
        {
            return Err(invalid("empty tree"));
        }
    } else {
        if header.tree_depth == 0 {
            return Err(invalid("zero-depth populated tree"));
        }
        tree.walk(
            dev,
            &reader,
            header.root_node,
            header.tree_depth as u8,
            deleted,
        )?;
    }
    tree.validate()?;
    Ok(tree)
}

pub(super) fn inline_record(cnid: u32, name: &str, value: &[u8]) -> Result<Vec<u8>> {
    let units = name.encode_utf16().collect::<Vec<_>>();
    if cnid < 2 || units.is_empty() || units.len() > 127 || units.contains(&0) || value.len() > 3802
    {
        return Err(crate::Error::InvalidArgument(
            "hfs+ inline attribute name/value bounds".into(),
        ));
    }
    let mut record = Vec::with_capacity(30 + units.len() * 2 + value.len() + 1);
    record.extend_from_slice(&((12 + units.len() * 2) as u16).to_be_bytes());
    record.extend_from_slice(&0u16.to_be_bytes());
    record.extend_from_slice(&cnid.to_be_bytes());
    record.extend_from_slice(&0u32.to_be_bytes());
    record.extend_from_slice(&(units.len() as u16).to_be_bytes());
    for unit in units {
        record.extend_from_slice(&unit.to_be_bytes());
    }
    record.extend_from_slice(&0x10u32.to_be_bytes());
    record.extend_from_slice(&[0; 8]);
    record.extend_from_slice(&(value.len() as u32).to_be_bytes());
    record.extend_from_slice(value);
    if record.len() % 2 != 0 {
        record.push(0);
    }
    Ok(record)
}
fn edit_records(tree: &mut Tree, cnid: u32, name: &str, value: Option<&[u8]>) -> Result<bool> {
    // The same encoder validates names even for removal. Attribute names use
    // exact binary UTF-16; catalog normalization/case folding is not applied.
    let replacement = inline_record(cnid, name, value.unwrap_or(&[]))?;
    if replacement.len() + 18 > tree.size {
        return Err(crate::Error::InvalidArgument(
            "hfs+ inline attribute exceeds node capacity".into(),
        ));
    }
    let target = UniStr {
        code_units: name.encode_utf16().collect(),
    };
    let mut records = Vec::with_capacity(tree.records.len() + usize::from(value.is_some()));
    for record in std::mem::take(&mut tree.records) {
        let decoded = key(&record)?;
        if decoded.file_id == cnid && decoded.name.code_units == target.code_units {
            if decoded.start_block != 0
                || !matches!(
                    AttrRecord::decode(&record[decoded.encoded_len..])?,
                    AttrRecord::Inline { .. }
                )
            {
                return Err(unsupported(
                    "fork-backed target values are not yet supported",
                ));
            }
        } else {
            records.push(record);
        }
    }
    if value.is_some() {
        records.push(replacement);
    }
    let mut ordered = records
        .into_iter()
        .map(|r| Ok((key(&r)?, r)))
        .collect::<Result<Vec<_>>>()?;
    ordered.sort_by(|(a, _), (b, _)| a.compare(b, true));
    if ordered
        .windows(2)
        .any(|p| p[0].0.compare(&p[1].0, true) != Ordering::Less)
    {
        return Err(invalid("duplicate edited attribute keys"));
    }
    let has_attributes = ordered.iter().any(|(key, _)| key.file_id == cnid);
    tree.records = ordered.into_iter().map(|(_, r)| r).collect();
    tree.leaf_records = u32::try_from(tree.records.len())
        .map_err(|_| invalid("attribute record count overflow"))?;
    tree.removed = 0;
    Ok(has_attributes)
}
pub(super) fn plan_edits(
    dev: &mut dyn BlockDevice,
    fork: &ForkData,
    block_size: u32,
    cnid: u32,
    changes: &[(&str, Option<&[u8]>)],
) -> Result<(Plan, bool)> {
    let mut tree = load(dev, fork, block_size, &BTreeSet::new())?;
    let mut has_attributes = false;
    for &(name, value) in changes {
        has_attributes = edit_records(&mut tree, cnid, name, value)?;
    }
    Ok((tree.repack()?, has_attributes))
}
pub(super) fn names(
    dev: &mut dyn BlockDevice,
    fork: &ForkData,
    block_size: u32,
    cnid: u32,
) -> Result<Vec<String>> {
    if fork.total_blocks == 0 {
        return Ok(Vec::new());
    }
    let tree = load(dev, fork, block_size, &BTreeSet::new())?;
    let mut names = Vec::new();
    for record in tree.records {
        let key = key(&record)?;
        if key.file_id == cnid && key.start_block == 0 {
            names.push(
                String::from_utf16(&key.name.code_units)
                    .map_err(|_| unsupported("attribute name cannot round-trip through UTF-16"))?,
            );
        }
    }
    Ok(names)
}
/// Immutable raw records from the same full-tree validation used by edits.
pub(super) fn records(
    dev: &mut dyn BlockDevice,
    fork: &ForkData,
    block_size: u32,
) -> Result<Vec<Vec<u8>>> {
    Ok(records_with_fixed_support(dev, fork, block_size)?.0)
}

pub(super) fn records_with_fixed_support(
    dev: &mut dyn BlockDevice,
    fork: &ForkData,
    block_size: u32,
) -> Result<(Vec<Vec<u8>>, bool)> {
    if fork.total_blocks == 0 {
        return Ok((Vec::new(), true));
    }
    let tree = load(dev, fork, block_size, &BTreeSet::new())?;
    // Optional private lookup retains its stricter geometry/depth contract,
    // even though complete tree validation supports deeper public trees.
    let fixed_supported = tree.header.tree_depth <= 16 && tree.header.node_size.is_power_of_two();
    Ok((tree.records, fixed_supported))
}
fn new_tree() -> Result<Tree> {
    const SIZE: usize = 4096;
    const CAPACITY: u32 = 8;
    let mut header = vec![0; SIZE];
    header[8] = 1;
    header[10..12].copy_from_slice(&3u16.to_be_bytes());
    header[32..34].copy_from_slice(&(SIZE as u16).to_be_bytes());
    header[34..36].copy_from_slice(&266u16.to_be_bytes());
    header[36..40].copy_from_slice(&CAPACITY.to_be_bytes());
    header[40..44].copy_from_slice(&(CAPACITY - 1).to_be_bytes());
    header[46..50].copy_from_slice(&((SIZE as u32) * CAPACITY).to_be_bytes());
    // The catalog comparison selector is unused for Apple attribute trees.
    header[51] = 0;
    header[52..56].copy_from_slice(&6u32.to_be_bytes());
    for (slot, offset) in [14u16, 120, 248, (SIZE - 8) as u16].into_iter().enumerate() {
        header[SIZE - 2 * (slot + 1)..SIZE - 2 * slot].copy_from_slice(&offset.to_be_bytes());
    }
    header[248] = 0x80;
    Ok(Tree {
        header: BTreeHeader::decode(&header[14..120])?,
        size: SIZE,
        maps: vec![MapPart {
            id: 0,
            offset: 248,
            start: 0,
            length: SIZE - 256,
        }],
        bitmap: header[248..SIZE - 8].to_vec(),
        originals: BTreeMap::from([(0, header)]),
        visited: BTreeSet::from([0]),
        levels: BTreeMap::new(),
        records: Vec::new(),
        previous: None,
        removed: 0,
        leaf_records: 0,
    })
}
pub(super) fn plan_new_edits(cnid: u32, changes: &[(&str, Option<&[u8]>)]) -> Result<(Plan, bool)> {
    const SIZE: usize = 4096;
    const CAPACITY: u32 = 8;
    let mut tree = new_tree()?;
    let mut has_attributes = false;
    for &(name, value) in changes {
        has_attributes = edit_records(&mut tree, cnid, name, value)?;
    }
    let mut plan = tree.repack()?;
    for node in 0..CAPACITY {
        plan.nodes.entry(node).or_insert_with(|| vec![0; SIZE]);
    }
    Ok((plan, has_attributes))
}

/// One tree publication for small values on multiple catalog identities and
/// already-preflighted file deletions. Target fork values remain refused.
pub(super) fn plan_small_batch(
    dev: &mut dyn BlockDevice,
    fork: &ForkData,
    block_size: u32,
    deleted: &BTreeSet<u32>,
    changes: &[(u32, &str, Option<&[u8]>)],
) -> Result<(Plan, BTreeMap<u32, bool>)> {
    let new = fork.total_blocks == 0;
    let mut tree = if new {
        new_tree()?
    } else {
        load(dev, fork, block_size, &BTreeSet::new())?
    };
    let total_blocks = u32::try_from(dev.total_size() / u64::from(block_size))
        .map_err(|_| invalid("volume block count overflow"))?;
    let retired = remove_records(&mut tree, block_size, total_blocks, deleted)?;
    let mut flags = BTreeMap::new();
    for &(cnid, name, value) in changes {
        if deleted.contains(&cnid) {
            return Err(invalid("attribute batch targets a deleted identity"));
        }
        flags.insert(cnid, edit_records(&mut tree, cnid, name, value)?);
    }
    let mut plan = tree.repack()?;
    plan.retired = retired;
    if new {
        for node in 0..8 {
            plan.nodes.entry(node).or_insert_with(|| vec![0; 4096]);
        }
    }
    Ok((plan, flags))
}
/// Replace complete value chains for multiple identities together with pending
/// file deletions. Callers validate targets, replacement records and ownership.
pub(super) fn plan_record_batch(
    dev: &mut dyn BlockDevice,
    fork: &ForkData,
    block_size: u32,
    deleted: &BTreeSet<u32>,
    changes: &[(u32, String, Vec<Vec<u8>>)],
) -> Result<(Plan, BTreeMap<u32, bool>)> {
    let new = fork.total_blocks == 0;
    let mut tree = if new {
        new_tree()?
    } else {
        load(dev, fork, block_size, &BTreeSet::new())?
    };
    let total_blocks = u32::try_from(dev.total_size() / u64::from(block_size))
        .map_err(|_| invalid("volume block count overflow"))?;
    let retired = remove_records(&mut tree, block_size, total_blocks, deleted)?;
    let mut flags = BTreeMap::new();
    for (cnid, name, replacement) in changes {
        if deleted.contains(cnid) {
            return Err(invalid("attribute batch targets a deleted identity"));
        }
        flags.insert(*cnid, false);
        let units = name.encode_utf16().collect::<Vec<_>>();
        let mut retained = Vec::new();
        for record in std::mem::take(&mut tree.records) {
            let decoded = key(&record)?;
            if decoded.file_id != *cnid || decoded.name.code_units != units {
                retained.push(record);
            }
        }
        retained.extend(replacement.iter().cloned());
        tree.records = retained;
    }
    let mut ordered = tree
        .records
        .into_iter()
        .map(|r| Ok((key(&r)?, r)))
        .collect::<Result<Vec<_>>>()?;
    ordered.sort_by(|(a, _), (b, _)| a.compare(b, true));
    if ordered
        .windows(2)
        .any(|p| p[0].0.compare(&p[1].0, true) != Ordering::Less)
    {
        return Err(invalid("duplicate edited attribute keys"));
    }
    for (key, _) in &ordered {
        if let Some(flag) = flags.get_mut(&key.file_id) {
            *flag = true;
        }
    }
    tree.records = ordered.into_iter().map(|(_, r)| r).collect();
    tree.leaf_records =
        u32::try_from(tree.records.len()).map_err(|_| invalid("record count overflow"))?;
    tree.removed = 0;
    let capacity = u32::try_from(dev.total_size() / tree.size as u64).unwrap_or(u32::MAX);
    let mut plan = tree.repack_with_growth(Some(capacity))?;
    plan.retired = retired;
    if new && plan.grown_tree.is_none() {
        for node in 0..8 {
            plan.nodes.entry(node).or_insert_with(|| vec![0; 4096]);
        }
    }
    Ok((plan, flags))
}
