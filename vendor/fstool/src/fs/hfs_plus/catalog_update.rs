//! Planned, localized catalog B-tree changes. Nothing is written here.
//! The writer publishes all returned nodes in its existing metadata batch.
use super::*;

type SortKey = (u32, Vec<u16>);

pub(super) struct Plan {
    pub nodes: BTreeMap<u32, Vec<u8>>,
    pub total_nodes: u32,
}

#[derive(Clone)]
struct Node {
    desc: NodeDescriptor,
    reserved: [u8; 2],
    records: Vec<PackedRecord>,
}

impl Node {
    fn used(&self) -> usize {
        NODE_DESCRIPTOR_SIZE
            + 2
            + self
                .records
                .iter()
                .map(|r| r.encoded_len() + 2)
                .sum::<usize>()
    }

    fn encode(&self, size: usize) -> Result<Vec<u8>> {
        if self.used() > size {
            return Err(invalid("oversized planned node"));
        }
        let refs: Vec<_> = self.records.iter().collect();
        let mut bytes = write_node(self.desc.kind, self.desc.height, &refs, size)?.bytes;
        bytes[0..4].copy_from_slice(&self.desc.f_link.to_be_bytes());
        bytes[4..8].copy_from_slice(&self.desc.b_link.to_be_bytes());
        bytes[12..14].copy_from_slice(&self.reserved);
        Ok(bytes)
    }

    fn pointer(&self, index: usize) -> Result<u32> {
        let body = &self.records[index].body;
        if self.desc.kind != KIND_INDEX || body.len() != 4 {
            return Err(invalid("bad index pointer"));
        }
        Ok(u32::from_be_bytes(body.as_slice().try_into().unwrap()))
    }
}

struct MapPart {
    id: u32,
    offset: usize,
    start: usize,
    length: usize,
    bytes: Vec<u8>,
}

struct Editor<'a> {
    catalog: &'a CatalogMap,
    dev: &'a mut dyn BlockDevice,
    reader: ForkReader,
    size: usize,
    header: BTreeHeader,
    maps: Vec<MapPart>,
    bitmap: Vec<u8>,
    originals: BTreeMap<u32, Vec<u8>>,
    nodes: BTreeMap<u32, Node>,
    dirty: BTreeSet<u32>,
    freed: BTreeSet<u32>,
    cursor: u32,
}

fn invalid(message: &str) -> crate::Error {
    crate::Error::InvalidImage(format!("hfs+ catalog update: {message}"))
}

fn key_order(key: &[u8], sensitive: bool) -> Result<SortKey> {
    let decoded = CatalogKey::decode(key)?;
    if decoded.encoded_len != key.len() {
        return Err(invalid("invalid encoded key length"));
    }
    Ok((
        decoded.parent_id,
        super::super::catalog::sort_units(&decoded.name, sensitive),
    ))
}

pub(super) fn plan(
    catalog: &CatalogMap,
    dev: &mut dyn BlockDevice,
    fork: &ForkData,
    node_size: u32,
    block_size: u32,
) -> Result<Plan> {
    let mut editor = Editor::load(catalog, dev, fork, node_size, block_size)?;
    for sk in &catalog.dirty {
        let old = catalog.slots.contains_key(sk);
        let replacement = catalog.map.get(sk).map(|(key, body)| PackedRecord {
            key: encode_catalog_key(key.parent_id, &key.name),
            body: body.clone(),
        });
        // Inserted and removed again before publication: no disk record exists.
        if !old && replacement.is_none() {
            continue;
        }
        editor.change(sk, replacement, old)?;
    }
    if usize::try_from(editor.header.leaf_records).ok() != Some(catalog.map.len()) {
        return Err(invalid("planned leaf record count mismatch"));
    }
    // Allocation blocks can contain several nodes. Describe all of them in
    // the node bitmap when the catalog fork is extended.
    loop {
        let bytes = u64::from(editor.header.total_nodes) * u64::from(node_size);
        let rounded = bytes.div_ceil(u64::from(block_size)) * u64::from(block_size);
        let capacity = u32::try_from(rounded / u64::from(node_size))
            .map_err(|_| invalid("catalog capacity overflow"))?;
        if capacity == editor.header.total_nodes {
            break;
        }
        editor.extend_to(capacity)?;
    }
    editor.finish()
}

impl<'a> Editor<'a> {
    fn load(
        catalog: &'a CatalogMap,
        dev: &'a mut dyn BlockDevice,
        fork: &ForkData,
        node_size: u32,
        block_size: u32,
    ) -> Result<Self> {
        let reader = ForkReader::from_inline(fork, block_size, "catalog update")?;
        let header_bytes = read_node(dev, &reader, 0, node_size)?;
        let desc = NodeDescriptor::decode(&header_bytes)?;
        let offsets = record_offsets(&header_bytes, desc.num_records)?;
        if desc.kind != KIND_HEADER || desc.height != 0 || desc.b_link != 0 || desc.num_records != 3
        {
            return Err(invalid("invalid header node"));
        }
        let header = BTreeHeader::decode(record_bytes(&header_bytes, &offsets, 0))?;
        if record_bytes(&header_bytes, &offsets, 2).len() != node_size as usize - 256 {
            return Err(invalid("invalid header map record size"));
        }
        if u32::from(header.node_size) != node_size
            || header.attributes & 6 != 6
            || header.total_nodes == 0
            || u64::from(header.total_nodes) * u64::from(node_size) > fork.logical_size
            || header.free_nodes >= header.total_nodes
            || header.tree_depth == 0
            || header.tree_depth > 255
            || header.root_node == 0
            || header.root_node >= header.total_nodes
            || header.key_compare_type != if catalog.case_sensitive { 0xBC } else { 0xCF }
        {
            return Err(invalid("unsupported or inconsistent header geometry"));
        }
        let mut bitmap = record_bytes(&header_bytes, &offsets, 2).to_vec();
        let mut maps = vec![MapPart {
            id: 0,
            offset: usize::from(offsets[2]),
            start: 0,
            length: bitmap.len(),
            bytes: header_bytes,
        }];
        let mut id = desc.f_link;
        let mut seen = BTreeSet::from([0]);
        while id != 0 {
            if id >= header.total_nodes || !seen.insert(id) {
                return Err(invalid("out-of-range or cyclic map chain"));
            }
            let bytes = read_node(dev, &reader, id, node_size)?;
            let desc = NodeDescriptor::decode(&bytes)?;
            let offsets = record_offsets(&bytes, desc.num_records)?;
            if desc.kind != 2 || desc.height != 0 || desc.b_link != 0 || desc.num_records != 1 {
                return Err(invalid("invalid map node"));
            }
            let record = record_bytes(&bytes, &offsets, 0);
            if record.len() != node_size as usize - 20 {
                return Err(invalid("invalid map record size"));
            }
            maps.push(MapPart {
                id,
                offset: usize::from(offsets[0]),
                start: bitmap.len(),
                length: record.len(),
                bytes: bytes.clone(),
            });
            bitmap.extend_from_slice(record);
            id = desc.f_link;
        }
        if bitmap.len() as u64 * 8 < u64::from(header.total_nodes) {
            return Err(invalid("node map is too short"));
        }
        let used = |id: u32| bitmap[id as usize / 8] & (0x80 >> (id & 7)) != 0;
        if seen.iter().any(|&id| !used(id))
            || !used(header.root_node)
            || (0..header.total_nodes).filter(|&id| !used(id)).count() != header.free_nodes as usize
        {
            return Err(invalid("node map and free count disagree"));
        }
        let originals = maps.iter().map(|m| (m.id, m.bytes.clone())).collect();
        Ok(Self {
            catalog,
            dev,
            reader,
            size: node_size as usize,
            header,
            maps,
            bitmap,
            originals,
            nodes: BTreeMap::new(),
            dirty: BTreeSet::new(),
            freed: BTreeSet::new(),
            cursor: 1,
        })
    }

    fn used(&self, id: u32) -> bool {
        id < self.header.total_nodes && self.bitmap[id as usize / 8] & (0x80 >> (id & 7)) != 0
    }

    fn set_used(&mut self, id: u32, used: bool) {
        let byte = &mut self.bitmap[id as usize / 8];
        let mask = 0x80 >> (id & 7);
        if used {
            *byte |= mask;
        } else {
            *byte &= !mask;
        }
    }

    fn extend_to(&mut self, requested: u32) -> Result<()> {
        while self.header.total_nodes < requested {
            let id = self.header.total_nodes;
            if id as u64 == self.bitmap.len() as u64 * 8 {
                // The new map node describes itself as the first bit of the
                // continuation. Link it without renumbering any existing node.
                let mut bytes = vec![0; self.size];
                bytes[8] = 2;
                bytes[10..12].copy_from_slice(&1u16.to_be_bytes());
                bytes[self.size - 2..].copy_from_slice(&14u16.to_be_bytes());
                bytes[self.size - 4..self.size - 2]
                    .copy_from_slice(&((self.size - 6) as u16).to_be_bytes());
                self.maps.last_mut().unwrap().bytes[0..4].copy_from_slice(&id.to_be_bytes());
                self.maps.push(MapPart {
                    id,
                    offset: 14,
                    start: self.bitmap.len(),
                    length: self.size - 20,
                    bytes,
                });
                self.bitmap.resize(self.bitmap.len() + self.size - 20, 0);
                self.header.total_nodes = self
                    .header
                    .total_nodes
                    .checked_add(1)
                    .ok_or_else(|| invalid("node count overflow"))?;
                self.set_used(id, true);
            } else {
                self.header.total_nodes = self
                    .header
                    .total_nodes
                    .checked_add(1)
                    .ok_or_else(|| invalid("node count overflow"))?;
                self.set_used(id, false);
                self.header.free_nodes += 1;
            }
        }
        Ok(())
    }

    fn allocate(&mut self, mut node: Node) -> Result<u32> {
        loop {
            for id in self.cursor..self.header.total_nodes {
                if !self.used(id) {
                    self.set_used(id, true);
                    self.header.free_nodes -= 1;
                    self.cursor = id + 1;
                    self.freed.remove(&id);
                    node.desc.num_records = node.records.len() as u16;
                    self.save(id, node);
                    return Ok(id);
                }
            }
            // Reserve eight nodes per growth, rather than consuming an
            // additional fork extent for each individual split.
            self.extend_to(
                self.header
                    .total_nodes
                    .checked_add(8)
                    .ok_or_else(|| invalid("node count overflow"))?,
            )?;
        }
    }

    fn load_node(&mut self, id: u32, height: u8) -> Result<Node> {
        if !self.used(id) || self.maps.iter().any(|map| map.id == id) {
            return Err(invalid("pointer targets a free or map node"));
        }
        if let Some(node) = self.nodes.get(&id) {
            if node.desc.height != height {
                return Err(invalid("cached node height mismatch"));
            }
            return Ok(node.clone());
        }
        let bytes = read_node(self.dev, &self.reader, id, self.size as u32)?;
        let desc = NodeDescriptor::decode(&bytes)?;
        if desc.height != height
            || height == 0
            || desc.num_records == 0
            || desc.kind != if height == 1 { KIND_LEAF } else { KIND_INDEX }
            || desc.f_link >= self.header.total_nodes
            || desc.b_link >= self.header.total_nodes
        {
            return Err(invalid("invalid keyed node descriptor"));
        }
        let offsets = record_offsets(&bytes, desc.num_records)?;
        let mut records = Vec::new();
        let mut previous = None;
        for index in 0..usize::from(desc.num_records) {
            let bytes = record_bytes(&bytes, &offsets, index);
            let key = CatalogKey::decode(bytes)?;
            if key.encoded_len > bytes.len() {
                return Err(invalid("key overruns record"));
            }
            let record = PackedRecord {
                key: bytes[..key.encoded_len].to_vec(),
                body: bytes[key.encoded_len..].to_vec(),
            };
            let sk = key_order(&record.key, self.catalog.case_sensitive)?;
            if previous.as_ref().is_some_and(|old| old >= &sk) {
                return Err(invalid("unordered or duplicate node keys"));
            }
            if height == 1 {
                let slot = self
                    .catalog
                    .slots
                    .get(&sk)
                    .ok_or_else(|| invalid("stale leaf key"))?;
                if slot.node != id
                    || slot.record != usize::from(offsets[index])
                    || slot.key_len != record.key.len()
                    || slot.body_len != record.body.len()
                {
                    return Err(invalid("stale leaf record layout"));
                }
            } else if record.body.len() != 4 {
                return Err(invalid("invalid pointer record length"));
            }
            previous = Some(sk);
            records.push(record);
        }
        self.originals.insert(id, bytes.clone());
        let node = Node {
            desc,
            reserved: bytes[12..14].try_into().unwrap(),
            records,
        };
        self.nodes.insert(id, node.clone());
        Ok(node)
    }

    fn save(&mut self, id: u32, node: Node) {
        self.nodes.insert(id, node);
        self.dirty.insert(id);
    }

    fn pointer_record(&self, id: u32) -> Result<PackedRecord> {
        let node = self
            .nodes
            .get(&id)
            .ok_or_else(|| invalid("missing planned child"))?;
        Ok(PackedRecord {
            key: node
                .records
                .first()
                .ok_or_else(|| invalid("empty child"))?
                .key
                .clone(),
            body: id.to_be_bytes().to_vec(),
        })
    }

    fn split_at(&self, node: &Node) -> Result<usize> {
        let minimum = if node.desc.kind == KIND_INDEX { 2 } else { 1 };
        let mut best = None;
        for index in minimum..=node.records.len().saturating_sub(minimum) {
            let left = NODE_DESCRIPTOR_SIZE
                + 2
                + node.records[..index]
                    .iter()
                    .map(|r| r.encoded_len() + 2)
                    .sum::<usize>();
            let right = NODE_DESCRIPTOR_SIZE
                + 2
                + node.records[index..]
                    .iter()
                    .map(|r| r.encoded_len() + 2)
                    .sum::<usize>();
            if left <= self.size
                && right <= self.size
                && best.is_none_or(|(_, difference)| left.abs_diff(right) < difference)
            {
                best = Some((index, left.abs_diff(right)));
            }
        }
        best.map(|(index, _)| index).ok_or_else(|| {
            crate::Error::Unsupported(
                "hfs+ catalog update: records cannot be split into legal nodes".into(),
            )
        })
    }

    fn split(&mut self, id: u32, mut left: Node) -> Result<Vec<u32>> {
        let at = self.split_at(&left)?;
        let mut right = left.clone();
        right.records = left.records.split_off(at);
        right.desc.b_link = id;
        let right_id = self.allocate(right.clone())?;
        left.desc.f_link = right_id;
        if right.desc.f_link != 0 {
            let mut next = self.load_node(right.desc.f_link, right.desc.height)?;
            if next.desc.b_link != id {
                return Err(invalid("broken split sibling link"));
            }
            next.desc.b_link = right_id;
            self.save(right.desc.f_link, next);
        }
        if left.desc.kind == KIND_LEAF && self.header.last_leaf_node == id {
            self.header.last_leaf_node = right_id;
        }
        self.save(id, left);
        self.save(right_id, right);
        Ok(vec![id, right_id])
    }

    fn retire(&mut self, id: u32, node: &Node) -> Result<()> {
        if node.desc.b_link != 0 {
            let mut previous = self.load_node(node.desc.b_link, node.desc.height)?;
            if previous.desc.f_link != id {
                return Err(invalid("broken previous sibling link"));
            }
            previous.desc.f_link = node.desc.f_link;
            self.save(node.desc.b_link, previous);
        }
        if node.desc.f_link != 0 {
            let mut next = self.load_node(node.desc.f_link, node.desc.height)?;
            if next.desc.b_link != id {
                return Err(invalid("broken next sibling link"));
            }
            next.desc.b_link = node.desc.b_link;
            self.save(node.desc.f_link, next);
        }
        if node.desc.kind == KIND_LEAF {
            if self.header.first_leaf_node == id {
                self.header.first_leaf_node = node.desc.f_link;
            }
            if self.header.last_leaf_node == id {
                self.header.last_leaf_node = node.desc.b_link;
            }
        }
        self.set_used(id, false);
        self.header.free_nodes += 1;
        self.cursor = self.cursor.min(id);
        self.nodes.remove(&id);
        self.dirty.remove(&id);
        self.freed.insert(id);
        Ok(())
    }

    fn rebalance(&mut self, parent: &mut Node, index: usize) -> Result<()> {
        if parent.records.len() < 2 {
            return Ok(());
        }
        let left_index = if index + 1 < parent.records.len() {
            index
        } else {
            index - 1
        };
        let left_id = parent.pointer(left_index)?;
        let right_id = parent.pointer(left_index + 1)?;
        let mut left = self.load_node(left_id, parent.desc.height - 1)?;
        let mut right = self.load_node(right_id, parent.desc.height - 1)?;
        if left.desc.f_link != right_id || right.desc.b_link != left_id {
            return Err(invalid("broken rebalance sibling links"));
        }
        if left.records[0].key != parent.records[left_index].key
            || right.records[0].key != parent.records[left_index + 1].key
            || key_order(
                &left.records.last().unwrap().key,
                self.catalog.case_sensitive,
            )? >= key_order(&right.records[0].key, self.catalog.case_sensitive)?
        {
            return Err(invalid("invalid rebalance key boundaries"));
        }
        let left_count = left.records.len();
        left.records.extend(right.records.clone());
        if left.used() <= self.size {
            // Save the combined left node before unlinking the right node;
            // retire() repairs its forward link and the next sibling's backlink.
            self.save(left_id, left);
            self.retire(right_id, &right)?;
            parent.records.remove(left_index + 1);
            parent.records[left_index] = self.pointer_record(left_id)?;
        } else if left.desc.kind == KIND_INDEX && (left_count < 2 || right.records.len() < 2) {
            let at = self.split_at(&left)?;
            right.records = left.records.split_off(at);
            self.save(left_id, left);
            self.save(right_id, right);
            parent.records[left_index] = self.pointer_record(left_id)?;
            parent.records[left_index + 1] = self.pointer_record(right_id)?;
        }
        Ok(())
    }

    fn change_node(
        &mut self,
        id: u32,
        height: u8,
        sk: &SortKey,
        replacement: &Option<PackedRecord>,
        expected: bool,
    ) -> Result<Vec<u32>> {
        let mut node = self.load_node(id, height)?;
        let keys = node
            .records
            .iter()
            .map(|r| key_order(&r.key, self.catalog.case_sensitive))
            .collect::<Result<Vec<_>>>()?;
        if height == 1 {
            let found = keys.binary_search(sk);
            if found.is_ok() != expected {
                return Err(invalid("record presence changed since open"));
            }
            match (found, replacement) {
                (Ok(index), Some(record)) => node.records[index] = record.clone(),
                (Err(index), Some(record)) => {
                    node.records.insert(index, record.clone());
                    self.header.leaf_records += 1;
                }
                (Ok(index), None) => {
                    node.records.remove(index);
                    self.header.leaf_records -= 1;
                }
                (Err(_), None) => return Err(invalid("missing deletion target")),
            }
        } else {
            let index = keys.partition_point(|key| key <= sk).saturating_sub(1);
            let child_id = node.pointer(index)?;
            let child = self.load_node(child_id, height - 1)?;
            if child.records[0].key != node.records[index].key {
                return Err(invalid("index key differs from child boundary"));
            }
            let children = self.change_node(child_id, height - 1, sk, replacement, expected)?;
            let pointers = children
                .iter()
                .map(|&id| self.pointer_record(id))
                .collect::<Result<Vec<_>>>()?;
            node.records.splice(index..index + 1, pointers);
            if replacement.is_none() && !node.records.is_empty() {
                let affected = index.min(node.records.len() - 1);
                self.rebalance(&mut node, affected)?;
            }
        }
        if node.records.is_empty() {
            self.retire(id, &node)?;
            return Ok(Vec::new());
        }
        if node.used() > self.size {
            return self.split(id, node);
        }
        self.save(id, node);
        Ok(vec![id])
    }

    fn change(
        &mut self,
        sk: &SortKey,
        replacement: Option<PackedRecord>,
        expected: bool,
    ) -> Result<()> {
        let root = self.header.root_node;
        let height = self.header.tree_depth as u8;
        let root_node = self.load_node(root, height)?;
        if root_node.desc.f_link != 0 || root_node.desc.b_link != 0 {
            return Err(invalid("root has siblings"));
        }
        let children = self.change_node(root, height, sk, &replacement, expected)?;
        match children.as_slice() {
            [] => {
                self.header.root_node = 0;
                self.header.tree_depth = 0;
            }
            &[id] => {
                self.header.root_node = id;
                // A root with one pointer has no purpose. The child is the
                // only node at its level, and becomes the new root.
                loop {
                    let node =
                        self.load_node(self.header.root_node, self.header.tree_depth as u8)?;
                    if node.desc.kind != KIND_INDEX || node.records.len() != 1 {
                        break;
                    }
                    let child = node.pointer(0)?;
                    let child_node = self.load_node(child, node.desc.height - 1)?;
                    if child_node.desc.f_link != 0 || child_node.desc.b_link != 0 {
                        return Err(invalid("collapsed root child has siblings"));
                    }
                    self.retire(self.header.root_node, &node)?;
                    self.header.root_node = child;
                    self.header.tree_depth -= 1;
                }
            }
            &[left, right] => {
                let height = height
                    .checked_add(1)
                    .ok_or_else(|| invalid("tree height overflow"))?;
                let root = Node {
                    desc: NodeDescriptor {
                        f_link: 0,
                        b_link: 0,
                        kind: KIND_INDEX,
                        height,
                        num_records: 2,
                    },
                    reserved: [0; 2],
                    records: vec![self.pointer_record(left)?, self.pointer_record(right)?],
                };
                self.header.root_node = self.allocate(root)?;
                self.header.tree_depth = u16::from(height);
            }
            _ => return Err(invalid("invalid split result")),
        }
        Ok(())
    }

    fn finish(mut self) -> Result<Plan> {
        let mut nodes = BTreeMap::new();
        for id in &self.dirty {
            nodes.insert(*id, self.nodes[id].encode(self.size)?);
        }
        for id in &self.freed {
            nodes.insert(*id, vec![0; self.size]);
        }
        let header = &mut self.maps[0].bytes;
        let offsets = record_offsets(header, 3)?;
        let start = usize::from(offsets[0]);
        for (offset, bytes) in [
            (0, self.header.tree_depth.to_be_bytes().to_vec()),
            (2, self.header.root_node.to_be_bytes().to_vec()),
            (6, self.header.leaf_records.to_be_bytes().to_vec()),
            (10, self.header.first_leaf_node.to_be_bytes().to_vec()),
            (14, self.header.last_leaf_node.to_be_bytes().to_vec()),
            (22, self.header.total_nodes.to_be_bytes().to_vec()),
            (26, self.header.free_nodes.to_be_bytes().to_vec()),
        ] {
            header[start + offset..start + offset + bytes.len()].copy_from_slice(&bytes);
        }
        for mut map in self.maps {
            map.bytes[map.offset..map.offset + map.length]
                .copy_from_slice(&self.bitmap[map.start..map.start + map.length]);
            // Existing map/header bytes are kept intact apart from owned
            // counts, pointers and allocation bits. Journal filtering skips
            // unchanged sectors, including unused map continuations.
            nodes.insert(map.id, map.bytes);
        }
        nodes.retain(|id, bytes| self.originals.get(id) != Some(bytes));
        Ok(Plan {
            nodes,
            total_nodes: self.header.total_nodes,
        })
    }
}
