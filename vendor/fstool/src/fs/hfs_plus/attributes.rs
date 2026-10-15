//! HFS+ attributes file — TN1150 "Attributes File".
//!
//! The attributes B-tree stores extended-attribute key/value pairs for
//! files and folders. We only need read-side support: looking up a
//! single attribute (such as `com.apple.decmpfs`) by `(fileID, name)`
//! and returning either its inline bytes or a fork descriptor.
//!
//! ## Key layout (HFSPlusAttrKey, TN1150 + Darwin `hfs_format.h`)
//!
//! ```text
//! offset  size  field
//! 0       2     keyLength       (bytes following this u16)
//! 2       2     pad             (reserved, 0)
//! 4       4     fileID          (HFSCatalogNodeID)
//! 8       4     startBlock      (alloc-block offset within attribute fork; 0 for inline)
//! 12      2     attrNameLength  (number of UTF-16 code units; max 127)
//! 14      ...   attrName        (UTF-16 BE, no NUL)
//! ```
//!
//! Comparison order is `(fileID, attrName, startBlock)`. The name is
//! compared in binary UTF-16 order on both HFS+ and HFSX. The attributes
//! header selects comparison independently of the catalog.
//!
//! ## Record layout (first 4 bytes select the record type)
//!
//! ```text
//! 0x00000010  HFSPlusAttrData       : recordType(4) + reserved(8) + attrSize(4) + data[attrSize]
//! 0x00000020  HFSPlusAttrForkData   : recordType(4) + reserved(4) + HFSPlusForkData(80)
//! 0x00000030  HFSPlusAttrExtents    : recordType(4) + reserved(4) + 8 × ExtentDescriptor
//! ```
//!
//! For decmpfs the value is small (≤ 3802 bytes is the inline cap in
//! practice) and always lands in an `Inline` record; the resource fork
//! holds the bulk compressed payload separately in the *catalog* file's
//! own `resourceFork` field, not via `HFSPlusAttrForkData`.

use std::cmp::Ordering;

use crate::Result;
use crate::block::BlockDevice;

use super::btree::{
    BTreeHeader, ForkReader, HEADER_REC_SIZE, KIND_INDEX, KIND_LEAF, NODE_DESCRIPTOR_SIZE,
    NodeDescriptor, read_node, record_bytes, record_offsets,
};
use super::catalog::{UniStr, compare_unistr};
use super::volume_header::ForkData;

/// `kHFSPlusAttrInlineData` — value stored inline in the leaf record.
pub const REC_INLINE_DATA: u32 = 0x10;
/// `kHFSPlusAttrForkData` — value stored in its own fork.
pub const REC_FORK_DATA: u32 = 0x20;
/// `kHFSPlusAttrExtents` — overflow extents for a fork-data attribute.
pub const REC_EXTENTS: u32 = 0x30;

/// macOS FinderInfo xattrs omit per-entry document ID, date added and write
/// generation. These catalog fields belong to the destination, not a copy.
pub fn public_finder_info(raw: &[u8; 32]) -> [u8; 32] {
    let mut bytes = *raw;
    bytes[16..24].fill(0);
    bytes[28..32].fill(0);
    bytes
}

pub(super) fn store_finder_info(body: &mut [u8], value: &[u8; 32]) {
    body[48..64].copy_from_slice(&value[..16]);
    body[72..76].copy_from_slice(&value[24..28]);
}

/// A decoded attribute key.
#[derive(Debug, Clone)]
pub struct AttrKey {
    pub file_id: u32,
    pub start_block: u32,
    pub name: UniStr,
    /// Total encoded length of the key including the leading
    /// `keyLength` u16, padded up to a 2-byte boundary.
    pub encoded_len: usize,
}

impl AttrKey {
    /// Decode an attribute key from `buf`.
    pub fn decode(buf: &[u8]) -> Result<Self> {
        if buf.len() < 14 {
            return Err(crate::Error::InvalidImage(
                "hfs+: short attribute key".into(),
            ));
        }
        let key_length = u16::from_be_bytes([buf[0], buf[1]]) as usize;
        // pad at [2..4] is reserved
        let file_id = u32::from_be_bytes(buf[4..8].try_into().unwrap());
        let start_block = u32::from_be_bytes(buf[8..12].try_into().unwrap());
        let name_len = u16::from_be_bytes([buf[12], buf[13]]) as usize;
        if name_len > 127 {
            return Err(crate::Error::InvalidImage(format!(
                "hfs+: attribute name length {name_len} exceeds 127"
            )));
        }
        // On-disk total encoded length = keyLength(2) + pad(2) + fileID(4)
        // + startBlock(4) + nameLength(2) + name(2*N) = 14 + 2*N.
        let payload_len = 14 + 2 * name_len;
        // The on-disk key_length field covers everything *after* the
        // keyLength u16 itself: pad(2) + fileID(4) + startBlock(4) +
        // nameLength(2) + name(2*N) = 12 + 2*N bytes.
        if 12 + 2 * name_len != key_length {
            return Err(crate::Error::InvalidImage(format!(
                "hfs+: attribute key_length {key_length} disagrees with parsed name \
                 ({name_len} UTF-16 code units)"
            )));
        }
        if buf.len() < payload_len {
            return Err(crate::Error::InvalidImage(
                "hfs+: attribute key truncated".into(),
            ));
        }
        let mut code_units = Vec::with_capacity(name_len);
        for i in 0..name_len {
            let off = 14 + 2 * i;
            code_units.push(u16::from_be_bytes([buf[off], buf[off + 1]]));
        }
        let used = payload_len;
        let encoded_len = if used.is_multiple_of(2) {
            used
        } else {
            used + 1
        };
        Ok(Self {
            file_id,
            start_block,
            name: UniStr { code_units },
            encoded_len,
        })
    }

    /// Compare two attribute keys. Order is `(fileID, name, startBlock)`.
    pub fn compare(&self, other: &AttrKey, case_sensitive: bool) -> Ordering {
        match self.file_id.cmp(&other.file_id) {
            Ordering::Equal => match compare_unistr(&self.name, &other.name, case_sensitive) {
                Ordering::Equal => self.start_block.cmp(&other.start_block),
                o => o,
            },
            o => o,
        }
    }
}

/// One leaf record from the attributes B-tree.
#[derive(Debug, Clone)]
pub enum AttrRecord {
    /// Value stored inline in the record (the common case for small
    /// xattrs like decmpfs headers ≤ ~3.8 KiB).
    Inline {
        /// The attribute value bytes, in declaration order.
        data: Vec<u8>,
    },
    /// Value stored in its own fork; the embedded `ForkData` describes
    /// up to eight inline extents. Overflow extents (record type 0x30)
    /// are not currently followed — they're rare for xattrs.
    Fork {
        /// Fork-data record describing the attribute's value extents.
        fork: ForkData,
    },
}

impl AttrRecord {
    /// Decode the body bytes of an attribute leaf record (the part
    /// after the key).
    pub fn decode(body: &[u8]) -> Result<Self> {
        if body.len() < 4 {
            return Err(crate::Error::InvalidImage(
                "hfs+: short attribute record body".into(),
            ));
        }
        let rec_type = u32::from_be_bytes(body[0..4].try_into().unwrap());
        match rec_type {
            REC_INLINE_DATA => {
                if body.len() < 16 {
                    return Err(crate::Error::InvalidImage(
                        "hfs+: short HFSPlusAttrData".into(),
                    ));
                }
                let attr_size = u32::from_be_bytes(body[12..16].try_into().unwrap()) as usize;
                if attr_size > body.len() - 16 {
                    return Err(crate::Error::InvalidImage(format!(
                        "hfs+: HFSPlusAttrData attrSize {attr_size} exceeds record body ({} bytes)",
                        body.len() - 16
                    )));
                }
                Ok(Self::Inline {
                    data: body[16..16 + attr_size].to_vec(),
                })
            }
            REC_FORK_DATA => {
                if body.len() < 8 + 80 {
                    return Err(crate::Error::InvalidImage(
                        "hfs+: short HFSPlusAttrForkData".into(),
                    ));
                }
                let mut tmp = [0u8; 80];
                tmp.copy_from_slice(&body[8..88]);
                Ok(Self::Fork {
                    fork: ForkData::decode(&tmp),
                })
            }
            REC_EXTENTS => Err(crate::Error::Unsupported(
                "hfs+: attribute overflow-extents record (0x30) not supported".into(),
            )),
            other => Err(crate::Error::InvalidImage(format!(
                "hfs+: unknown attribute record type {other:#010x}"
            ))),
        }
    }
}

/// Opened, ready-to-query attributes B-tree.
pub struct Attributes {
    pub fork: ForkReader,
    pub header: BTreeHeader,
    pub case_sensitive: bool,
}

impl Attributes {
    /// Open the attributes B-tree by reading its header node (node 0).
    /// `fork` is the attributes file's data fork.
    pub fn open(
        dev: &mut dyn BlockDevice,
        fork: ForkReader,
        _case_sensitive: bool,
    ) -> Result<Self> {
        let mut bootstrap = vec![0u8; 512];
        fork.read(dev, 0, &mut bootstrap)?;
        let probe_desc = NodeDescriptor::decode(&bootstrap)?;
        if probe_desc.kind != super::btree::KIND_HEADER {
            return Err(crate::Error::InvalidImage(format!(
                "hfs+: attributes node 0 has kind {} (expected header)",
                probe_desc.kind
            )));
        }
        let hdr_buf = &bootstrap[NODE_DESCRIPTOR_SIZE..NODE_DESCRIPTOR_SIZE + HEADER_REC_SIZE];
        let header = BTreeHeader::decode(hdr_buf)?;
        // Apple leaves this catalog-specific selector at zero in attributes
        // trees; attribute names always use binary UTF-16 comparison.
        if !matches!(header.key_compare_type, 0 | 0xbc) {
            return Err(crate::Error::Unsupported(
                "hfs+: attributes require binary key comparison".into(),
            ));
        }
        Ok(Self {
            fork,
            header,
            case_sensitive: true,
        })
    }

    /// Bounded lookup for optional private records. It reads at most 16 nodes
    /// of at most 32 KiB after the 512-byte header probe. It never decodes or
    /// follows a value fork, or allocates a declared attribute value length.
    pub fn lookup_fixed_inline(
        &self,
        dev: &mut dyn BlockDevice,
        file_id: u32,
        name: &str,
        expected_size: usize,
    ) -> Result<Option<Vec<u8>>> {
        let invalid =
            || crate::Error::InvalidImage("hfs+: invalid bounded attributes traversal".into());
        if expected_size > 3802
            || name.is_empty()
            || name.encode_utf16().count() > 127
            || name.contains('\0')
        {
            return Err(crate::Error::InvalidArgument(
                "hfs+: fixed attribute read limit or name".into(),
            ));
        }
        let h = &self.header;
        if !(512..=32768).contains(&h.node_size)
            || !h.node_size.is_power_of_two()
            || h.tree_depth > 16
            || h.total_nodes == 0
            || h.free_nodes > h.total_nodes
            || u64::from(h.total_nodes) * u64::from(h.node_size) > self.fork.logical_size
        {
            return Err(invalid());
        }
        if h.root_node == 0 {
            return if h.tree_depth == 0 && h.leaf_records == 0 {
                Ok(None)
            } else {
                Err(invalid())
            };
        }
        if h.tree_depth == 0 || h.leaf_records == 0 {
            return Err(invalid());
        }
        let wanted = AttrKey {
            file_id,
            start_block: 0,
            name: UniStr::from_str_lossy(name),
            encoded_len: 0,
        };
        let mut node_idx = h.root_node;
        for height in (1..=h.tree_depth).rev() {
            if node_idx == 0 || node_idx >= h.total_nodes {
                return Err(invalid());
            }
            let node = read_node(dev, &self.fork, node_idx, u32::from(h.node_size))?;
            let desc = NodeDescriptor::decode(&node)?;
            if u16::from(desc.height) != height
                || desc.num_records == 0
                || desc.kind != if height == 1 { KIND_LEAF } else { KIND_INDEX }
            {
                return Err(invalid());
            }
            let offs = record_offsets(&node, desc.num_records)?;
            if offs.windows(2).any(|p| p[0] >= p[1] || p[0] % 2 != 0)
                || usize::from(*offs.last().unwrap()) > node.len() - 2 * offs.len()
            {
                return Err(invalid());
            }
            let mut prior: Option<AttrKey> = None;
            let mut child = None;
            let mut matched = None;
            // Validate every key in the visited node, including duplicate keys,
            // before trusting a match. Other subtrees are deliberately not scanned.
            for i in 0..desc.num_records as usize {
                let rec = record_bytes(&node, &offs, i);
                let key = AttrKey::decode(rec)?;
                if rec[2..4] != [0; 2]
                    || prior
                        .as_ref()
                        .is_some_and(|p| p.compare(&key, true) != Ordering::Less)
                {
                    return Err(invalid());
                }
                let order = key.compare(&wanted, true);
                let body = &rec[key.encoded_len..];
                if height == 1 {
                    if order == Ordering::Equal {
                        matched = Some(body);
                    }
                } else {
                    if body.len() != 4 {
                        return Err(invalid());
                    }
                    let next = u32::from_be_bytes(body.try_into().unwrap());
                    if next == 0 || next >= h.total_nodes {
                        return Err(invalid());
                    }
                    if order != Ordering::Greater {
                        child = Some(next);
                    }
                }
                prior = Some(key);
            }
            if height == 1 {
                let Some(body) = matched else {
                    return Ok(None);
                };
                return Ok(fixed_inline_body(body, expected_size));
            }
            let Some(next) = child else {
                return Ok(None);
            };
            node_idx = next;
        }
        Err(invalid())
    }

    /// Look up an attribute named `name` on file `file_id`. Returns
    /// `None` if no record exists. The lookup uses `startBlock = 0`
    /// (the inline / first-segment record).
    pub fn lookup(
        &self,
        dev: &mut dyn BlockDevice,
        file_id: u32,
        name: &str,
    ) -> Result<Option<AttrRecord>> {
        let wanted = AttrKey {
            file_id,
            start_block: 0,
            name: UniStr::from_str_lossy(name),
            encoded_len: 0,
        };
        let node_size = u32::from(self.header.node_size);
        let mut node_idx = self.header.root_node;
        if node_idx == 0 {
            return Ok(None);
        }
        // Bound the descent by tree depth and reject out-of-range child
        // pointers: a malicious index record can otherwise loop forever.
        let max_descent = self.header.tree_depth.max(1) as usize + 1;
        for _ in 0..max_descent {
            if node_idx >= self.header.total_nodes {
                return Err(crate::Error::InvalidImage(format!(
                    "hfs+: attributes child node {node_idx} >= total_nodes {}",
                    self.header.total_nodes
                )));
            }
            let node = read_node(dev, &self.fork, node_idx, node_size)?;
            let desc = NodeDescriptor::decode(&node)?;
            let offs = record_offsets(&node, desc.num_records)?;
            if desc.kind == KIND_LEAF {
                for i in 0..desc.num_records as usize {
                    let rec = record_bytes(&node, &offs, i);
                    let key = AttrKey::decode(rec)?;
                    match key.compare(&wanted, self.case_sensitive) {
                        Ordering::Equal => {
                            let body_start = align2(key.encoded_len);
                            if body_start > rec.len() {
                                return Err(crate::Error::InvalidImage(
                                    "hfs+: attribute key overruns record".into(),
                                ));
                            }
                            return Ok(Some(AttrRecord::decode(&rec[body_start..])?));
                        }
                        Ordering::Greater => return Ok(None),
                        Ordering::Less => continue,
                    }
                }
                return Ok(None);
            } else if desc.kind == KIND_INDEX {
                let mut child: Option<u32> = None;
                for i in 0..desc.num_records as usize {
                    let rec = record_bytes(&node, &offs, i);
                    let key = AttrKey::decode(rec)?;
                    let pointer_off = align2(key.encoded_len);
                    if pointer_off + 4 > rec.len() {
                        return Err(crate::Error::InvalidImage(
                            "hfs+: attributes index record missing child pointer".into(),
                        ));
                    }
                    let next =
                        u32::from_be_bytes(rec[pointer_off..pointer_off + 4].try_into().unwrap());
                    match key.compare(&wanted, self.case_sensitive) {
                        Ordering::Less | Ordering::Equal => child = Some(next),
                        Ordering::Greater => break,
                    }
                }
                node_idx = match child {
                    Some(c) => c,
                    None => return Ok(None),
                };
            } else {
                return Err(crate::Error::InvalidImage(format!(
                    "hfs+: unexpected B-tree node kind {} in attributes traversal",
                    desc.kind
                )));
            }
        }
        Err(crate::Error::InvalidImage(
            "hfs+: attributes B-tree descent exceeded tree depth (cycle?)".into(),
        ))
    }
}

/// Optional private records never follow forks or allocate declared lengths.
/// Shared by bounded tree lookup and a fully validated committed snapshot.
pub(super) fn fixed_inline_body(body: &[u8], expected_size: usize) -> Option<Vec<u8>> {
    if expected_size > 3802
        || body.len() < 16
        || body[..4] != REC_INLINE_DATA.to_be_bytes()
        || body[4..12] != [0; 8]
        || u32::from_be_bytes(body[12..16].try_into().unwrap()) as usize != expected_size
        || body.len() != ((16 + expected_size + 1) & !1)
    {
        return None;
    }
    Some(body[16..16 + expected_size].to_vec())
}

fn align2(n: usize) -> usize {
    n + (n & 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_inline_record(name: &str, value: &[u8]) -> Vec<u8> {
        // Build a (key, inline-record) pair encoded as one leaf-record
        // byte slice, suitable for AttrKey::decode + AttrRecord::decode.
        let name_units: Vec<u16> = name.encode_utf16().collect();
        let key_payload_len = 12 + 2 * name_units.len();
        let mut out = Vec::new();
        out.extend_from_slice(&(key_payload_len as u16).to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes()); // pad
        out.extend_from_slice(&42u32.to_be_bytes()); // file_id
        out.extend_from_slice(&0u32.to_be_bytes()); // start_block
        out.extend_from_slice(&(name_units.len() as u16).to_be_bytes());
        for u in &name_units {
            out.extend_from_slice(&u.to_be_bytes());
        }
        // Pad to 2-byte alignment (already aligned: 14 + 2*N is even)
        // Inline record body
        out.extend_from_slice(&REC_INLINE_DATA.to_be_bytes());
        out.extend_from_slice(&0u64.to_be_bytes()); // two reserved words
        out.extend_from_slice(&(value.len() as u32).to_be_bytes()); // attrSize
        out.extend_from_slice(value);
        out
    }

    #[test]
    fn attr_key_round_trip() {
        let buf = make_inline_record("com.apple.decmpfs", &[0u8; 32]);
        let key = AttrKey::decode(&buf).unwrap();
        assert_eq!(key.file_id, 42);
        assert_eq!(key.start_block, 0);
        assert_eq!(key.name.to_string_lossy(), "com.apple.decmpfs");
        // 2 (keyLength) + 4 (pad+fileID? no — pad=2 + fileID=4) etc.
        // = 2 + 2 + 4 + 4 + 2 + 2*17 = 48
        assert_eq!(key.encoded_len, 48);
    }

    #[test]
    fn attr_inline_record_decode() {
        let payload = b"hello world".to_vec();
        let buf = make_inline_record("foo", &payload);
        let key = AttrKey::decode(&buf).unwrap();
        let body = &buf[align2(key.encoded_len)..];
        match AttrRecord::decode(body).unwrap() {
            AttrRecord::Inline { data } => assert_eq!(data, payload),
            other => panic!("expected Inline, got {other:?}"),
        }
    }

    #[test]
    fn attr_key_compare_orders_by_file_id_then_name() {
        let a = AttrKey {
            file_id: 1,
            start_block: 0,
            name: UniStr::from_str_lossy("zzz"),
            encoded_len: 0,
        };
        let b = AttrKey {
            file_id: 2,
            start_block: 0,
            name: UniStr::from_str_lossy("aaa"),
            encoded_len: 0,
        };
        assert_eq!(a.compare(&b, false), Ordering::Less);

        let c = AttrKey {
            file_id: 2,
            start_block: 0,
            name: UniStr::from_str_lossy("bbb"),
            encoded_len: 0,
        };
        assert_eq!(b.compare(&c, false), Ordering::Less);
    }
}
