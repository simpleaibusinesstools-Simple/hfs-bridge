//! Checked attribute value chains. Extents belong to the attribute tree,
//! never to the ordinary extents-overflow file. No payload is read here.
use super::{
    attributes::{AttrKey, AttrRecord, REC_EXTENTS, REC_FORK_DATA, REC_INLINE_DATA},
    btree::ForkReader,
    volume_header::{ExtentDescriptor, ForkData},
};
use crate::Result;

pub(super) enum Value {
    Inline(Vec<u8>),
    Fork(ForkReader),
}
pub(super) fn forks(
    records: &[Vec<u8>],
    block_size: u32,
    total_blocks: u32,
) -> Result<Vec<(AttrKey, ForkReader)>> {
    let mut forks = Vec::new();
    let mut cursor = 0;
    while cursor < records.len() {
        let key = AttrKey::decode(&records[cursor])?;
        let mut end = cursor + 1;
        while end < records.len() {
            let next = AttrKey::decode(&records[end])?;
            if next.file_id != key.file_id || next.name.code_units != key.name.code_units {
                break;
            }
            end += 1;
        }
        let body = &records[cursor][key.encoded_len..];
        if key.start_block != 0 {
            return Err(invalid("orphan continuation record"));
        }
        if body[..4] == REC_FORK_DATA.to_be_bytes() {
            let group = records[cursor..end]
                .iter()
                .map(Vec::as_slice)
                .collect::<Vec<_>>();
            let Value::Fork(reader) = decode(&group, block_size, total_blocks)? else {
                unreachable!()
            };
            forks.push((key, reader));
        } else if end != cursor + 1 {
            return Err(invalid("continuations without primary fork record"));
        }
        cursor = end;
    }
    Ok(forks)
}
fn invalid(message: &str) -> crate::Error {
    crate::Error::InvalidImage(format!("hfs+ attribute value: {message}"))
}
pub(super) const MAX_VALUE_BYTES: usize = 16 * 1024 * 1024;
pub(super) fn fork_record(
    cnid: u32,
    name: &str,
    length: usize,
    extent: ExtentDescriptor,
) -> Result<Vec<u8>> {
    let mut record = super::attribute_delete::inline_record(cnid, name, &[])?;
    record.truncate(14 + name.encode_utf16().count() * 2);
    record.extend_from_slice(&REC_FORK_DATA.to_be_bytes());
    record.extend_from_slice(&0u32.to_be_bytes());
    record.extend_from_slice(&(length as u64).to_be_bytes());
    record.extend_from_slice(&0u32.to_be_bytes()); // Apple emits zero clump size.
    record.extend_from_slice(&extent.block_count.to_be_bytes());
    record.extend_from_slice(&extent.start_block.to_be_bytes());
    record.extend_from_slice(&extent.block_count.to_be_bytes());
    record.extend_from_slice(&[0; 56]);
    Ok(record)
}
/// One fresh contiguous reservation; old value blocks stay allocated until
/// every replacement has been reserved, preventing reuse of live payload.
pub(super) fn reserve(
    allocation: &mut super::attribute_delete::Allocation,
    blocks: u32,
    total: u32,
) -> Result<ExtentDescriptor> {
    if blocks == 0 || blocks > allocation.free_blocks {
        return Err(crate::Error::Unsupported(
            "hfs+: insufficient attribute copy-on-write space".into(),
        ));
    }
    let mut count = 0;
    for block in 0..total {
        if allocation.bitmap[block as usize / 8] & (0x80 >> (block % 8)) == 0 {
            count += 1;
        } else {
            count = 0;
        }
        if count == blocks {
            let start = block + 1 - blocks;
            for bit in start..start + blocks {
                allocation.bitmap[bit as usize / 8] |= 0x80 >> (bit % 8);
            }
            allocation.free_blocks -= blocks;
            allocation.next_alloc = allocation.next_alloc.max(start + blocks);
            return Ok(ExtentDescriptor {
                start_block: start,
                block_count: blocks,
            });
        }
    }
    Err(crate::Error::Unsupported(
        "hfs+: no contiguous attribute copy-on-write reservation".into(),
    ))
}
/// Records must all identify one attribute and be ordered by startBlock.
pub(super) fn decode(records: &[&[u8]], block_size: u32, total_blocks: u32) -> Result<Value> {
    if records.is_empty() || block_size == 0 {
        return Err(invalid("missing primary record or invalid block size"));
    }
    let first = AttrKey::decode(records[0])?;
    if first.start_block != 0 {
        return Err(invalid("missing primary record"));
    }
    let body = records[0]
        .get(first.encoded_len..)
        .ok_or_else(|| invalid("primary key length"))?;
    let record_type = body
        .get(..4)
        .ok_or_else(|| invalid("short primary record"))?;
    if record_type == REC_INLINE_DATA.to_be_bytes() {
        if records.len() != 1 {
            return Err(invalid("inline value has continuation records"));
        }
        let AttrRecord::Inline { data } = AttrRecord::decode(body)? else {
            unreachable!()
        };
        if body.len() != (16 + data.len()).next_multiple_of(2) {
            return Err(invalid("inline value length"));
        }
        return Ok(Value::Inline(data));
    }
    if record_type != REC_FORK_DATA.to_be_bytes() || body.len() != 88 {
        return Err(invalid("primary fork record type/length"));
    }
    let fork = ForkData::decode(body[8..].try_into().unwrap());
    if fork.logical_size > u64::from(fork.total_blocks) * u64::from(block_size)
        || fork.total_blocks > total_blocks
    {
        return Err(invalid("fork logical size or block count"));
    }
    let mut extents = Vec::new();
    let mut covered = 0u64;
    for (index, record) in records.iter().enumerate() {
        let key = AttrKey::decode(record)?;
        if key.file_id != first.file_id
            || key.name.code_units != first.name.code_units
            || u64::from(key.start_block) != covered
            || (index != 0 && covered >= u64::from(fork.total_blocks))
        {
            return Err(invalid("continuation identity or logical block offset"));
        }
        let body = record
            .get(key.encoded_len..)
            .ok_or_else(|| invalid("continuation key length"))?;
        let group = if index == 0 {
            fork.extents
        } else {
            if body.len() != 72 || body[..4] != REC_EXTENTS.to_be_bytes() {
                return Err(invalid("continuation type/length"));
            }
            std::array::from_fn(|i| {
                ExtentDescriptor::decode(body[8 + i * 8..16 + i * 8].try_into().unwrap())
            })
        };
        let mut terminated = false;
        let mut used = 0;
        for extent in group {
            if extent.block_count == 0 {
                if extent.start_block != 0 {
                    return Err(invalid("nonzero unused extent"));
                }
                terminated = true;
                continue;
            }
            let start = u64::from(extent.start_block);
            let end = start + u64::from(extent.block_count);
            if terminated
                || start == 0
                || end > u64::from(total_blocks)
                || extents.iter().any(|other: &ExtentDescriptor| {
                    start < u64::from(other.start_block) + u64::from(other.block_count)
                        && u64::from(other.start_block) < end
                })
            {
                return Err(invalid("extent order, bounds or physical overlap"));
            }
            covered += u64::from(extent.block_count);
            if covered > u64::from(fork.total_blocks) {
                return Err(invalid("extent chain exceeds declared blocks"));
            }
            extents.push(extent);
            used += 1;
        }
        if (index + 1 < records.len() && used != 8) || (index != 0 && used == 0) {
            return Err(invalid("empty or prematurely terminated extent group"));
        }
    }
    if covered != u64::from(fork.total_blocks) {
        return Err(invalid("incomplete extent chain"));
    }
    Ok(Value::Fork(ForkReader {
        base_offset: 0,
        block_size,
        extents,
        logical_size: fork.logical_size,
    }))
}
