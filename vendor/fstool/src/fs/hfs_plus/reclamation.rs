//! Read-only ownership checks before any deletion can retire allocation blocks.
use super::{
    HfsPlus, attribute_delete, attribute_value, catalog, extents, volume_header::ForkData,
};
use crate::{Result, block::BlockDevice};

fn invalid(message: &str) -> crate::Error {
    crate::Error::InvalidImage(format!("hfs+ reclamation: {message}"))
}

fn intersects(a: (u64, u64), b: (u64, u64)) -> bool {
    a.0 < b.1 && b.0 < a.1
}

pub(super) fn validate(fs: &HfsPlus, dev: &mut dyn BlockDevice, cnid: u32) -> Result<()> {
    let key = fs.namespace_metadata_key(cnid, false)?;
    let w = fs.writer.as_ref().unwrap();
    let body = w.catalog.get(&key).unwrap();
    if i16::from_be_bytes(body[..2].try_into().unwrap()) == catalog::REC_FOLDER {
        if w.overflow_extents.keys().any(|(_, id, _)| *id == cnid) {
            return Err(invalid("directory owns file overflow records"));
        }
        return Ok(());
    }
    let bs = u64::from(w.block_size);
    let mut owned = Vec::new();
    for (offset, tag) in [(88, extents::FORK_DATA), (168, extents::FORK_RESOURCE)] {
        let fork = ForkData::decode(body[offset..offset + 80].try_into().unwrap());
        let mut covered = 0u64;
        let mut append = |group: &[super::volume_header::ExtentDescriptor]| -> Result<()> {
            let mut ended = false;
            for run in group {
                if run.block_count == 0 {
                    if run.start_block != 0 {
                        return Err(invalid("nonzero empty extent"));
                    }
                    ended = true;
                    continue;
                }
                if ended {
                    return Err(invalid("nonempty extent after empty slot"));
                }
                let start = u64::from(run.start_block);
                let end = start + u64::from(run.block_count);
                if start * bs < 2048
                    || end > u64::from(w.total_blocks)
                    || end * bs > fs.total_bytes() - 1024
                {
                    return Err(invalid("fork extent outside usable volume"));
                }
                if (start..end).any(|block| {
                    w.bitmap
                        .get(block as usize / 8)
                        .is_none_or(|value| value & (0x80 >> (block % 8)) == 0)
                }) {
                    return Err(invalid("fork extent is not allocated"));
                }
                owned.push((start, end));
                covered += u64::from(run.block_count);
            }
            Ok(())
        };
        append(&fork.extents)?;
        // Each group is keyed by its exact logical starting allocation block.
        let mut logical = fork.inline_blocks();
        for ((_, _, start), group) in w
            .overflow_extents
            .range((tag, cnid, 0)..=(tag, cnid, u32::MAX))
        {
            if u64::from(*start) != logical {
                return Err(invalid("discontinuous overflow extent key"));
            }
            append(group)?;
            logical += group
                .iter()
                .map(|run| u64::from(run.block_count))
                .sum::<u64>();
        }
        if covered != u64::from(fork.total_blocks) || fork.logical_size > covered * bs {
            return Err(invalid("fork extent coverage mismatch"));
        }
    }
    if w.overflow_extents.keys().any(|(tag, id, _)| {
        *id == cnid && !matches!(*tag, extents::FORK_DATA | extents::FORK_RESOURCE)
    }) {
        return Err(invalid("unknown target overflow fork"));
    }
    owned.sort_unstable();
    if owned.windows(2).any(|pair| intersects(pair[0], pair[1])) {
        return Err(invalid("target forks share storage"));
    }
    let overlaps = |run: &super::volume_header::ExtentDescriptor| {
        run.block_count != 0
            && owned.iter().any(|&span| {
                intersects(
                    span,
                    (
                        u64::from(run.start_block),
                        u64::from(run.start_block) + u64::from(run.block_count),
                    ),
                )
            })
    };
    for (low, high) in fs.attribute_journal_ranges(dev)? {
        if owned
            .iter()
            .any(|&(start, end)| intersects((start * bs, end * bs), (low, high)))
        {
            return Err(invalid(
                "fork overlaps journal or journal information block",
            ));
        }
    }
    for fork in [
        &w.allocation_file,
        &w.extents_file,
        &w.catalog_file,
        &w.attributes_file,
        &w.startup_file,
    ] {
        if fork.extents.iter().any(overlaps) {
            return Err(invalid("fork overlaps filesystem metadata"));
        }
    }
    if w.catalog.overlaps_file_forks_except(&owned, &key)? {
        return Err(invalid("fork overlaps another catalog file"));
    }
    if w.overflow_extents
        .iter()
        .any(|((_, id, _), runs)| *id != cnid && runs.iter().any(overlaps))
    {
        return Err(invalid("fork overlaps another overflow owner"));
    }
    let records = attribute_delete::records(dev, &w.attributes_file, w.block_size)?;
    for (_, fork) in attribute_value::forks(&records, w.block_size, w.total_blocks)? {
        if fork.extents.iter().any(overlaps) {
            return Err(invalid("fork overlaps attribute value storage"));
        }
    }
    Ok(())
}
