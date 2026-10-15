//! Explicit journal replay into a new regular image. Existing inputs stay locked
//! read-only. This is not general filesystem repair or physical-drive recovery.
use crate::{Result, engine, image::Image, volume};
use fstool::fs::hfs_plus::{ReplaySummary, preflight_replay, replay_journal};
use std::path::Path;

#[derive(Debug)]
pub struct RecoveryResult {
    pub replay: ReplaySummary,
    pub engine_accessible: bool,
}

pub fn recover_copy(
    source: &Path,
    output: &Path,
    base: u64,
    length: Option<u64>,
) -> Result<RecoveryResult> {
    // Keep the read-only Windows sharing lock alive through copying and replay.
    let mut original = Image::read_only(source, base, length)?;
    let before = volume::inspect(&mut original)?;
    volume::require_supported_features(&before.header)?;
    if before.header.attributes & volume::JOURNALED == 0 {
        return Err("journal recovery requires an initialized journaled volume".into());
    }
    if !before.alternate_compatible || before.header.attributes & volume::INCONSISTENT != 0 {
        return Err("journal-only recovery refuses incompatible headers or a volume marked inconsistent; native repair is required".into());
    }
    // Includes every committed payload/checksum and all target/budget bounds.
    // No destination file exists until this entire pass succeeds.
    let expected = preflight_replay(&mut original)?;
    let mut copy = Image::copy_new(source, output, base, length)?;
    // Revalidate the exclusive copy; never reuse a source plan on another device.
    if preflight_replay(&mut copy)? != expected {
        return Err("copied journal differs from source preflight".into());
    }
    let actual = replay_journal(&mut copy)?;
    if actual != expected {
        return Err("copied journal differs from source preflight".into());
    }
    let after = volume::inspect(&mut copy)?;
    if matches!(after.journal, volume::Journal::Pending { .. })
        || !after.alternate_compatible
        || after.header.signature != before.header.signature
        || after.header.version != before.header.version
        || after.header.block_size != before.header.block_size
        || after.header.total_blocks != before.header.total_blocks
        || after.header.journal_info_block != before.header.journal_info_block
    {
        return Err(
            "replayed image failed structural postflight; native checking is required".into(),
        );
    }
    let engine_accessible = volume::require_engine_access(&after).is_ok();
    if engine_accessible {
        let _checked = engine::open_checked(&mut copy)?;
    }
    // Do not invent a clean-unmount flag after replay. A genuinely unclean
    // volume remains guarded by normal opens until separately checked natively.
    Ok(RecoveryResult {
        replay: actual,
        engine_accessible,
    })
}
