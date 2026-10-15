//! Fixed HFS Unicode 3.2 decomposition, independent of platform Unicode updates.
//! The Apple UTF converter decomposes BMP code units; supplementary pairs pass
//! through unchanged. Symbol/CJK exclusions follow TN1150. Case comparison stays
//! in the separate, existing Apple case-fold tables.
use super::unicode_data::{COMBINING_CLASS, DECOMPOSITION};

fn combining_class(unit: u16) -> u8 {
    COMBINING_CLASS
        .binary_search_by_key(&unit, |&(key, _)| key)
        .map(|index| COMBINING_CLASS[index].1)
        .unwrap_or(0)
}

fn append(out: &mut Vec<u16>, unit: u16) {
    let class = combining_class(unit);
    out.push(unit);
    if class == 0 {
        return;
    }
    // Stable insertion orders marks within the current starter segment.
    let mut index = out.len() - 1;
    while index > 0 && combining_class(out[index - 1]) > class {
        out.swap(index - 1, index);
        index -= 1;
    }
}

/// Normalize a host string to HFS catalog UTF-16 units. Length/character
/// validation is separate so raw catalog names and internal records stay intact.
pub fn normalize_units(text: &str) -> Vec<u16> {
    let mut out = Vec::with_capacity(text.len());
    for unit in text.encode_utf16() {
        if (0xAC00..=0xD7A3).contains(&unit) {
            let syllable = unit - 0xAC00;
            append(&mut out, 0x1100 + syllable / 588);
            append(&mut out, 0x1161 + (syllable % 588) / 28);
            if syllable % 28 != 0 {
                append(&mut out, 0x11A7 + syllable % 28);
            }
        } else if let Ok(index) = DECOMPOSITION.binary_search_by_key(&unit, |&(key, _)| key) {
            for &part in DECOMPOSITION[index].1 {
                append(&mut out, part);
            }
        } else {
            append(&mut out, unit);
        }
    }
    out
}
