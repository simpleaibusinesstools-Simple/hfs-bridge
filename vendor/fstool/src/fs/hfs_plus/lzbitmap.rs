// SPDX-License-Identifier: MIT
// Bitmap decoding adapted from libzbitmap, Copyright (c) 2022 Corellium LLC.
// Author of the reference implementation: Ernesto A. Fernandez.
// Reference: 574abeae25b25c3319b9b6a9225cc7464e08ae88.
// See third-party/compression/lzbitmap-LICENSE.txt in the enclosing project.
//! Bounded, safe LZBITMAP decoding for one decmpfs unit (at most 64 KiB).
use std::io;

fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "malformed LZBITMAP unit")
}
fn u24(bytes: &[u8], at: usize) -> io::Result<usize> {
    let field = bytes.get(at..at + 3).ok_or_else(invalid)?;
    Ok(usize::from(field[0]) | usize::from(field[1]) << 8 | usize::from(field[2]) << 16)
}
fn byte(bytes: &[u8], at: &mut usize, limit: usize) -> io::Result<u8> {
    if *at >= limit {
        return Err(invalid());
    }
    let value = *bytes.get(*at).ok_or_else(invalid)?;
    *at += 1;
    Ok(value)
}
fn nibble(bytes: &[u8], at: &mut usize, limit: usize) -> io::Result<u8> {
    if *at / 2 >= limit {
        return Err(invalid());
    }
    let value = *bytes.get(*at / 2).ok_or_else(invalid)? >> ((*at % 2) * 4) & 15;
    *at += 1;
    Ok(value)
}

pub(super) fn decode(input: &[u8], expected: usize) -> io::Result<Vec<u8>> {
    if expected > 65_536 || input.len() > 65_536 + 4096 || !input.starts_with(b"ZBM\x09") {
        return Err(invalid());
    }
    let mut output = Vec::with_capacity(expected);
    let mut position = 4;
    loop {
        let length = u24(input, position)?;
        let decoded = u24(input, position + 3)?;
        if length < 6 || decoded > 32_768 || decoded > expected - output.len() {
            return Err(invalid());
        }
        let end = position.checked_add(length).ok_or_else(invalid)?;
        let chunk = input.get(position..end).ok_or_else(invalid)?;
        position = end;
        if decoded == 0 {
            if length != 6 || position != input.len() || output.len() != expected {
                return Err(invalid());
            }
            return Ok(output);
        }
        if length == decoded + 6 {
            output.extend_from_slice(&chunk[6..]);
            continue;
        }
        // Compressed chunks have a 15-byte header and 17-byte bitmap trailer.
        if length < 32 {
            return Err(invalid());
        }
        let trailer = length - 17;
        let mut data = 15;
        let mut periods = u24(chunk, 6)?;
        let mut bitmaps = u24(chunk, 9)?;
        let mut codes = u24(chunk, 12)? * 2;
        let (data_end, periods_end, bitmaps_end) = (periods, bitmaps, codes / 2);
        if !(15 <= periods && periods <= bitmaps && bitmaps <= codes / 2 && codes / 2 <= trailer) {
            return Err(invalid());
        }
        let mut table = [(0u8, 0u8); 12];
        for (index, entry) in table.iter_mut().enumerate() {
            let bit = index * 10;
            let offset = trailer + bit / 8;
            let packed = u16::from_le_bytes([chunk[offset], chunk[offset + 1]]) >> (bit % 8);
            *entry = (packed as u8, ((packed >> 8) & 3) as u8);
            if entry.1 > 2 {
                return Err(invalid());
            }
        }
        let stop = output.len() + decoded;
        let mut period = 8usize;
        while output.len() < stop {
            let code = nibble(chunk, &mut codes, trailer)?;
            if code == 15 {
                return Err(invalid());
            }
            let mut repeats = 1usize;
            if stop - output.len() > 8 {
                let saved = codes;
                if nibble(chunk, &mut codes, trailer)? == 15 {
                    repeats = 4;
                    loop {
                        let count = usize::from(nibble(chunk, &mut codes, trailer)?);
                        repeats = repeats.checked_add(count).ok_or_else(invalid)?;
                        if repeats > (stop - output.len()).div_ceil(8) {
                            return Err(invalid());
                        }
                        if count != 15 {
                            break;
                        }
                    }
                } else {
                    codes = saved;
                }
            }
            for _ in 0..repeats {
                let (bitmap, period_bytes) = if code < 3 {
                    (byte(chunk, &mut bitmaps, bitmaps_end)?, code)
                } else {
                    table[usize::from(code - 3)]
                };
                if period_bytes != 0 {
                    period = usize::from(byte(chunk, &mut periods, periods_end)?);
                    if period_bytes == 2 {
                        period |= usize::from(byte(chunk, &mut periods, periods_end)?) << 8;
                    }
                }
                if period == 0 {
                    return Err(invalid());
                }
                for bit in 0..8 {
                    if output.len() == stop {
                        break;
                    }
                    let value = if bitmap & (1 << bit) != 0 {
                        byte(chunk, &mut data, data_end)?
                    } else {
                        let source = output.len().checked_sub(period).ok_or_else(invalid)?;
                        output[source]
                    };
                    output.push(value);
                }
            }
        }
        if data != data_end || periods != periods_end || bitmaps != bitmaps_end {
            return Err(invalid());
        }
        // Only the unused high nibble in the final code byte may remain.
        if codes.div_ceil(2) != trailer {
            return Err(invalid());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const APPLE: &[u8] =
        include_bytes!("../../../../../tests/fixtures/compression/apple-1024-constant.zbm");
    #[test]
    fn apple_encoded_bytes_and_exact_framing() {
        assert_eq!(decode(APPLE, 1024).unwrap(), vec![b'A'; 1024]);
        for end in 0..APPLE.len() {
            assert!(decode(&APPLE[..end], 1024).is_err());
        }
        for expected in [0, 1023, 1025, 65_537, usize::MAX] {
            assert!(decode(APPLE, expected).is_err());
        }
        let mut trailing = APPLE.to_vec();
        trailing.push(0);
        assert!(decode(&trailing, 1024).is_err());
        assert_eq!(
            decode(b"ZBM\x09\x06\0\0\0\0\0", 0).unwrap(),
            Vec::<u8>::new()
        );
    }
    #[test]
    fn bounded_malformed_chunks_and_metadata() {
        for (at, value) in [
            (0, 0),
            (4, 0),
            (4, 5),
            (7, 0xff),
            (9, 1),
            (10, 0),
            (10, 0xff),
            (13, 0),
            (16, 0),
            (27, 0xff),
        ] {
            let mut bytes = APPLE.to_vec();
            bytes[at] = value;
            assert!(
                decode(&bytes, 1024).is_err(),
                "accepted malformed byte {at}={value}"
            );
        }
        // Every one-bit mutation must remain bounded, whether valid or refused.
        for at in 0..APPLE.len() {
            for bit in 0..8 {
                let mut bytes = APPLE.to_vec();
                bytes[at] ^= 1 << bit;
                if let Ok(output) = decode(&bytes, 1024) {
                    assert_eq!(output.len(), 1024);
                }
            }
        }
    }
}
