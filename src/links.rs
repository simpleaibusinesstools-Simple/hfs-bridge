//! Windows representations and bounded metadata for supported Mac links.
use crate::windows::{Error, Result, Status};

pub const KIND_ATTRIBUTE: &str = "org.hfsbridge.windows.symlink-kind";
const KIND_MAGIC: &[u8; 8] = b"HFSLK001";

/// Windows remembers whether a link was created as a file or directory even
/// when its target is missing. Bind that hint to the exact CNID and POSIX target
/// so foreign replacement of the target bytes cannot reuse stale metadata.
pub(crate) fn kind_record(cnid: u32, target: &str, directory: bool) -> Vec<u8> {
    let mut bytes = KIND_MAGIC.to_vec();
    bytes.extend_from_slice(&cnid.to_be_bytes());
    bytes.push(u8::from(directory));
    bytes.extend_from_slice(target.as_bytes());
    bytes
}

pub(crate) fn recorded_kind(bytes: &[u8], cnid: u32, target: &str) -> Option<bool> {
    if target.is_empty()
        || target.len() > 1024
        || bytes.len() != 13 + target.len()
        || &bytes[..8] != KIND_MAGIC
        || bytes[8..12] != cnid.to_be_bytes()
        || bytes[12] > 1
        || &bytes[13..] != target.as_bytes()
    {
        return None;
    }
    Some(bytes[12] == 1)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Node {
    Ordinary,
    HardLink,
    SymbolicLink,
    Fifo,
}

impl Node {
    pub fn reparse_tag(self) -> u32 {
        match self {
            Self::SymbolicLink => 0xa000000c,
            Self::Fifo => 0x80000024,
            _ => 0,
        }
    }
}

pub fn normalize_target(parent: &[String], target: &str) -> Result<Vec<String>> {
    if target.is_empty() || target.contains('\0') || target.len() > 16384 {
        return Err(Error {
            status: Status::Unsupported,
            detail: "invalid or oversized Mac link target".into(),
        });
    }
    let mut parts = if target.starts_with('/') {
        Vec::new()
    } else {
        parent.to_vec()
    };
    for part in target.split('/') {
        match part {
            "" | "." => (),
            ".." => {
                if parts.pop().is_none() {
                    return Err(Error {
                        status: Status::AccessDenied,
                        detail: "link target escapes the image namespace".into(),
                    });
                }
            }
            _ => parts.push(part.to_owned()),
        }
    }
    Ok(parts)
}

pub fn symbolic_packet(target: &str) -> Result<Vec<u8>> {
    if target.is_empty()
        || target.contains('\0')
        || target.starts_with('\\')
        || target.contains(':')
    {
        return Err(Error {
            status: Status::Unsupported,
            detail: "relative mount-local link target required".into(),
        });
    }
    let units = target.encode_utf16().collect::<Vec<_>>();
    // Two names and their terminators must fit MAXIMUM_REPARSE_DATA_BUFFER_SIZE.
    if units.len() > 4090 {
        return Err(Error {
            status: Status::Unsupported,
            detail: "Windows link packet exceeds16KiB".into(),
        });
    }
    let bytes = (units.len() * 2) as u16;
    let mut packet = Vec::with_capacity(24 + units.len() * 4);
    packet.extend_from_slice(&0xa000000cu32.to_le_bytes());
    packet.extend_from_slice(&(16u16 + bytes * 2).to_le_bytes());
    packet.extend_from_slice(&0u16.to_le_bytes());
    packet.extend_from_slice(&0u16.to_le_bytes()); // substitute offset
    packet.extend_from_slice(&bytes.to_le_bytes());
    packet.extend_from_slice(&(bytes + 2).to_le_bytes()); // print offset
    packet.extend_from_slice(&bytes.to_le_bytes());
    packet.extend_from_slice(&1u32.to_le_bytes()); // SYMLINK_FLAG_RELATIVE
    for _ in 0..2 {
        for unit in &units {
            packet.extend_from_slice(&unit.to_le_bytes());
        }
        packet.extend_from_slice(&0u16.to_le_bytes());
    }
    Ok(packet)
}

/// Decode the Microsoft symbolic-link packet accepted by a future mutation
/// callback. This only validates the wire representation; the adapter must
/// resolve aliases, confine the target and authorize the target node separately.
/// Neither string is assumed to be terminated or to precede the other.
pub fn relative_symbolic_target(packet: &[u8]) -> Result<String> {
    let invalid = || Error {
        status: Status::InvalidParameter,
        detail: "invalid symbolic-link reparse packet".into(),
    };
    if !(20..=16384).contains(&packet.len()) {
        return Err(invalid());
    }
    let word = |offset| u16::from_le_bytes([packet[offset], packet[offset + 1]]) as usize;
    if u32::from_le_bytes(packet[..4].try_into().unwrap()) != Node::SymbolicLink.reparse_tag() {
        return Err(Error {
            status: Status::Unsupported,
            detail: "only symbolic-link reparse packets are supported".into(),
        });
    }
    if word(4) + 8 != packet.len() || word(6) != 0 {
        return Err(invalid());
    }
    if u32::from_le_bytes(packet[16..20].try_into().unwrap()) != 1 {
        return Err(Error {
            status: Status::Unsupported,
            detail: "only relative symbolic-link targets are supported".into(),
        });
    }
    let name = |offset: usize, length: usize| -> Result<String> {
        if !offset.is_multiple_of(2) || !length.is_multiple_of(2) {
            return Err(invalid());
        }
        let bytes = packet
            .get(20 + offset..20 + offset + length)
            .ok_or_else(invalid)?;
        let units = bytes
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect::<Vec<_>>();
        let value = String::from_utf16(&units).map_err(|_| invalid())?;
        if value.contains('\0') {
            return Err(invalid());
        }
        Ok(value)
    };
    let target = name(word(8), word(10))?;
    // Validate even the optional display name; it cannot grant a different
    // target and is not used as the filesystem path.
    name(word(12), word(14))?;
    if target.is_empty() {
        return Err(invalid());
    }
    if target.starts_with('\\') || target.contains([':', '/']) {
        return Err(Error {
            status: Status::AccessDenied,
            detail: "mount-local Windows relative target required".into(),
        });
    }
    Ok(target)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn link_kind_requires_exact_identity_target_and_bounded_record() {
        let bytes = kind_record(20, "../missing", true);
        assert_eq!(recorded_kind(&bytes, 20, "../missing"), Some(true));
        assert_eq!(recorded_kind(&bytes, 21, "../missing"), None);
        assert_eq!(recorded_kind(&bytes, 20, "../changed"), None);
        for length in 0..bytes.len() {
            assert_eq!(recorded_kind(&bytes[..length], 20, "../missing"), None);
        }
        for index in [0, 8, 12, 13] {
            let mut bad = bytes.clone();
            bad[index] ^= 0x40;
            assert_eq!(recorded_kind(&bad, 20, "../missing"), None);
        }
        let long = "x".repeat(1025);
        assert_eq!(
            recorded_kind(&kind_record(20, &long, true), 20, &long),
            None
        );
        assert_eq!(
            recorded_kind(&kind_record(20, "file", false), 20, "file"),
            Some(false)
        );
    }
    #[test]
    fn decode_relative_packet_by_declared_ranges() {
        for target in ["target.txt", ".", "..\\sub\\file", "café\\猫.txt"] {
            assert_eq!(
                relative_symbolic_target(&symbolic_packet(target).unwrap()).unwrap(),
                target
            );
        }
        // Print name first, no terminators: display 'x', actual target '..\\y'.
        let packet = [
            0x0c, 0x00, 0x00, 0xa0, 22, 0, 0, 0, 2, 0, 8, 0, 0, 0, 2, 0, 1, 0, 0, 0, b'x', 0, b'.',
            0, b'.', 0, b'\\', 0, b'y', 0,
        ];
        assert_eq!(relative_symbolic_target(&packet).unwrap(), "..\\y");
        let mut no_print = packet;
        no_print[12..16].fill(0);
        assert_eq!(relative_symbolic_target(&no_print).unwrap(), "..\\y");
    }

    #[test]
    fn malformed_symbolic_packets_refuse_without_panics() {
        let packet = symbolic_packet("target").unwrap();
        for length in 0..packet.len() {
            assert!(relative_symbolic_target(&packet[..length]).is_err());
        }
        for (offset, bytes) in [
            (4, [0xff, 0xff]),
            (6, [1, 0]),
            (8, [1, 0]),
            (10, [1, 0]),
            (12, [1, 0]),
            (14, [1, 0]),
            (8, [0xfe, 0xff]),
            (10, [0xfe, 0xff]),
            (12, [0xfe, 0xff]),
            (14, [0xfe, 0xff]),
            (20, [0, 0]),
            (20, [0, 0xd8]),
        ] {
            let mut bad = packet.clone();
            bad[offset..offset + 2].copy_from_slice(&bytes);
            assert!(relative_symbolic_target(&bad).is_err(), "offset {offset}");
        }
        let mut extra = packet.clone();
        extra.push(0);
        assert!(relative_symbolic_target(&extra).is_err());
        assert!(relative_symbolic_target(&vec![0; 16385]).is_err());
        for flags in [0u32, 2, 3, u32::MAX] {
            let mut bad = packet.clone();
            bad[16..20].copy_from_slice(&flags.to_le_bytes());
            assert_eq!(
                relative_symbolic_target(&bad).unwrap_err().status,
                Status::Unsupported
            );
        }
        let mut bad_tag = packet;
        bad_tag[0] = 3;
        assert_eq!(
            relative_symbolic_target(&bad_tag).unwrap_err().status,
            Status::Unsupported
        );
    }

    #[test]
    fn packet_display_name_cannot_redirect_target_or_hide_invalid_utf16() {
        let mut packet = symbolic_packet("target").unwrap();
        let start = 20 + u16::from_le_bytes(packet[12..14].try_into().unwrap()) as usize;
        packet[start..start + 2].copy_from_slice(&[b'X', 0]);
        assert_eq!(relative_symbolic_target(&packet).unwrap(), "target");
        packet[start..start + 2].copy_from_slice(&[0, 0xd8]);
        assert!(relative_symbolic_target(&packet).is_err());
        for target in [
            "C:relative",
            "C:\\outside",
            "\\outside",
            "\\\\server\\share",
            "a/b",
            "x:stream",
        ] {
            let mut packet = vec![
                0x0c, 0, 0, 0xa0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0,
            ];
            let units = target.encode_utf16().collect::<Vec<_>>();
            packet[4..6].copy_from_slice(&(12 + 2 * units.len() as u16).to_le_bytes());
            packet[10..12].copy_from_slice(&(2 * units.len() as u16).to_le_bytes());
            for unit in units {
                packet.extend_from_slice(&unit.to_le_bytes());
            }
            assert_eq!(
                relative_symbolic_target(&packet).unwrap_err().status,
                Status::AccessDenied
            );
        }
    }
    #[test]
    fn normalization_confines_relative_and_absolute_targets() {
        let parent = vec!["Links".into(), "subdir".into()];
        assert_eq!(
            normalize_target(&parent, "../target.bin").unwrap(),
            vec!["Links", "target.bin"]
        );
        assert_eq!(
            normalize_target(&parent, "/Links/target.bin").unwrap(),
            vec!["Links", "target.bin"]
        );
        assert_eq!(normalize_target(&parent, "./../subdir/.").unwrap(), parent);
        for target in ["../../../Windows/System32", "/../escape", "", "a\0b"] {
            assert!(normalize_target(&parent, target).is_err());
        }
    }
    #[test]
    fn symbolic_packet_has_exact_utf16_offsets_lengths_and_bound() {
        let target = "..\\Links\\Unicode Ω.txt";
        let packet = symbolic_packet(target).unwrap();
        let length = target.encode_utf16().count() * 2;
        assert_eq!(
            u32::from_le_bytes(packet[..4].try_into().unwrap()),
            0xa000000c
        );
        assert_eq!(
            u16::from_le_bytes(packet[4..6].try_into().unwrap()) as usize,
            packet.len() - 8
        );
        assert_eq!(
            u16::from_le_bytes(packet[10..12].try_into().unwrap()) as usize,
            length
        );
        assert_eq!(
            u16::from_le_bytes(packet[12..14].try_into().unwrap()) as usize,
            length + 2
        );
        assert_eq!(u32::from_le_bytes(packet[16..20].try_into().unwrap()), 1);
        assert_eq!(
            &packet[20..20 + length],
            &packet[22 + length..22 + length * 2]
        );
        assert!(symbolic_packet(&"a".repeat(4090)).is_ok());
        assert!(symbolic_packet(&"a".repeat(4091)).is_err());
        assert!(symbolic_packet("C:\\Windows").is_err());
        assert!(symbolic_packet("\\\\server\\share").is_err());
    }
}
