use flate2::read::GzDecoder;
use fstool::block::{BlockDevice, MemoryBackend};
use hfs_bridge::{
    links::Node,
    windows::{Access, Adapter, OpenRequest, Share, Status},
};
use sha2::{Digest, Sha256};
use std::{
    io::{self, Read, Seek, SeekFrom, Write},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

struct ReadOnly {
    image: MemoryBackend,
    writes: Arc<AtomicUsize>,
}
impl Read for ReadOnly {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.image.read(bytes)
    }
}
impl Seek for ReadOnly {
    fn seek(&mut self, at: SeekFrom) -> io::Result<u64> {
        self.image.seek(at)
    }
}
impl Write for ReadOnly {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> {
        self.writes.fetch_add(1, Ordering::SeqCst);
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "read-only native fixture",
        ))
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
impl BlockDevice for ReadOnly {
    fn block_size(&self) -> u32 {
        512
    }
    fn total_size(&self) -> u64 {
        67108864
    }
    fn sync(&mut self) -> fstool::Result<()> {
        Ok(())
    }
}
fn fixture() -> (Adapter<ReadOnly>, Arc<AtomicUsize>) {
    named_fixture("native-link-fixture")
}
fn named_fixture(name: &str) -> (Adapter<ReadOnly>, Arc<AtomicUsize>) {
    let (device, writes) = fixture_device(name);
    (Adapter::from_device(device).unwrap(), writes)
}
fn fixture_device(name: &str) -> (ReadOnly, Arc<AtomicUsize>) {
    let (compressed, pin): (&[u8], &str) = match name {
        "native-link-fixture" => (
            include_bytes!("fixtures/mac-links-plain.img.gz"),
            "3F3A5D1F96A863A6FBC8C5D9093BDF100C973EAA692B6ACFB83FD56D131EF02A",
        ),
        "native-link-metadata-fixture" => (
            include_bytes!("fixtures/mac-links-metadata.img.gz"),
            "0CD7EE4998CBA0C9BE0532A58F9B4E855277364B7720EF97E99E0D58FEAFFCB1",
        ),
        _ => panic!("unknown native fixture"),
    };
    assert!(compressed.len() < 1024 * 1024);
    let mut bytes = Vec::new();
    GzDecoder::new(compressed)
        .take(67108865)
        .read_to_end(&mut bytes)
        .unwrap();
    assert_eq!(bytes.len(), 67108864);
    assert_eq!(format!("{:X}", Sha256::digest(&bytes)), pin);
    let writes = Arc::new(AtomicUsize::new(0));
    let image = MemoryBackend::from_bytes(bytes);
    (
        ReadOnly {
            image,
            writes: writes.clone(),
        },
        writes,
    )
}
#[test]
fn read_only_caches_preserve_native_link_identity_targets_and_shared_forks() {
    for name in ["native-link-fixture", "native-link-metadata-fixture"] {
        let (device, writes) = fixture_device(name);
        let mut a = Adapter::from_read_only_device(device).unwrap();
        let mut identity = None;
        let mut listing = None;
        for _ in 0..3 {
            let directory = a.open(r"\Links", OpenRequest::default()).unwrap();
            let names = a
                .read_directory(directory)
                .unwrap()
                .into_iter()
                .map(|entry| (entry.name, entry.info.cnid))
                .collect::<Vec<_>>();
            if let Some(previous) = &listing {
                assert_eq!(&names, previous);
            } else {
                listing = Some(names);
            }
            a.close(directory).unwrap();
            for alias in ["target.bin", "hard-a.bin", "hard-b.bin"] {
                let h = a
                    .open(&format!(r"\Links\{alias}"), OpenRequest::default())
                    .unwrap();
                let info = a.file_info(h).unwrap();
                if name == "native-link-metadata-fixture" {
                    // This native fixture deliberately exceeds Windows' EA
                    // value limit; warm caches must preserve that refusal.
                    assert_eq!(
                        a.file_info_with_ea(h).unwrap_err().status,
                        Status::Unsupported
                    );
                } else {
                    assert_eq!(
                        a.file_info_with_ea(h).unwrap().identity_cnid,
                        info.identity_cnid
                    );
                }
                assert_eq!(info.node, Node::HardLink);
                if let Some(previous) = identity {
                    assert_eq!(info.identity_cnid, previous);
                } else {
                    identity = Some(info.identity_cnid);
                }
                let mut bytes = vec![0; 70019];
                assert_eq!(a.read(h, 0, &mut bytes).unwrap(), bytes.len());
                assert_eq!(
                    bytes,
                    (0..70019).map(|i| (i % 251) as u8).collect::<Vec<_>>()
                );
                a.close(h).unwrap();
                if name == "native-link-metadata-fixture" {
                    let h = a
                        .open(
                            &format!(r"\Links\{alias}:AFP_Resource"),
                            OpenRequest::default(),
                        )
                        .unwrap();
                    let mut bytes = vec![0; 70019];
                    assert_eq!(a.read(h, 0, &mut bytes).unwrap(), bytes.len());
                    assert_eq!(
                        bytes,
                        (0..70019).map(|i| (i % 113) as u8).collect::<Vec<_>>()
                    );
                    a.close(h).unwrap();
                }
            }
            for link in ["relative", "absolute"] {
                let packet = a
                    .reparse_by_path(&format!(r"\Links\{link}"))
                    .unwrap()
                    .unwrap();
                assert_eq!(packet_target(&packet), r"..\Links\target.bin");
            }
        }
        let exclusive = a
            .open(
                r"\Links\hard-a.bin",
                OpenRequest {
                    share: Share {
                        read: false,
                        write: false,
                        delete: false,
                    },
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(
            a.open(r"\Links\hard-b.bin", OpenRequest::default())
                .unwrap_err()
                .status,
            Status::SharingViolation
        );
        a.close(exclusive).unwrap();
        a.shutdown().unwrap();
        assert_eq!(writes.load(Ordering::SeqCst), 0);
    }
}
#[test]
fn hardlink_aliases_share_read_exclusion_and_release_it_on_cleanup() {
    let (mut a, writes) = fixture();
    let exclusive = a
        .open(
            "\\Links\\hard-a.bin",
            OpenRequest {
                share: Share {
                    read: false,
                    write: false,
                    delete: false,
                },
                ..Default::default()
            },
        )
        .unwrap();
    for name in ["target.bin", "hard-b.bin"] {
        assert_eq!(
            a.open(&format!("\\Links\\{name}"), OpenRequest::default())
                .unwrap_err()
                .status,
            Status::SharingViolation
        );
    }
    a.cleanup(exclusive, false).unwrap();
    let other = a
        .open("\\Links\\hard-b.bin", OpenRequest::default())
        .unwrap();
    a.close(exclusive).unwrap();
    a.cleanup(other, false).unwrap();
    a.close(other).unwrap();
    assert_eq!(writes.load(Ordering::SeqCst), 0);
}
#[test]
fn hardlink_stream_sharing_uses_shared_inode_and_stream_identity() {
    let (mut a, writes) = named_fixture("native-link-metadata-fixture");
    let suffixes = ["", ":AFP_Resource", ":AFP_AfpInfo", ":HFSB_Attributes"];
    for first in suffixes {
        for second in suffixes {
            let h = a
                .open(
                    &format!(r"\Links\hard-a.bin{first}"),
                    OpenRequest {
                        share: Share {
                            read: false,
                            write: false,
                            delete: true,
                        },
                        ..Default::default()
                    },
                )
                .unwrap();
            for alias in ["target.bin", "hard-b.bin"] {
                let result = a.open(&format!(r"\Links\{alias}{second}"), OpenRequest::default());
                if first == second {
                    assert_eq!(
                        result.unwrap_err().status,
                        Status::SharingViolation,
                        "same stream across {alias}: {first}"
                    );
                } else {
                    a.close(result.unwrap()).unwrap();
                }
            }
            a.cleanup(h, false).unwrap();
            let released = a
                .open(
                    &format!(r"\Links\hard-b.bin{first}"),
                    OpenRequest::default(),
                )
                .unwrap();
            a.close(released).unwrap();
            a.close(h).unwrap();
        }
    }
    assert_eq!(writes.load(Ordering::SeqCst), 0);
}

#[test]
fn genuine_hardlink_resource_attributes_and_finder_are_read_from_the_shared_inode() {
    let (mut a, writes) = named_fixture("native-link-metadata-fixture");
    for name in ["target.bin", "hard-a.bin", "hard-b.bin"] {
        let path = format!("\\Links\\{name}");
        let h = a.open(&path, OpenRequest::default()).unwrap();
        // The complete EA API rejects values above Windows' EA limit.
        // Native projection is exercised by the external Windows workflow;
        // here the supplementary archive carries the complete large value.
        assert_eq!(
            a.extended_attributes(h).unwrap_err().status,
            Status::Unsupported
        );
        a.cleanup(h, false).unwrap();
        a.close(h).unwrap();
        for (stream, bytes) in [
            (
                "AFP_Resource",
                (0..70019).map(|i| (i % 113) as u8).collect::<Vec<_>>(),
            ),
            (
                "AFP_AfpInfo",
                hfs_bridge::afp::encode(
                    b"BINAmacs\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
                    0,
                )
                .unwrap()
                .to_vec(),
            ),
        ] {
            let h = a
                .open(&format!("{path}:{stream}"), OpenRequest::default())
                .unwrap();
            let mut actual = vec![0; bytes.len()];
            assert_eq!(a.read(h, 0, &mut actual).unwrap(), actual.len());
            assert_eq!(actual, bytes);
            a.cleanup(h, false).unwrap();
            a.close(h).unwrap();
        }
        let h = a
            .open(&format!("{path}:HFSB_Attributes"), OpenRequest::default())
            .unwrap();
        let size = a.file_info(h).unwrap().size as usize;
        let mut bytes = vec![0; size];
        assert_eq!(a.read(h, 0, &mut bytes).unwrap(), size);
        let snapshot = hfs_bridge::attribute_archive::decode_snapshot(&bytes).unwrap();
        assert!(snapshot.projected);
        assert_eq!(
            snapshot
                .records
                .iter()
                .find(|r| r.0 == "org.hfsbridge.link.large")
                .unwrap()
                .1,
            Some((0..70019).map(|i| (i % 239) as u8).collect::<Vec<_>>())
        );
        a.cleanup(h, false).unwrap();
        a.close(h).unwrap();
        for stream in ["AFP_Resource", "AFP_AfpInfo", "HFSB_Attributes"] {
            assert_eq!(
                a.open(
                    &format!("{path}:{stream}"),
                    OpenRequest {
                        access: Access::ALL,
                        ..Default::default()
                    }
                )
                .unwrap_err()
                .status,
                Status::AccessDenied
            );
        }
    }
    assert!(a.failure().is_none());
    assert_eq!(writes.load(Ordering::SeqCst), 0);
}
fn packet_target(packet: &[u8]) -> String {
    assert_eq!(
        u32::from_le_bytes(packet[..4].try_into().unwrap()),
        0xa000000c
    );
    assert_eq!(
        u16::from_le_bytes(packet[4..6].try_into().unwrap()) as usize,
        packet.len() - 8
    );
    let length = u16::from_le_bytes(packet[10..12].try_into().unwrap()) as usize;
    let units = packet[20..20 + length]
        .as_chunks::<2>()
        .0
        .iter()
        .map(|b| u16::from_le_bytes(*b))
        .collect::<Vec<_>>();
    String::from_utf16(&units).unwrap()
}
#[test]
fn genuine_mac_link_directory_enumerates_and_hardlink_payloads_share_effective_identity() {
    let (mut a, writes) = fixture();
    let dir = a.open("\\Links", OpenRequest::default()).unwrap();
    let entries = a.read_directory(dir).unwrap();
    assert_eq!(entries.len(), 17); // the18th oracle entry is nested subdir/up
    assert_eq!(
        entries
            .iter()
            .filter(|e| e.info.node == Node::SymbolicLink)
            .count(),
        9
    );
    assert_eq!(
        entries
            .iter()
            .filter(|e| e.info.node == Node::HardLink)
            .count(),
        3
    );
    assert_eq!(
        entries.iter().filter(|e| e.info.node == Node::Fifo).count(),
        1
    );
    let mut identity = None;
    for name in ["target.bin", "hard-a.bin", "hard-b.bin"] {
        let handle = a
            .open(&format!("\\Links\\{name}"), OpenRequest::default())
            .unwrap();
        let info = a.file_info_with_ea(handle).unwrap();
        assert_eq!(info.size, 70019);
        assert_eq!(info.mac_uid, 501);
        assert_eq!(info.mac_gid, 20);
        assert_eq!(info.node, Node::HardLink);
        assert_eq!(info.attributes & 1, 1);
        if let Some(id) = identity {
            assert_eq!(info.identity_cnid, id)
        } else {
            identity = Some(info.identity_cnid)
        }
        let mut bytes = vec![0; 70019];
        assert_eq!(a.read(handle, 0, &mut bytes).unwrap(), bytes.len());
        assert_eq!(
            bytes,
            (0..70019).map(|i| (i % 251) as u8).collect::<Vec<_>>()
        );
        a.cleanup(handle, false).unwrap();
        a.close(handle).unwrap();
    }
    a.cleanup(dir, false).unwrap();
    a.close(dir).unwrap();
    assert_eq!(writes.load(Ordering::SeqCst), 0);
}
#[test]
fn native_mac_targets_use_existing_aliases_and_cannot_escape() {
    let (mut a, writes) = fixture();
    for (name, target) in [
        ("relative", "..\\Links\\target.bin"),
        ("absolute", "..\\Links\\target.bin"),
        ("subdir\\up", "..\\..\\Links\\target.bin"),
        ("dangling", "..\\Links\\Missing folder\\ghost.bin"),
        ("directory", "..\\Links\\subdir"),
        ("cycle-a", "..\\Links\\cycle-b"),
    ] {
        let packet = a
            .reparse_by_path(&format!("\\Links\\{name}"))
            .unwrap()
            .unwrap();
        assert_eq!(packet_target(&packet), target);
    }
    let reserved = packet_target(&a.reparse_by_path("\\Links\\reserved").unwrap().unwrap());
    let dir = a.open("\\Links", OpenRequest::default()).unwrap();
    let entries = a.read_directory(dir).unwrap();
    let alias = &entries
        .iter()
        .find(|e| e.info.cnid != 2 && e.aliased)
        .unwrap()
        .name;
    assert_eq!(reserved, format!("..\\Links\\{alias}"));
    assert_eq!(
        a.reparse_by_path("\\Links\\escape").unwrap_err().status,
        Status::AccessDenied
    );
    assert!(
        a.reparse_by_path("\\Links\\regular-sibling.txt")
            .unwrap()
            .is_none()
    );
    assert_eq!(
        a.reparse_by_path("\\Links\\named-pipe").unwrap().unwrap(),
        vec![0x24, 0, 0, 0x80, 0, 0, 0, 0]
    );
    a.cleanup(dir, false).unwrap();
    a.close(dir).unwrap();
    assert_eq!(writes.load(Ordering::SeqCst), 0);
}
#[test]
fn every_mutating_open_on_existing_link_nodes_is_refused_before_writes() {
    let (mut a, writes) = fixture();
    for name in ["target.bin", "relative", "named-pipe"] {
        for access in [
            Access {
                write: true,
                ..Access::READ
            },
            Access {
                append: true,
                ..Access::READ
            },
            Access {
                delete: true,
                ..Access::READ
            },
            Access {
                metadata: true,
                ..Access::READ
            },
            Access {
                write_ea: true,
                ..Access::READ
            },
        ] {
            let error = a
                .open(
                    &format!("\\Links\\{name}"),
                    OpenRequest {
                        access,
                        ..Default::default()
                    },
                )
                .unwrap_err();
            assert_eq!(error.status, Status::AccessDenied);
        }
        let handle = a
            .open(&format!("\\Links\\{name}"), OpenRequest::default())
            .unwrap();
        if name != "target.bin" {
            assert!(a.streams(handle).unwrap().is_empty());
            assert_eq!(
                a.read(handle, 0, &mut [0; 16]).unwrap_err().status,
                Status::Unsupported
            )
        }
        assert_eq!(
            a.write(handle, 0, b"refused", false, false)
                .unwrap_err()
                .status,
            Status::AccessDenied
        );
        a.cleanup(handle, false).unwrap();
        a.close(handle).unwrap();
    }
    assert!(a.failure().is_none());
    assert_eq!(writes.load(Ordering::SeqCst), 0);
}
