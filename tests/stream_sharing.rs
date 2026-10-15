use fstool::{
    block::MemoryBackend,
    fs::hfs_plus::{FormatOpts, HfsPlus},
};
use hfs_bridge::{
    attribute_archive as wire, volume,
    windows::{Access, Adapter, Handle, Kind, OpenRequest, Share, Status},
};

const PATHS: [&str; 4] = [
    r"\file",
    r"\file:AFP_Resource",
    r"\file:AFP_AfpInfo",
    r"\file:HFSB_Attributes",
];
fn all() -> OpenRequest {
    OpenRequest {
        access: Access::ALL,
        ..Default::default()
    }
}
fn fixture(journaled: bool, sensitive: bool) -> Adapter<MemoryBackend> {
    let mut disk = MemoryBackend::new(32 * 1024 * 1024);
    let mut fs = HfsPlus::format(
        &mut disk,
        &FormatOpts {
            journaled,
            ..Default::default()
        },
    )
    .unwrap();
    fs.flush(&mut disk).unwrap();
    drop(fs);
    if sensitive {
        let mut bytes = disk.into_bytes();
        bytes[1024..1028].copy_from_slice(&[b'H', b'X', 0, 5]);
        let catalog = volume::be32(&bytes, 1312) as usize * volume::be32(&bytes, 1064) as usize;
        bytes[catalog + 51] = 0xbc;
        let header = bytes[1024..1536].to_vec();
        let end = bytes.len() - 1024;
        bytes[end..end + 512].copy_from_slice(&header);
        disk = MemoryBackend::from_bytes(bytes);
    }
    let mut a = Adapter::from_device(disk).unwrap();
    let mut finder = [0; 32];
    finder[..8].copy_from_slice(b"TEXTttxt");
    for (path, bytes) in PATHS.into_iter().zip([
        b"data".to_vec(),
        b"resource".to_vec(),
        hfs_bridge::afp::encode(&finder, 3_900_000_000)
            .unwrap()
            .to_vec(),
        wire::encode(&[("large".into(), vec![17; 20019])]).unwrap(),
    ]) {
        let h = a.create(path, Kind::File, all()).unwrap();
        a.write(h, 0, &bytes, false, false).unwrap();
        a.close(h).unwrap();
    }
    a
}
fn read(a: &mut Adapter<MemoryBackend>, h: Handle) -> Vec<u8> {
    let mut bytes = vec![0; a.file_info(h).unwrap().size as usize];
    let mut offset = 0;
    while offset < bytes.len() {
        let n = a.read(h, offset as u64, &mut bytes[offset..]).unwrap();
        assert_ne!(n, 0);
        offset += n;
    }
    bytes
}

// Expectations are also checked against actual NTFS CreateFileW results by the
// native harness. Metadata-only opens do not participate in data sharing.
#[test]
fn sharing_matrix_is_per_stream_with_base_delete_protection() {
    let mut mismatches = Vec::new();
    let mut cases = 0;
    for (journaled, sensitive) in [(false, false), (true, false), (true, true)] {
        let mut a = fixture(journaled, sensitive);
        for metadata_only in [false, true] {
            for (first, first_path) in PATHS.iter().enumerate() {
                for (second, second_path) in PATHS.iter().enumerate() {
                    for mode in 0..4 {
                        for reverse in [false, true] {
                            let access = Access {
                                read: mode == 0,
                                write: mode == 1,
                                append: mode == 2,
                                delete: mode == 3,
                                ..Access::default()
                            };
                            let limited = OpenRequest {
                                access: if metadata_only {
                                    Access::default()
                                } else {
                                    Access::READ
                                },
                                share: Share {
                                    read: mode != 0,
                                    write: mode != 1 && mode != 2,
                                    delete: mode != 3,
                                },
                                kind: None,
                            };
                            let unrestricted = OpenRequest {
                                access,
                                ..Default::default()
                            };
                            let (one, two) = if reverse {
                                (unrestricted, limited)
                            } else {
                                (limited, unrestricted)
                            };
                            let first_handle = a.open(first_path, one).unwrap();
                            let second_result = a.open(second_path, two);
                            let expected_failure = !metadata_only
                                && (first == second
                                    || (mode == 3
                                        && if reverse { first == 0 } else { second == 0 }));
                            let actual = match second_result {
                                Ok(h) => {
                                    a.close(h).unwrap();
                                    None
                                }
                                Err(e) => Some(e.status),
                            };
                            let expected = expected_failure.then_some(Status::SharingViolation);
                            if actual != expected {
                                mismatches.push(format!("{journaled}/{sensitive} metadata={metadata_only} {first}->{second} mode={mode} reverse={reverse}: {actual:?} expected {expected:?}"));
                            }
                            a.close(first_handle).unwrap();
                            cases += 1;
                        }
                    }
                }
            }
        }
        a.shutdown().unwrap();
    }
    assert_eq!(cases, 768);
    assert!(
        mismatches.is_empty(),
        "{} mismatches:\n{}",
        mismatches.len(),
        mismatches.join("\n")
    );
}

#[test]
fn stream_creation_and_aliases_use_the_correct_sharing_identity() {
    let mut a = fixture(true, false);
    let exclusive = OpenRequest {
        access: Access::READ,
        share: Share {
            read: false,
            write: false,
            delete: true,
        },
        kind: None,
    };
    let main = a.open(PATHS[0], exclusive).unwrap();
    for path in &PATHS[1..] {
        let h = a.open(path, all()).unwrap();
        a.close(h).unwrap();
    }
    assert_eq!(
        a.open(r"\file::$DATA", all()).unwrap_err().status,
        Status::SharingViolation
    );
    a.close(main).unwrap();
    for path in &PATHS[1..] {
        let h = a.open(path, exclusive).unwrap();
        assert_eq!(
            a.open(&format!("{}:$DATA", path.to_ascii_lowercase()), all())
                .unwrap_err()
                .status,
            Status::SharingViolation
        );
        a.close(h).unwrap();
    }
    let base = a.create(r"\created", Kind::File, exclusive).unwrap();
    for (suffix, bytes) in [
        (":AFP_Resource", b"new resource".to_vec()),
        (
            ":AFP_AfpInfo",
            hfs_bridge::afp::encode(&[0; 32], 3_900_000_000)
                .unwrap()
                .to_vec(),
        ),
        (
            ":HFSB_Attributes",
            wire::encode(&[("large".into(), vec![5; 20019])]).unwrap(),
        ),
    ] {
        let h = a
            .create(&format!(r"\created{suffix}"), Kind::File, all())
            .unwrap();
        a.write(h, 0, &bytes, false, false).unwrap();
        a.close(h).unwrap();
    }
    a.close(base).unwrap();
    a.shutdown().unwrap();
}

#[test]
fn detached_archive_sharing_does_not_bind_its_replacement() {
    let mut a = fixture(true, false);
    let remover = a
        .open(
            PATHS[3],
            OpenRequest {
                access: Access {
                    delete: true,
                    ..Access::default()
                },
                ..Default::default()
            },
        )
        .unwrap();
    let old = a
        .open(
            PATHS[3],
            OpenRequest {
                share: Share {
                    read: true,
                    write: false,
                    delete: true,
                },
                ..Default::default()
            },
        )
        .unwrap();
    let before = read(&mut a, old);
    a.cleanup(remover, true).unwrap();
    let fresh = a.create(PATHS[3], Kind::File, all()).unwrap();
    let bytes = wire::encode(&[("new".into(), vec![29; 20019])]).unwrap();
    a.write(fresh, 0, &bytes, false, false).unwrap();
    a.flush(Some(fresh)).unwrap();
    assert_eq!(read(&mut a, old), before);
    a.close(old).unwrap();
    a.close(remover).unwrap();
    a.close(fresh).unwrap();
    let fresh = a.open(PATHS[3], OpenRequest::default()).unwrap();
    assert_eq!(
        wire::decode_snapshot(&read(&mut a, fresh)).unwrap().records,
        vec![("new".into(), Some(vec![29; 20019]))]
    );
    a.close(fresh).unwrap();
    a.shutdown().unwrap();
}

#[test]
fn metadata_only_handles_do_not_prevent_delete_eligibility() {
    let mut a = fixture(true, false);
    let mut metadata = Vec::new();
    for path in PATHS {
        metadata.push(
            a.open(
                path,
                OpenRequest {
                    access: Access::default(),
                    share: Share {
                        read: false,
                        write: false,
                        delete: false,
                    },
                    kind: None,
                },
            )
            .unwrap(),
        );
    }
    for path in PATHS {
        let h = a.open(path, all()).unwrap();
        a.can_delete(h).unwrap();
        a.close(h).unwrap();
    }
    for h in metadata {
        a.close(h).unwrap();
    }
    a.shutdown().unwrap();
}
