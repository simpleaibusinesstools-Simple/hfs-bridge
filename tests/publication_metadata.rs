//! Catalog fields and creation reservation preflight are part of publication.
use fstool::{
    block::MemoryBackend,
    fs::hfs_plus::{CatalogUpdate, ForkEdit, FormatOpts, HfsPlus, PublicationMetadata},
};
use hfs_bridge::{
    volume,
    windows::{Access, Adapter, OpenRequest},
};
use std::path::Path;
#[path = "support/fault_disk.rs"]
mod fault;

fn fixture() -> Vec<u8> {
    let mut d = MemoryBackend::new(8 * 1024 * 1024);
    let mut fs = HfsPlus::format(
        &mut d,
        &FormatOpts {
            journaled: true,
            ..Default::default()
        },
    )
    .unwrap();
    fs.create_file(
        &mut d,
        "/file",
        &mut &b"original"[..],
        8,
        0o644,
        501,
        20,
        1_700_000_000,
    )
    .unwrap();
    fs.flush(&mut d).unwrap();
    d.into_bytes()
}
#[test]
fn catalog_refusals_precede_fork_payload_and_attribute_staging() {
    let before = fixture();
    for variant in 0..5 {
        let mut d = fault::Disk::new(&before);
        let mut fs = HfsPlus::open(&mut d).unwrap();
        let cnid = volume::be32(&fs.catalog_record("/file").unwrap(), 8);
        let update = CatalogUpdate {
            cnid,
            times: [Some(3_800_000_000); 4],
            attributes: Some(0x22),
        };
        let mut updates = vec![update];
        match variant {
            0 => updates.push(update),
            1 => updates.push(CatalogUpdate {
                cnid: 999999,
                ..update
            }),
            2 => updates[0].attributes = Some(0x10),
            3 => updates[0].attributes = Some(0x8000),
            4 => updates.extend(std::iter::repeat_n(update, 16)),
            _ => unreachable!(),
        }
        for metadata_only in [false, true] {
            d.arm(None);
            let metadata = PublicationMetadata {
                attributes: &[("large", Some(&[5; 6001]))],
                related: &[(2, "marker", Some(b"new"))],
                catalog: &updates,
            };
            let result = if metadata_only {
                fs.set_attributes_with_publication(&mut d, cnid, metadata)
            } else {
                fs.edit_fork_with_publication(
                    &mut d,
                    Path::new("/file"),
                    false,
                    ForkEdit::Write {
                        offset: 9000,
                        bytes: b"patch",
                    },
                    metadata,
                )
                .map(|_| ())
            };
            assert!(result.is_err());
            assert_eq!(d.0.lock().unwrap().calls, 0);
            fs.flush(&mut d).unwrap();
            assert!(d.snapshot(1, 0) == before);
        }
    }
}
#[test]
fn new_entry_reservation_and_catalog_refusals_do_not_consume_identity() {
    let before = fixture();
    for variant in 0..6 {
        let mut d = fault::Disk::new(&before);
        let mut fs = HfsPlus::open(&mut d).unwrap();
        let cnid = fs.creation_cnid("/new").unwrap();
        let mut allocation = 8192;
        let mut update = CatalogUpdate {
            cnid,
            times: [Some(3_800_000_000); 4],
            attributes: Some(0x23),
        };
        match variant {
            0 => update.attributes = Some(0x8000),
            1 => update.cnid = cnid + 1,
            2 => allocation = 8193,
            3 => allocation = volume::be32(&before, 1072) as u64 * 4096,
            4 => update.attributes = Some(0x10),
            5 => {}
            _ => unreachable!(),
        }
        d.arm(None);
        assert!(
            fs.create_entry_with_publication(
                &mut d,
                "/new",
                cnid,
                variant == 5,
                501,
                20,
                0,
                allocation,
                PublicationMetadata {
                    attributes: &[("large", Some(&[5; 6001]))],
                    related: &[(2, "marker", Some(b"new"))],
                    catalog: &[update]
                }
            )
            .is_err()
        );
        assert_eq!(d.0.lock().unwrap().calls, 0);
        assert_eq!(fs.creation_cnid("/new").unwrap(), cnid);
        fs.flush(&mut d).unwrap();
        assert!(d.snapshot(1, 0) == before);
    }
}
#[test]
fn metadata_only_fields_and_records_publish_once() {
    let before = fixture();
    let mut d = MemoryBackend::from_bytes(before.clone());
    let mut fs = HfsPlus::open(&mut d).unwrap();
    let cnid = volume::be32(&fs.catalog_record("/file").unwrap(), 8);
    let fork = fs.catalog_record_cnid(cnid).unwrap()[88..].to_vec();
    fs.set_attributes_with_publication(
        &mut d,
        cnid,
        PublicationMetadata {
            related: &[(2, "marker", Some(b"new"))],
            catalog: &[CatalogUpdate {
                cnid,
                times: [Some(3_800_000_000); 4],
                attributes: Some(0x23),
            }],
            ..Default::default()
        },
    )
    .unwrap();
    assert!(d.as_slice() == before);
    fs.flush(&mut d).unwrap();
    assert_eq!(
        volume::be32(d.as_slice(), 1092),
        volume::be32(&before, 1092) + 1
    );
    assert_eq!(fs.catalog_record_cnid(cnid).unwrap()[88..], fork);
    assert_eq!(
        fs.inline_attribute(&mut d, 2, "marker").unwrap(),
        Some(b"new".to_vec())
    );
}
#[test]
fn windows_ordinary_write_and_resize_use_one_publication_and_keep_noops_unchanged() {
    for resource in [false, true] {
        for resize in [false, true] {
            let mut d = MemoryBackend::from_bytes(fixture());
            if resource {
                use std::io::Write;
                let mut fs = HfsPlus::open(&mut d).unwrap();
                let mut f = fs
                    .open_resource_fork_rw(&mut d, Path::new("/file"))
                    .unwrap();
                f.write_all(b"resource").unwrap();
                f.sync().unwrap();
            }
            let before = d.into_bytes();
            let d = fault::Disk::new(&before);
            let observer = d.clone();
            let mut a = Adapter::from_device(d).unwrap();
            let h = a
                .open(
                    if resource {
                        "\\file:AFP_Resource"
                    } else {
                        "\\file"
                    },
                    OpenRequest {
                        access: Access::ALL,
                        ..Default::default()
                    },
                )
                .unwrap();
            observer.arm(None);
            if resize {
                a.set_size(h, 10000).unwrap();
            } else {
                a.write(h, 9000, b"new", false, false).unwrap();
            }
            let info = a.file_info(h).unwrap();
            let saved = observer.snapshot(0, 0);
            assert_eq!(volume::be32(&saved, 1092), volume::be32(&before, 1092) + 1);
            let fs = HfsPlus::open(&mut MemoryBackend::from_bytes(saved.clone())).unwrap();
            let body = fs.catalog_record("/file").unwrap();
            assert_eq!(
                hfs_bridge::windows::filetime_to_hfs(info.write_time).unwrap(),
                volume::be32(&body, 16)
            );
            assert_eq!(
                hfs_bridge::windows::filetime_to_hfs(info.change_time).unwrap(),
                volume::be32(&body, 20)
            );
            assert_eq!(info.write_time, info.change_time);
            let mut reopened =
                Adapter::from_device(MemoryBackend::from_bytes(saved.clone())).unwrap();
            let persisted = reopened.path_info(r"\file").unwrap();
            assert_eq!(persisted.write_time, info.write_time);
            assert_eq!(persisted.change_time, info.change_time);
            reopened.shutdown().unwrap();
            observer.arm(None);
            a.write(h, 0, &[], false, false).unwrap();
            a.set_size(h, info.size).unwrap();
            assert_eq!(observer.0.lock().unwrap().calls, 0);
            a.close(h).unwrap();
            a.shutdown().unwrap();
            assert!(observer.snapshot(0, 0) == saved);
        }
    }
}
