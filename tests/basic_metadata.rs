//! Basic metadata may update dates and native catalog locks, never BSD protection.
use fstool::{
    block::MemoryBackend,
    fs::hfs_plus::{FormatOpts, HfsPlus},
};
use hfs_bridge::{
    volume,
    windows::{Access, Adapter, BasicTimes, OpenRequest, Status},
};
const ENTRY: &str = "org.hfsbridge.windows.times";
const ROOT: &str = "org.hfsbridge.windows.time-generation";
fn fixture(directory: bool, protection: u8) -> (Vec<u8>, u32) {
    let mut d = MemoryBackend::new(8 * 1024 * 1024);
    let mut fs = HfsPlus::format(
        &mut d,
        &FormatOpts {
            journaled: true,
            ..Default::default()
        },
    )
    .unwrap();
    let cnid = if directory {
        fs.create_dir(&mut d, "/target", 0o755, 501, 20, 0).unwrap()
    } else {
        fs.create_file(
            &mut d,
            "/target",
            &mut &b"original"[..],
            8,
            0o644,
            501,
            20,
            0,
        )
        .unwrap()
    };
    fs.set_catalog_windows_info(cnid, [None; 4], Some(1))
        .unwrap();
    fs.flush(&mut d).unwrap();
    let mut bytes = d.into_bytes();
    if protection != 0 {
        let tree = volume::be32(&bytes, 1312) as usize * 4096;
        let mut leaf = volume::be32(&bytes, tree + 24);
        let size = volume::be16(&bytes, tree + 32) as usize;
        let mut found = 0;
        while leaf != 0 {
            let node = tree + leaf as usize * size;
            for i in 0..volume::be16(&bytes, node + 10) as usize {
                let key = node + volume::be16(&bytes, node + size - 2 * (i + 1)) as usize;
                let body = key + 2 + volume::be16(&bytes, key) as usize;
                if matches!(volume::be16(&bytes, body), 1 | 2)
                    && volume::be32(&bytes, body + 8) == cnid
                {
                    bytes[body + 41] |= protection;
                    found += 1;
                }
            }
            leaf = volume::be32(&bytes, node);
        }
        assert_eq!(found, 1);
    }
    (bytes, cnid)
}
#[test]
fn basic_dates_preserve_bsd_protection_and_only_explicit_catalog_unlocks_succeed() {
    for directory in [false, true] {
        for protection in [0, 2, 4] {
            let (bytes, cnid) = fixture(directory, protection);
            let mut d = MemoryBackend::from_bytes(bytes.clone());
            let mut fs = HfsPlus::open(&mut d).unwrap();
            let related = [
                (2, ROOT, Some(&b"root"[..])),
                (cnid, ENTRY, Some(&b"fraction"[..])),
            ];
            if protection != 0 {
                assert!(
                    fs.set_basic_metadata_with_publication(
                        &mut d,
                        cnid,
                        [Some(3_800_000_000); 4],
                        Some(0x22),
                        &related
                    )
                    .is_err()
                );
                assert!(!fs.requires_reopen());
                fs.flush(&mut d).unwrap();
                assert!(d.as_slice() == bytes);
            }
            // Existing basic-info behavior permits dates on locked objects. It
            // neither clears BSD bits nor grants a general attribute/data edit.
            fs.set_basic_metadata_with_publication(
                &mut d,
                cnid,
                [Some(3_800_000_000); 4],
                None,
                &related,
            )
            .unwrap();
            fs.flush(&mut d).unwrap();
            assert_eq!(fs.catalog_record_cnid(cnid).unwrap()[41] & 6, protection);
            assert!(
                fs.set_inline_attribute(&mut d, cnid, "ordinary", Some(b"denied"))
                    .is_err()
            );
            assert!(
                fs.set_basic_metadata_with_publication(
                    &mut d,
                    cnid,
                    [None; 4],
                    None,
                    &[(cnid, "org.hfsbridge.windows.attributes", Some(b"denied"))]
                )
                .is_err()
            );
            let committed = d.as_slice().to_vec();
            fs.flush(&mut d).unwrap();
            assert!(d.as_slice() == committed);
            if protection == 0 {
                fs.set_basic_metadata_with_publication(&mut d, cnid, [None; 4], Some(0x22), &[])
                    .unwrap();
                fs.flush(&mut d).unwrap();
                fs.set_inline_attribute(&mut d, cnid, "ordinary", Some(b"allowed after unlock"))
                    .unwrap();
                fs.flush(&mut d).unwrap();
            }
        }
    }
}
#[test]
fn windows_basic_metadata_unlocks_catalog_but_not_bsd_and_keeps_noops_unchanged() {
    for directory in [false, true] {
        for protection in [0, 2, 4] {
            let (bytes, cnid) = fixture(directory, protection);
            let mut a = Adapter::from_device(MemoryBackend::from_bytes(bytes)).unwrap();
            let mut access = Access::READ;
            access.metadata = true;
            let h = a
                .open(
                    "\\target",
                    OpenRequest {
                        access,
                        ..Default::default()
                    },
                )
                .unwrap();
            a.set_basic_info(
                h,
                BasicTimes {
                    write: Some(hfs_bridge::windows::hfs_to_filetime(3_800_000_001)),
                    ..Default::default()
                },
                None,
            )
            .unwrap();
            let result = a.set_basic_info(h, BasicTimes::default(), Some(0x22));
            if protection == 0 {
                result.unwrap();
            } else {
                assert_eq!(result.unwrap_err().status, Status::AccessDenied);
            }
            assert!(a.failure().is_none());
            a.close(h).unwrap();
            let mut d = a.shutdown().unwrap();
            let fs = HfsPlus::open(&mut d).unwrap();
            let body = fs.catalog_record_cnid(cnid).unwrap();
            assert_eq!(volume::be32(&body, 16), 3_800_000_001);
            assert_eq!(body[41] & 6, protection);
            let before = d.as_slice().to_vec();
            let mut a = Adapter::from_device(d).unwrap();
            let h = a
                .open(
                    "\\target",
                    OpenRequest {
                        access,
                        ..Default::default()
                    },
                )
                .unwrap();
            a.set_basic_info(h, BasicTimes::default(), None).unwrap();
            a.close(h).unwrap();
            assert!(a.shutdown().unwrap().as_slice() == before);
        }
    }
}
