//! Namespace, parent dates and private records share one publication.
use fstool::{
    block::{BlockDevice, MemoryBackend},
    fs::hfs_plus::{CatalogUpdate, FormatOpts, HfsPlus},
};
use hfs_bridge::volume;
use std::io::Read;
#[path = "support/fault_disk.rs"]
mod fault;
const GEN: &str = "org.hfsbridge.windows.time-generation";
const TIMES: &str = "org.hfsbridge.windows.times";
fn fixture(journaled: bool, sensitive: bool) -> (Vec<u8>, [u32; 4]) {
    let mut d = MemoryBackend::new(8 * 1024 * 1024);
    let mut fs = HfsPlus::format(
        &mut d,
        &FormatOpts {
            journaled,
            ..Default::default()
        },
    )
    .unwrap();
    let source = fs
        .create_dir(&mut d, "/source", 0o755, 501, 20, 1_700_000_000)
        .unwrap();
    let dest = fs
        .create_dir(&mut d, "/destination", 0o755, 501, 20, 1_700_000_000)
        .unwrap();
    let file = fs
        .create_file(
            &mut d,
            "/source/file",
            &mut &b"survivor"[..],
            8,
            0o644,
            501,
            20,
            1_700_000_000,
        )
        .unwrap();
    let victim = fs
        .create_file(
            &mut d,
            "/destination/victim",
            &mut &b"retired"[..],
            7,
            0o644,
            501,
            20,
            1_700_000_000,
        )
        .unwrap();
    fs.flush(&mut d).unwrap();
    fs.set_inline_attribute(&mut d, victim, "large", Some(&[5; 9001]))
        .unwrap();
    fs.flush(&mut d).unwrap();
    let mut bytes = d.into_bytes();
    if sensitive {
        bytes[1024..1026].copy_from_slice(b"HX");
        bytes[1026..1028].copy_from_slice(&5u16.to_be_bytes());
        let cat = volume::be32(&bytes, 1312) as usize * 4096;
        bytes[cat + 51] = 0xbc;
        // HFSX folderCount fields must reflect the two existing subfolders.
        let size = volume::be16(&bytes, cat + 32) as usize;
        let mut leaf = volume::be32(&bytes, cat + 24);
        while leaf != 0 {
            let node = cat + leaf as usize * size;
            for i in 0..volume::be16(&bytes, node + 10) as usize {
                let key = node + volume::be16(&bytes, node + size - 2 * (i + 1)) as usize;
                let body = key + 2 + volume::be16(&bytes, key) as usize;
                if volume::be16(&bytes, body) == 1 {
                    let flags = volume::be16(&bytes, body + 2) | 0x10;
                    bytes[body + 2..body + 4].copy_from_slice(&flags.to_be_bytes());
                    let count = if volume::be32(&bytes, body + 8) == 2 {
                        2u32
                    } else {
                        0
                    };
                    bytes[body + 84..body + 88].copy_from_slice(&count.to_be_bytes());
                }
            }
            leaf = volume::be32(&bytes, node);
        }
        let header = bytes[1024..1536].to_vec();
        let alt = bytes.len() - 1024;
        bytes[alt..alt + 512].copy_from_slice(&header);
    }
    (bytes, [source, dest, file, victim])
}
fn namespace(fs: &mut HfsPlus, d: &mut dyn BlockDevice) {
    fs.remove(d, "/destination/victim").unwrap();
    fs.rename(d, "/source/file", "/destination/renamed")
        .unwrap();
}
fn updates(ids: [u32; 4]) -> Vec<CatalogUpdate> {
    [ids[0], ids[1], ids[2], 2]
        .into_iter()
        .map(|cnid| CatalogUpdate {
            cnid,
            times: [None, None, Some(3_800_000_002), Some(3_800_000_003)],
            attributes: None,
        })
        .collect()
}
fn stage(fs: &mut HfsPlus, d: &mut dyn BlockDevice, ids: [u32; 4]) -> fstool::Result<()> {
    fs.set_namespace_metadata_with_publication(
        d,
        &updates(ids),
        &[
            (2, GEN, Some(b"next namespace")),
            (ids[2], TIMES, Some(b"new precision")),
        ],
    )
}
fn export(name: &str, bytes: &[u8]) {
    if let Some(dir) = std::env::var_os("HFS_NAMESPACE_IMAGES") {
        let dir = std::path::Path::new(&dir);
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(dir.join(name), bytes).unwrap();
    }
}
#[test]
fn namespace_and_pending_attributes_publish_with_related_records_once() {
    for journaled in [false, true] {
        for sensitive in [false, true] {
            let (bytes, ids) = fixture(journaled, sensitive);
            let mut d = MemoryBackend::from_bytes(bytes.clone());
            let mut fs = HfsPlus::open(&mut d).unwrap();
            namespace(&mut fs, &mut d);
            stage(&mut fs, &mut d, ids).unwrap();
            assert_eq!(d.as_slice(), bytes);
            fs.flush(&mut d).unwrap();
            assert_eq!(
                volume::be32(d.as_slice(), 1092),
                volume::be32(&bytes, 1092) + 1
            );
            for update in updates(ids) {
                let b = fs.catalog_record_cnid(update.cnid).unwrap();
                assert_eq!(volume::be32(&b, 16), 3_800_000_002);
                assert_eq!(volume::be32(&b, 20), 3_800_000_003);
            }
            assert!(fs.catalog_record_cnid(ids[3]).is_err());
            assert_eq!(
                fs.inline_attribute(&mut d, 2, GEN).unwrap(),
                Some(b"next namespace".to_vec())
            );
            assert_eq!(
                fs.inline_attribute(&mut d, ids[2], TIMES).unwrap(),
                Some(b"new precision".to_vec())
            );
            let saved = d.as_slice().to_vec();
            fs.flush(&mut d).unwrap();
            assert_eq!(d.as_slice(), saved);
            export(&format!("namespace-{journaled}-{sensitive}.img"), &saved);
        }
    }
}
#[test]
fn namespace_scope_refusals_preserve_already_staged_work() {
    let (bytes, ids) = fixture(true, false);
    for variant in 0..8 {
        let mut d = MemoryBackend::from_bytes(bytes.clone());
        let mut fs = HfsPlus::open(&mut d).unwrap();
        namespace(&mut fs, &mut d);
        let mut catalog = updates(ids);
        let before = ids[..3]
            .iter()
            .map(|&id| fs.catalog_record_cnid(id).unwrap())
            .collect::<Vec<_>>();
        let large = vec![0; 3803];
        let mut related = vec![(2, GEN, Some(b"next namespace".as_slice()))];
        match variant {
            0 => catalog.push(catalog[0]),
            1 => catalog[0].cnid = ids[3],
            2 => catalog[0].attributes = Some(1),
            3 => related.push((ids[2], "public", Some(b"bad"))),
            4 => related.push((ids[3], TIMES, Some(b"bad"))),
            5 => related[0].0 = ids[2],
            6 => related.push(related[0]),
            7 => related[0].2 = Some(&large),
            _ => unreachable!(),
        }
        assert!(
            fs.set_namespace_metadata_with_publication(&mut d, &catalog, &related)
                .is_err()
        );
        assert!(!fs.requires_reopen());
        assert_eq!(d.as_slice(), bytes);
        assert_eq!(
            ids[..3]
                .iter()
                .map(|&id| fs.catalog_record_cnid(id).unwrap())
                .collect::<Vec<_>>(),
            before
        );
        stage(&mut fs, &mut d, ids).unwrap();
        fs.flush(&mut d).unwrap();
        assert!(fs.catalog_record("/destination/renamed").is_ok());
    }
}
#[test]
fn namespace_full_volume_refusal_and_locked_dates_keep_narrow_scope() {
    let (bytes, ids) = fixture(true, false);
    let mut d = MemoryBackend::from_bytes(bytes);
    let mut fs = HfsPlus::open(&mut d).unwrap();
    let mut targets = vec![ids[2]];
    for index in 0..14 {
        targets.push(
            fs.create_dir(
                &mut d,
                &format!("/extra-{index}"),
                0o755,
                501,
                20,
                1_700_000_000,
            )
            .unwrap(),
        );
    }
    fs.flush(&mut d).unwrap();
    let free = u64::from(volume::be32(d.as_slice(), 1072)) * 4096;
    fs.set_data_allocation(
        &mut d,
        std::path::Path::new("/source/file"),
        free + 4096,
        false,
    )
    .unwrap();
    assert_eq!(volume::be32(d.as_slice(), 1072), 0);
    let before = d.as_slice().to_vec();
    namespace(&mut fs, &mut d);
    let body = fs.catalog_record_cnid(ids[2]).unwrap();
    // Small records can reuse the existing attribute tree even at zero free
    // blocks. Sixteen maximum inline records require genuine tree growth.
    let value = vec![7; 3802];
    let mut related = vec![(2, GEN, Some(value.as_slice()))];
    related.extend(
        targets
            .iter()
            .map(|&id| (id, TIMES, Some(value.as_slice()))),
    );
    let catalog = targets
        .iter()
        .map(|&cnid| CatalogUpdate {
            cnid,
            times: [None; 4],
            attributes: None,
        })
        .collect::<Vec<_>>();
    let error = fs
        .set_namespace_metadata_with_publication(&mut d, &catalog, &related)
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("insufficient attribute copy-on-write space"),
        "{error}"
    );
    assert!(!fs.requires_reopen());
    assert_eq!(fs.catalog_record_cnid(ids[2]).unwrap(), body);
    assert_eq!(d.as_slice(), before);
    fs.set_namespace_metadata_with_publication(&mut d, &updates(ids), &[])
        .unwrap();
    fs.flush(&mut d).unwrap();
    fs.set_catalog_windows_info(ids[2], [None; 4], Some(1))
        .unwrap();
    fs.flush(&mut d).unwrap();
    let locked = fs.catalog_record_cnid(ids[2]).unwrap();
    fs.set_namespace_metadata_with_publication(
        &mut d,
        &[CatalogUpdate {
            cnid: ids[2],
            times: [Some(3_800_000_000); 4],
            attributes: None,
        }],
        &[],
    )
    .unwrap();
    fs.flush(&mut d).unwrap();
    let after = fs.catalog_record_cnid(ids[2]).unwrap();
    assert_eq!(&after[..12], &locked[..12]);
    assert_eq!(&after[28..], &locked[28..]);
    assert!(
        fs.set_inline_attribute(&mut d, ids[2], "public", Some(b"denied"))
            .is_err()
    );
}
#[derive(Debug, PartialEq, Eq)]
struct State {
    paths: Vec<Option<Vec<u8>>>,
    marker: Option<Vec<u8>>,
    precision: Option<Vec<u8>>,
    counter: u32,
    free: u32,
}
fn inspect(bytes: Vec<u8>, file: u32) -> State {
    let mut d = MemoryBackend::from_bytes(bytes);
    let fs = HfsPlus::open(&mut d).unwrap();
    let path = if fs.catalog_record("/source/file").is_ok() {
        "/source/file"
    } else {
        "/destination/renamed"
    };
    let mut data = Vec::new();
    fs.open_file_reader(&mut d, path)
        .unwrap()
        .read_to_end(&mut data)
        .unwrap();
    assert_eq!(data, b"survivor");
    State {
        paths: [
            "/source",
            "/destination",
            "/source/file",
            "/destination/renamed",
            "/destination/victim",
        ]
        .iter()
        .map(|p| fs.catalog_record(p).ok())
        .collect(),
        marker: fs.inline_attribute(&mut d, 2, GEN).unwrap(),
        precision: fs.inline_attribute(&mut d, file, TIMES).unwrap(),
        counter: volume::be32(d.as_slice(), 1092),
        free: volume::be32(d.as_slice(), 1072),
    }
}
#[test]
fn namespace_replacement_and_related_records_recover_all_old_or_all_new() {
    let mut failures = 0;
    let mut snapshots = 0;
    for sensitive in [false, true] {
        let (bytes, ids) = fixture(true, sensitive);
        let old = inspect(bytes.clone(), ids[2]);
        let mut complete = fault::Disk::new(&bytes);
        let mut fs = HfsPlus::open(&mut complete).unwrap();
        complete.arm(None);
        namespace(&mut fs, &mut complete);
        stage(&mut fs, &mut complete, ids).unwrap();
        fs.flush(&mut complete).unwrap();
        let count = complete.0.lock().unwrap().calls;
        let new = inspect(complete.snapshot(0, 0), ids[2]);
        let jib = volume::be32(&bytes, 1036) as usize * 4096;
        let journal = volume::be64(&bytes, jib + 36) as usize;
        let mut retained = false;
        for fail in 0..count {
            let mut d = fault::Disk::new(&bytes);
            let mut fs = HfsPlus::open(&mut d).unwrap();
            d.arm(Some(fail));
            namespace(&mut fs, &mut d);
            stage(&mut fs, &mut d, ids).unwrap();
            assert!(fs.flush(&mut d).is_err());
            assert!(fs.requires_reopen());
            let calls = d.0.lock().unwrap().calls;
            assert!(fs.flush(&mut d).is_err());
            assert_eq!(d.0.lock().unwrap().calls, calls);
            failures += 1;
            for policy in 0..6 {
                let snapshot = d.snapshot(policy, journal);
                if !retained
                    && snapshot[journal + 8..journal + 16] != snapshot[journal + 16..journal + 24]
                {
                    export(&format!("namespace-pending-{sensitive}.img"), &snapshot);
                    retained = true;
                }
                let got = inspect(snapshot, ids[2]);
                assert!(got == old || got == new, "fail {fail} policy {policy}");
                snapshots += 1;
            }
        }
        assert!(retained);
    }
    println!("NAMESPACE_RECOVERY: {failures} failed boundaries; {snapshots} persistence snapshots");
}
