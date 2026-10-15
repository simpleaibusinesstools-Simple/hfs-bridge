//! Compare ownership queries with an independent full fork scan, including
//! changed, deleted, duplicated, nested and out-of-u32-end descriptors.
#[path = "../vendor/fstool/src/fs/hfs_plus/catalog_ownership.rs"]
mod ownership;
use fstool::fs::hfs_plus::volume_header::ForkData;
use ownership::{CatalogOwnership, RecordKey};
use std::{collections::BTreeMap, hint::black_box, time::Instant};

fn key(id: u32) -> RecordKey {
    (2, format!("file-{id:06}").encode_utf16().collect())
}
fn file(data: &[(u32, u32)], resource: &[(u32, u32)]) -> Vec<u8> {
    let mut body = vec![0; 248];
    body[..2].copy_from_slice(&2i16.to_be_bytes());
    for (offset, extents) in [(88, data), (168, resource)] {
        for (i, &(start, count)) in extents.iter().enumerate() {
            let at = offset + 16 + 8 * i;
            body[at..at + 4].copy_from_slice(&start.to_be_bytes());
            body[at + 4..at + 8].copy_from_slice(&count.to_be_bytes());
        }
    }
    body
}
fn scan(records: &BTreeMap<RecordKey, Vec<u8>>, low: u64, high: u64) -> bool {
    records.values().any(|body| {
        body.len() >= 248
            && body[..2] == 2i16.to_be_bytes()
            && [88, 168].into_iter().any(|at| {
                ForkData::decode(body[at..at + 80].try_into().unwrap())
                    .extents
                    .iter()
                    .any(|extent| {
                        extent.block_count != 0
                            && u64::from(extent.start_block) < high
                            && u64::from(extent.start_block) + u64::from(extent.block_count) > low
                    })
            })
    })
}
fn refresh(index: &mut CatalogOwnership, records: &BTreeMap<RecordKey, Vec<u8>>) {
    if !index.initialized() {
        for (key, body) in records {
            index.replace(key.clone(), Some(body));
        }
        index.finish_initialization();
    } else {
        for key in index.take_pending() {
            let body = records.get(&key).map(Vec::as_slice);
            index.replace(key, body);
        }
    }
}

fn scan_except(
    records: &BTreeMap<RecordKey, Vec<u8>>,
    excluded: &RecordKey,
    owned: &[(u64, u64)],
) -> Result<bool, ()> {
    for (key, body) in records {
        if key == excluded {
            continue;
        }
        if body.len() >= 2 && body[..2] == 2i16.to_be_bytes() {
            if body.len() != 248 {
                return Err(());
            }
            for at in [88, 168] {
                let fork = ForkData::decode(body[at..at + 80].try_into().unwrap());
                if fork.extents.iter().any(|extent| {
                    extent.block_count != 0
                        && owned.iter().any(|&(low, high)| {
                            u64::from(extent.start_block) < high
                                && u64::from(extent.start_block) + u64::from(extent.block_count)
                                    > low
                        })
                }) {
                    return Ok(true);
                }
            }
        }
    }
    Ok(false)
}

#[test]
fn reclamation_excludes_only_exact_owner_and_keeps_duplicate_and_malformed_guards() {
    let mut records = BTreeMap::new();
    records.insert(key(0), file(&[(70000, 4)], &[(70000, 4)]));
    let mut index = CatalogOwnership::default();
    refresh(&mut index, &records);
    assert!(!index.overlaps_excluding(70000, 70004, Some(&key(0))));
    records.insert(key(1), file(&[(70000, 4)], &[]));
    index.changed(key(1));
    refresh(&mut index, &records);
    assert!(index.overlaps_excluding(70000, 70004, Some(&key(0))));
    records.remove(&key(1));
    index.changed(key(1));
    refresh(&mut index, &records);
    assert!(!index.overlaps_excluding(70000, 70004, Some(&key(0))));
    for length in [2, 247, 249, 256] {
        let mut body = vec![0; length];
        body[..2].copy_from_slice(&2i16.to_be_bytes());
        records.insert(key(2), body);
        index.changed(key(2));
        refresh(&mut index, &records);
        assert!(index.malformed_file_except(&key(0)));
        assert!(!index.malformed_file_except(&key(2)));
    }
    records.insert(key(2), vec![0; 88]);
    index.changed(key(2));
    refresh(&mut index, &records);
    assert!(!index.malformed_file_except(&key(0)));
}

#[test]
fn exclusion_queries_match_full_reclamation_scan_after_changes() {
    let mut records = BTreeMap::new();
    let mut index = CatalogOwnership::default();
    let mut rng = 101u64;
    for step in 0..1000 {
        rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1);
        let id = (rng >> 32) as u32 % 80;
        let target = key(id);
        index.changed(target.clone());
        if step % 5 == 0 {
            records.remove(&target);
        } else {
            records.insert(target, file(&[(rng as u32 % 200000, 8193)], &[(70000, 4)]));
        }
        refresh(&mut index, &records);
        let excluded = key((rng >> 48) as u32 % 80);
        let owned = [(rng % 200000, rng % 200000 + 8), (70000, 70004)];
        assert!(!index.malformed_file_except(&excluded));
        assert_eq!(
            owned
                .iter()
                .any(|&(low, high)| index.overlaps_excluding(low, high, Some(&excluded))),
            scan_except(&records, &excluded, &owned).unwrap(),
            "step {step}"
        );
    }
}

#[test]
fn generated_fragmented_reclamation_comparison() {
    let mut records = (0..280019)
        .map(|id| (key(id), file(&[(10000 + id * 1024, 3)], &[])))
        .collect::<BTreeMap<_, _>>();
    let excluded = key(280019);
    let owned = (0..256)
        .map(|i| (487000000 + i * 1024, 487000004 + i * 1024))
        .collect::<Vec<_>>();
    records.insert(
        excluded.clone(),
        file(
            &owned[..8]
                .iter()
                .map(|&(low, high)| (low as u32, (high - low) as u32))
                .collect::<Vec<_>>(),
            &[],
        ),
    );
    let mut index = CatalogOwnership::default();
    refresh(&mut index, &records);
    let before = index.decoded_records;
    let clock = Instant::now();
    for _ in 0..4 {
        assert!(!black_box(
            scan_except(black_box(&records), &excluded, black_box(&owned)).unwrap()
        ));
    }
    let scan_ms = clock.elapsed().as_secs_f64() * 1000.0;
    let clock = Instant::now();
    for _ in 0..4 {
        assert!(!black_box(owned.iter().any(|&(low, high)| {
            index.overlaps_excluding(low, high, Some(&excluded))
        })));
    }
    let index_ms = clock.elapsed().as_secs_f64() * 1000.0;
    assert_eq!(index.decoded_records, before);
    println!(
        "RECLAMATION_CATALOG_BENCH files=280020 fragments=256 rounds=4 full_scan_ms={scan_ms:.3} indexed_ms={index_ms:.3}"
    );
}
#[test]
fn overlaps_match_full_scan_across_mutations_and_duplicates() {
    let mut records = BTreeMap::new();
    // Nested long spans and duplicate owners in either fork must survive
    // removal of a shorter/later span or of only one duplicate.
    records.insert(
        key(0),
        file(&[(1, 200_000), (70_000, 4)], &[(u32::MAX - 3, 10)]),
    );
    records.insert(key(1), file(&[(70_000, 4)], &[(90_000, 9)]));
    records.insert(key(2), file(&[(70_000, 4)], &[(70_000, 4)]));
    let mut index = CatalogOwnership::default();
    refresh(&mut index, &records);
    for point in [0, 1, 2, 65536, 70000, 200001] {
        assert_eq!(index.overlaps(point, point), scan(&records, point, point));
    }
    let mut rng = 7u64;
    for step in 0..1000 {
        rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1);
        let id = (rng >> 32) as u32 % 80;
        let target = key(id);
        index.changed(target.clone());
        match step % 5 {
            0 => {
                records.remove(&target);
            }
            1 => {
                records.insert(target, vec![0; 88]);
            }
            _ => {
                records.insert(target, file(&[((rng >> 16) as u32, 8193)], &[(70_000, 4)]));
            }
        }
        refresh(&mut index, &records);
        for (low, high) in [
            (0, 1),
            (70_000, 70_004),
            (199_999, 200_002),
            (u64::from(u32::MAX), u64::from(u32::MAX) + 4),
            (rng % 500_000, rng % 500_000 + 11),
        ] {
            assert_eq!(
                index.overlaps(low, high),
                scan(&records, low, high),
                "step {step}: {low}..{high}"
            );
        }
    }
    assert_eq!(index.overlaps(7, 7), scan(&records, 7, 7));
}
#[test]
fn unchanged_queries_and_single_record_edits_do_not_redecode_catalog() {
    let records = (0..10000)
        .map(|id| (key(id), file(&[(10000 + id * 1024, 3)], &[])))
        .collect::<BTreeMap<_, _>>();
    let mut index = CatalogOwnership::default();
    refresh(&mut index, &records);
    assert_eq!(index.decoded_records, 10000);
    for _ in 0..100 {
        refresh(&mut index, &records);
        assert!(!index.overlaps(100, 104));
    }
    assert_eq!(index.decoded_records, 10000);
    // Repeated mutable access is coalesced; all fields use the latest body.
    for _ in 0..20 {
        index.changed(key(17));
    }
    refresh(&mut index, &records);
    assert_eq!(index.decoded_records, 10001);
    // Deletion consumes no record and cannot retain a stale ownership span.
    let mut records = records;
    records.remove(&key(17));
    index.changed(key(17));
    refresh(&mut index, &records);
    assert!(!index.overlaps(10000 + 17 * 1024, 10001 + 17 * 1024));
}
#[test]
fn generated_toshiba_sized_catalog_comparison() {
    let records = (0..280019)
        .map(|id| (key(id), file(&[(10000 + id * 1024, 3)], &[])))
        .collect::<BTreeMap<_, _>>();
    let rounds = 60;
    let clock = Instant::now();
    for _ in 0..rounds {
        assert!(!black_box(scan(
            black_box(&records),
            488_000_000,
            488_000_004
        )));
    }
    let scan_ms = clock.elapsed().as_secs_f64() * 1000.0;
    let clock = Instant::now();
    let mut index = CatalogOwnership::default();
    refresh(&mut index, &records);
    let build_ms = clock.elapsed().as_secs_f64() * 1000.0;
    let clock = Instant::now();
    for round in 0..rounds {
        index.changed(key(round));
        refresh(&mut index, &records);
        assert!(!black_box(index.overlaps(488_000_000, 488_000_004)));
    }
    let indexed_ms = clock.elapsed().as_secs_f64() * 1000.0;
    assert_eq!(index.decoded_records, 280019 + rounds as usize);
    println!(
        "CATALOG_OWNERSHIP_BENCH records=280019 queries={rounds} full_scan_ms={scan_ms:.3} index_build_ms={build_ms:.3} changed_record_queries_ms={indexed_ms:.3}"
    );
}
