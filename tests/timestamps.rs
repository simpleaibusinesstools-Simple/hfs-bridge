use fstool::{
    block::MemoryBackend,
    fs::hfs_plus::{FormatOpts, HfsPlus},
};
use hfs_bridge::{engine, timestamps::*, volume, windows::hfs_to_filetime};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
#[path = "support/fault_disk.rs"]
mod fault;

const SECONDS: [u32; 4] = [3_782_844_800, 3_782_844_801, 3_782_844_802, 3_782_844_803];
fn epoch(n: u8) -> Epoch {
    Epoch::new([n; 16]).unwrap()
}
fn current(count: u32) -> VolumeState {
    VolumeState {
        id: *b"TS51vol!",
        created: 3_782_844_799,
        write_count: count,
    }
}
fn next(count: u32, n: u8) -> Generation {
    Generation::next(current(count), None, epoch(n)).unwrap()
}
fn exact(seconds: [u32; 4]) -> [Option<u64>; 4] {
    std::array::from_fn(|i| Some(hfs_to_filetime(seconds[i]) + [1, 9_999_999, 66, 1234567][i]))
}
fn record(g: Generation, cnid: u32) -> PrecisionRecord {
    PrecisionRecord::new(g, cnid, EntryKind::File, SECONDS, exact(SECONDS)).unwrap()
}
fn reseal(bytes: &mut [u8]) {
    let end = bytes.len() - 32;
    let digest = Sha256::digest(&bytes[..end]);
    bytes[end..].copy_from_slice(&digest);
}

#[test]
fn independently_constructed_wire_format_and_exact_official_date_roundtrip() {
    let g = next(41, 7);
    let mut expected = [0u8; 80];
    expected[..8].copy_from_slice(b"HBTGEN01");
    expected[8..16].copy_from_slice(b"TS51vol!");
    expected[16..20].copy_from_slice(&3_782_844_799u32.to_be_bytes());
    expected[20..24].copy_from_slice(&42u32.to_be_bytes());
    expected[24..40].fill(7);
    reseal(&mut expected);
    assert_eq!(g.encode(), expected);
    assert_eq!(Generation::decode(&expected), Some(g));
    let date = 116_444_736_000_000_000 + 0x4200000042;
    let s = hfs_bridge::windows::filetime_to_hfs(date).unwrap();
    let r = PrecisionRecord::new(g, 25, EntryKind::File, [s; 4], [Some(date); 4]).unwrap();
    let mut wire = [0u8; 112];
    wire[..8].copy_from_slice(b"HBTTIM01");
    wire[8..16].copy_from_slice(b"TS51vol!");
    wire[16..20].copy_from_slice(&3_782_844_799u32.to_be_bytes());
    wire[20..24].copy_from_slice(&25u32.to_be_bytes());
    wire[24..40].fill(7);
    wire[40] = 2;
    wire[41] = 15;
    for i in 0..4 {
        wire[48 + i * 4..52 + i * 4].copy_from_slice(&s.to_be_bytes());
        wire[64 + i * 4..68 + i * 4].copy_from_slice(&((date % 10_000_000) as u32).to_be_bytes());
    }
    reseal(&mut wire);
    assert_eq!(r.encode(), wire);
    assert_eq!(
        PrecisionRecord::decode(&wire).unwrap().resolve(
            Some(g),
            current(42),
            25,
            EntryKind::File,
            [s; 4]
        ),
        [date; 4]
    );
    // This is a codec assertion using the upstream date, not the Windows API test.
}

#[test]
fn malformed_envelopes_truncation_extension_and_every_single_bit_flip_are_refused() {
    let g = next(8, 3).encode();
    let r = record(next(8, 3), 22).encode();
    for n in 0..GENERATION_BYTES {
        assert!(Generation::decode(&g[..n]).is_none());
    }
    for n in 0..RECORD_BYTES {
        assert!(PrecisionRecord::decode(&r[..n]).is_none());
    }
    let mut extra = g.to_vec();
    extra.push(0);
    assert!(Generation::decode(&extra).is_none());
    let mut extra = r.to_vec();
    extra.push(0);
    assert!(PrecisionRecord::decode(&extra).is_none());
    for bit in 0..g.len() * 8 {
        let mut changed = g;
        changed[bit / 8] ^= 1 << (bit % 8);
        assert!(Generation::decode(&changed).is_none());
    }
    for bit in 0..r.len() * 8 {
        let mut changed = r;
        changed[bit / 8] ^= 1 << (bit % 8);
        assert!(PrecisionRecord::decode(&changed).is_none());
    }
    for offset in [0, 7, 40, 47] {
        let mut changed = g;
        changed[offset] ^= 1;
        reseal(&mut changed);
        assert!(Generation::decode(&changed).is_none());
    }
    let mut changed = g;
    changed[24..40].fill(0);
    reseal(&mut changed);
    assert!(Generation::decode(&changed).is_none());
    for (offset, value) in [(0, 0), (7, 0), (40, 0), (40, 3), (41, 16), (42, 1), (47, 1)] {
        let mut changed = r;
        changed[offset] = value;
        reseal(&mut changed);
        assert!(PrecisionRecord::decode(&changed).is_none());
    }
    for cnid in [0u32, 1, 2, 3, 15] {
        let mut changed = r;
        changed[20..24].copy_from_slice(&cnid.to_be_bytes());
        reseal(&mut changed);
        assert!(PrecisionRecord::decode(&changed).is_none());
    }
    let mut changed = r;
    changed[24..40].fill(0);
    reseal(&mut changed);
    assert!(PrecisionRecord::decode(&changed).is_none());
    for i in 0..4 {
        let mut changed = r;
        changed[64 + i * 4..68 + i * 4].copy_from_slice(&10_000_000u32.to_be_bytes());
        reseal(&mut changed);
        assert!(PrecisionRecord::decode(&changed).is_none());
        let mut changed = r;
        changed[41] &= !(1 << i);
        reseal(&mut changed);
        assert!(PrecisionRecord::decode(&changed).is_none());
    }
    assert!(Epoch::new([0; 16]).is_none());
}

#[test]
fn foreign_same_second_edit_invalidates_every_record_and_new_epoch_cannot_revive_them() {
    let g = next(10, 1);
    let a = record(g, 20);
    let b = record(g, 21);
    let baseline = SECONDS.map(hfs_to_filetime);
    assert_ne!(
        a.resolve(Some(g), current(11), 20, EntryKind::File, SECONDS),
        baseline
    );
    assert_eq!(
        a.resolve(Some(g), current(12), 20, EntryKind::File, SECONDS),
        baseline
    );
    assert_eq!(
        b.resolve(Some(g), current(12), 21, EntryKind::File, SECONDS),
        baseline
    );
    assert_eq!(
        Generation::next(current(12), Some(g), epoch(1)),
        Err(RecordError::ReusedEpoch)
    );
    let renewed = Generation::next(current(12), Some(g), epoch(2)).unwrap();
    let new_a = record(renewed, 20);
    // Preparing a next-generation marker cannot authorize reads before commit.
    assert_eq!(
        new_a.resolve(Some(renewed), current(12), 20, EntryKind::File, SECONDS),
        baseline
    );
    assert_ne!(
        new_a.resolve(Some(renewed), current(13), 20, EntryKind::File, SECONDS),
        baseline
    );
    assert_eq!(
        a.resolve(Some(renewed), current(13), 20, EntryKind::File, SECONDS),
        baseline
    );
    assert_eq!(
        b.resolve(Some(renewed), current(13), 21, EntryKind::File, SECONDS),
        baseline
    );
    // A further valid publication retains the new epoch, never the old one.
    let later = Generation::next(current(13), Some(renewed), epoch(3)).unwrap();
    assert_ne!(
        new_a.resolve(Some(later), current(14), 20, EntryKind::File, SECONDS),
        baseline
    );
    assert_eq!(
        b.resolve(Some(later), current(14), 21, EntryKind::File, SECONDS),
        baseline
    );
}

#[test]
fn identity_birth_kind_and_missing_marker_fail_closed_while_fields_are_independent() {
    let g = next(41, 7);
    let r = record(g, 20);
    let v = current(42);
    let baseline = SECONDS.map(hfs_to_filetime);
    for (root, live, id, kind) in [
        (None, v, 20, EntryKind::File),
        (
            Some(g),
            VolumeState {
                id: *b"another!",
                ..v
            },
            20,
            EntryKind::File,
        ),
        (
            Some(g),
            VolumeState { created: 0, ..v },
            20,
            EntryKind::File,
        ),
        (Some(g), v, 21, EntryKind::File),
        (Some(g), v, 20, EntryKind::Directory),
        (Some(next(41, 8)), v, 20, EntryKind::File),
    ] {
        assert_eq!(r.resolve(root, live, id, kind, SECONDS), baseline);
    }
    let mut changed = SECONDS;
    changed[0] += 1;
    assert_eq!(
        r.resolve(Some(g), v, 20, EntryKind::File, changed),
        changed.map(hfs_to_filetime)
    );
    for i in 1..4 {
        let mut changed = SECONDS;
        changed[i] += 1;
        let resolved = r.resolve(Some(g), v, 20, EntryKind::File, changed);
        for j in 0..4 {
            assert_eq!(
                resolved[j],
                if i == j {
                    hfs_to_filetime(changed[j])
                } else {
                    exact(SECONDS)[j].unwrap()
                }
            );
        }
    }
    for mask in 0..16 {
        let dates =
            std::array::from_fn(|i| (mask & (1 << i) != 0).then_some(exact(SECONDS)[i].unwrap()));
        let r = PrecisionRecord::new(g, 2, EntryKind::Directory, SECONDS, dates).unwrap();
        let resolved = PrecisionRecord::decode(&r.encode()).unwrap().resolve(
            Some(g),
            v,
            2,
            EntryKind::Directory,
            SECONDS,
        );
        for i in 0..4 {
            assert_eq!(resolved[i], dates[i].unwrap_or(baseline[i]));
        }
    }
}

#[test]
fn bounds_maximum_fraction_epoch_and_counter_rollover_are_explicit() {
    let g = next(u32::MAX, 1);
    assert!(g.matches(current(0)));
    let dates = [
        Some(hfs_to_filetime(0)),
        Some(hfs_to_filetime(u32::MAX) + 9_999_999),
        None,
        None,
    ];
    let seconds = [0, u32::MAX, 0, 0];
    let r = PrecisionRecord::new(g, 16, EntryKind::File, seconds, dates).unwrap();
    let actual = r.resolve(Some(g), current(0), 16, EntryKind::File, seconds);
    assert_eq!(actual[0], dates[0].unwrap());
    assert_eq!(actual[1], dates[1].unwrap());
    for date in [
        0,
        hfs_to_filetime(0) - 1,
        hfs_to_filetime(u32::MAX) + 10_000_000,
        u64::MAX,
    ] {
        assert!(
            PrecisionRecord::new(
                g,
                16,
                EntryKind::File,
                seconds,
                [Some(date), None, None, None]
            )
            .is_err()
        );
    }
    assert!(
        PrecisionRecord::new(
            g,
            16,
            EntryKind::File,
            SECONDS,
            [Some(hfs_to_filetime(SECONDS[0] + 1)), None, None, None]
        )
        .is_err()
    );
    assert_eq!(
        PrecisionRecord::new(g, 2, EntryKind::File, SECONDS, [None; 4]),
        Err(RecordError::InvalidIdentity)
    );
    // A missing/corrupt root requires a fresh random epoch; no old records match.
    let reestablished = Generation::next(current(0), None, epoch(9)).unwrap();
    assert_eq!(
        r.resolve(
            Some(reestablished),
            current(1),
            16,
            EntryKind::File,
            seconds
        ),
        seconds.map(hfs_to_filetime)
    );
}

fn state(bytes: &[u8]) -> VolumeState {
    VolumeState {
        id: bytes[1128..1136].try_into().unwrap(),
        created: volume::be32(bytes, 1040),
        write_count: volume::be32(bytes, 1092),
    }
}
fn seconds(body: &[u8]) -> [u32; 4] {
    [12, 24, 16, 20].map(|i| volume::be32(body, i))
}
fn fixture(journaled: bool, sensitive: bool) -> Vec<u8> {
    let mut d = MemoryBackend::new(8 * 1024 * 1024);
    let mut fs = HfsPlus::format(
        &mut d,
        &FormatOpts {
            journaled,
            ..Default::default()
        },
    )
    .unwrap();
    for path in ["/same-second", "/untouched"] {
        fs.create_file(
            &mut d,
            path,
            &mut &b"before edit"[..],
            11,
            0o644,
            501,
            20,
            1_700_000_000,
        )
        .unwrap();
    }
    fs.flush(&mut d).unwrap();
    let mut b = d.into_bytes();
    b[1128..1136].copy_from_slice(b"TS51vol!");
    if sensitive {
        b[1024..1026].copy_from_slice(b"HX");
        b[1026..1028].copy_from_slice(&5u16.to_be_bytes());
        let catalog = volume::be32(&b, 1312) as usize * 4096;
        b[catalog + 51] = 0xbc;
    }
    let alternate = b.len() - 1024;
    let header = b[1024..1536].to_vec();
    b[alternate..alternate + 512].copy_from_slice(&header);
    let mut d = MemoryBackend::from_bytes(b);
    let mut fs = engine::open_checked(&mut d).unwrap();
    let g = Generation::next(state(d.as_slice()), None, epoch(51)).unwrap();
    let mut records = Vec::new();
    for path in ["/same-second", "/untouched"] {
        let body = fs.catalog_record(path).unwrap();
        let cnid = volume::be32(&body, 8);
        let s = seconds(&body);
        records.push((
            cnid,
            PrecisionRecord::new(g, cnid, EntryKind::File, s, exact(s))
                .unwrap()
                .encode(),
        ));
    }
    let marker = g.encode();
    fs.set_small_attributes_batch(
        &mut d,
        &[
            (2, GENERATION_ATTRIBUTE, Some(&marker)),
            (records[0].0, TIMES_ATTRIBUTE, Some(&records[0].1)),
            (records[1].0, TIMES_ATTRIBUTE, Some(&records[1].1)),
        ],
    )
    .unwrap();
    fs.flush(&mut d).unwrap();
    assert!(g.matches(state(d.as_slice())));
    d.into_bytes()
}

#[test]
fn records_persist_with_atomic_generation_and_unchanged_flush_preserves_images() {
    for journaled in [false, true] {
        for sensitive in [false, true] {
            let bytes = fixture(journaled, sensitive);
            let mut d = MemoryBackend::from_bytes(bytes.clone());
            let mut fs = engine::open_checked(&mut d).unwrap();
            let v = state(d.as_slice());
            let g = Generation::decode(
                &fs.inline_attribute(&mut d, 2, GENERATION_ATTRIBUTE)
                    .unwrap()
                    .unwrap(),
            )
            .unwrap();
            assert!(g.matches(v));
            for path in ["/same-second", "/untouched"] {
                let b = fs.catalog_record(path).unwrap();
                let cnid = volume::be32(&b, 8);
                let s = seconds(&b);
                let r = PrecisionRecord::decode(
                    &fs.inline_attribute(&mut d, cnid, TIMES_ATTRIBUTE)
                        .unwrap()
                        .unwrap(),
                )
                .unwrap();
                assert_eq!(
                    r.resolve(Some(g), v, cnid, EntryKind::File, s),
                    exact(s).map(Option::unwrap)
                );
            }
            fs.flush(&mut d).unwrap();
            assert!(d.as_slice() == bytes);
            if let Some(dir) = std::env::var_os("HFS_TIMESTAMP_ARTIFACT_DIR") {
                std::fs::create_dir_all(&dir).unwrap();
                let path = std::path::PathBuf::from(dir)
                    .join(format!("timestamps-{journaled}-{sensitive}.img"));
                let mut file = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(path)
                    .unwrap();
                file.write_all(&bytes).unwrap();
                file.sync_all().unwrap();
            }
        }
    }
}

#[test]
#[ignore = "requires independently edited Mac return images"]
fn independent_mac_return_invalidates_old_precision_without_reviving_untouched_files() {
    let dir = std::env::var_os("HFS_TIMESTAMP_MAC_RETURN_DIR")
        .expect("native return images are required for this acceptance test");
    let mut checked = 0;
    for journaled in [false, true] {
        for sensitive in [false, true] {
            let name = format!("native-timestamps-{journaled}-{sensitive}.img");
            let bytes = std::fs::read(std::path::Path::new(&dir).join(name)).unwrap();
            let mut d = MemoryBackend::from_bytes(bytes.clone());
            let mut fs = engine::open_checked(&mut d).unwrap();
            let v = state(d.as_slice());
            let old = Generation::decode(
                &fs.inline_attribute(&mut d, 2, GENERATION_ATTRIBUTE)
                    .unwrap()
                    .unwrap(),
            )
            .unwrap();
            assert!(
                !old.matches(v),
                "native writer did not invalidate generation"
            );
            let fresh = Generation::next(v, Some(old), epoch(52)).unwrap();
            let mut entries = Vec::new();
            for path in ["/same-second", "/untouched"] {
                let b = fs.catalog_record(path).unwrap();
                let cnid = volume::be32(&b, 8);
                let s = seconds(&b);
                let r = PrecisionRecord::decode(
                    &fs.inline_attribute(&mut d, cnid, TIMES_ATTRIBUTE)
                        .unwrap()
                        .unwrap(),
                )
                .unwrap();
                assert_eq!(
                    s[2], 3_782_844_800,
                    "whole write second changed; experiment inconclusive"
                );
                assert_eq!(
                    r.resolve(Some(old), v, cnid, EntryKind::File, s),
                    s.map(hfs_to_filetime)
                );
                let mut data = Vec::new();
                fs.open_file_reader(&mut d, path)
                    .unwrap()
                    .read_to_end(&mut data)
                    .unwrap();
                assert_eq!(
                    data,
                    if path == "/same-second" {
                        b"after  edit"
                    } else {
                        b"before edit"
                    }
                );
                entries.push((cnid, s, r));
            }
            fs.flush(&mut d).unwrap();
            assert!(
                d.as_slice() == bytes,
                "unchanged native-return flush wrote bytes"
            );
            // Exercise the production committed-snapshot path against the
            // same real Mac publications, not only the record codec above.
            let mut view = hfs_bridge::windows::Adapter::from_read_only_device(
                MemoryBackend::from_bytes(bytes.clone()),
            )
            .unwrap();
            for (i, path) in [r"\same-second", r"\untouched"].iter().enumerate() {
                for _ in 0..3 {
                    let info = view.path_info(path).unwrap();
                    assert_eq!(
                        [
                            info.creation_time,
                            info.access_time,
                            info.write_time,
                            info.change_time
                        ],
                        entries[i].1.map(hfs_to_filetime),
                        "native publication must invalidate adapter precision snapshots"
                    );
                }
            }
            let mut returned = view.shutdown().unwrap();
            let mut compared = vec![0; bytes.len()];
            fstool::block::BlockDevice::read_at(&mut returned, 0, &mut compared).unwrap();
            assert_eq!(compared, bytes);
            let marker = fresh.encode();
            let new = PrecisionRecord::new(
                fresh,
                entries[0].0,
                EntryKind::File,
                entries[0].1,
                exact(entries[0].1),
            )
            .unwrap()
            .encode();
            fs.set_small_attributes_batch(
                &mut d,
                &[
                    (2, GENERATION_ATTRIBUTE, Some(&marker)),
                    (entries[0].0, TIMES_ATTRIBUTE, Some(&new)),
                ],
            )
            .unwrap();
            fs.flush(&mut d).unwrap();
            let v = state(d.as_slice());
            let fs = engine::open_checked(&mut d).unwrap();
            let g = Generation::decode(
                &fs.inline_attribute(&mut d, 2, GENERATION_ATTRIBUTE)
                    .unwrap()
                    .unwrap(),
            )
            .unwrap();
            assert!(g.matches(v));
            for (i, (cnid, s, _)) in entries.into_iter().enumerate() {
                let r = PrecisionRecord::decode(
                    &fs.inline_attribute(&mut d, cnid, TIMES_ATTRIBUTE)
                        .unwrap()
                        .unwrap(),
                )
                .unwrap();
                assert_eq!(
                    r.resolve(Some(g), v, cnid, EntryKind::File, s),
                    if i == 0 {
                        exact(s).map(Option::unwrap)
                    } else {
                        s.map(hfs_to_filetime)
                    }
                );
            }
            checked += 1;
        }
    }
    assert_eq!(checked, 4);
    println!(
        "MAC_TIMESTAMP_RETURN: 4 native Mac edits invalidated old fractions; 4 new epochs did not revive untouched records"
    );
}

#[derive(Debug, PartialEq, Eq)]
struct Publication {
    volume: VolumeState,
    marker: Vec<u8>,
    catalogs: Vec<Vec<u8>>,
    records: Vec<Vec<u8>>,
    resolved: Vec<[u64; 4]>,
}
fn observe_publication(bytes: Vec<u8>) -> Publication {
    let mut disk = MemoryBackend::from_bytes(bytes);
    // Explicit test-only replay; the production checked opener never repairs.
    let fs = HfsPlus::open(&mut disk).unwrap();
    let v = state(disk.as_slice());
    let marker = fs
        .inline_attribute(&mut disk, 2, GENERATION_ATTRIBUTE)
        .unwrap()
        .unwrap();
    let g = Generation::decode(&marker).unwrap();
    let mut result = Publication {
        volume: v,
        marker,
        catalogs: Vec::new(),
        records: Vec::new(),
        resolved: Vec::new(),
    };
    for path in ["/same-second", "/untouched"] {
        let body = fs.catalog_record(path).unwrap();
        let cnid = volume::be32(&body, 8);
        let bytes = fs
            .inline_attribute(&mut disk, cnid, TIMES_ATTRIBUTE)
            .unwrap()
            .unwrap();
        let record = PrecisionRecord::decode(&bytes).unwrap();
        result
            .resolved
            .push(record.resolve(Some(g), v, cnid, EntryKind::File, seconds(&body)));
        result.catalogs.push(body);
        result.records.push(bytes);
    }
    result
}
fn attempt_publication(bytes: &[u8], failure: Option<usize>) -> (bool, fault::Disk) {
    use fstool::block::BlockDevice;
    let mut disk = fault::Disk::new(bytes);
    let mut fs = HfsPlus::open(&mut disk).unwrap();
    let mut header = [0; 1136];
    disk.read_at(0, &mut header).unwrap();
    let g = Generation::decode(
        &fs.inline_attribute(&mut disk, 2, GENERATION_ATTRIBUTE)
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    let new_g = Generation::next(state(&header), Some(g), epoch(63)).unwrap();
    let body = fs.catalog_record("/same-second").unwrap();
    let cnid = volume::be32(&body, 8);
    let seconds = seconds(&body).map(|v| v + 99);
    let record = PrecisionRecord::new(new_g, cnid, EntryKind::File, seconds, exact(seconds))
        .unwrap()
        .encode();
    fs.set_small_attributes_batch(
        &mut disk,
        &[
            (2, GENERATION_ATTRIBUTE, Some(&new_g.encode())),
            (cnid, TIMES_ATTRIBUTE, Some(&record)),
        ],
    )
    .unwrap();
    fs.set_catalog_times(cnid, seconds.map(Some)).unwrap();
    disk.arm(failure);
    let pass = fs.flush(&mut disk).is_ok();
    if !pass {
        let calls = disk.0.lock().unwrap().calls;
        assert!(fs.flush(&mut disk).is_err());
        assert_eq!(calls, disk.0.lock().unwrap().calls);
    }
    (pass, disk)
}

#[test]
fn timestamp_catalog_epoch_and_precision_publish_together_across_injected_failures() {
    let mut checks = 0;
    for sensitive in [false, true] {
        for foreign in [false, true] {
            let mut bytes = fixture(true, sensitive);
            if foreign {
                // A foreign write left the private root attribute untouched.
                let count = state(&bytes).write_count + 1;
                let alternate = bytes.len() - 1024;
                for header in [1024, alternate] {
                    bytes[header + 68..header + 72].copy_from_slice(&count.to_be_bytes());
                }
            }
            let old = observe_publication(bytes.clone());
            let (pass, complete) = attempt_publication(&bytes, None);
            assert!(pass);
            let new = observe_publication(complete.0.lock().unwrap().durable.clone());
            assert_ne!(old, new);
            assert_eq!(
                new.resolved[0],
                exact(seconds(&new.catalogs[0])).map(Option::unwrap)
            );
            assert_eq!(
                new.resolved[1],
                if foreign {
                    seconds(&new.catalogs[1]).map(hfs_to_filetime)
                } else {
                    exact(seconds(&new.catalogs[1])).map(Option::unwrap)
                }
            );
            let info = volume::be32(&bytes, 1036) as usize * volume::be32(&bytes, 1064) as usize;
            let journal = volume::be64(&bytes, info + 36) as usize;
            let boundaries = complete.0.lock().unwrap().calls;
            for failure in 0..boundaries {
                let (pass, disk) = attempt_publication(&bytes, Some(failure));
                assert!(!pass);
                for policy in 0..6 {
                    let snapshot = disk.snapshot(policy, journal);
                    let observed = observe_publication(snapshot);
                    assert!(
                        observed == old || observed == new,
                        "partial timestamp publication: {sensitive}/{foreign}/{failure}/{policy}"
                    );
                    checks += 1;
                }
            }
        }
    }
    println!(
        "TIMESTAMP_PUBLICATION: {checks} persistence snapshots; 4 journaled scenarios, including epoch renewal"
    );
}
