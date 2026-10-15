//! Pure planning checks; these do not claim native stream callback acceptance.
use hfs_bridge::{
    named_streams::{self as wire, Store, Stream},
    windows::Status,
};
fn valid(store: &Store) {
    assert_eq!(&wire::decode(&wire::encode(store).unwrap()).unwrap(), store);
}
#[test]
fn creation_identity_case_and_deletion_do_not_reuse_ids_or_mutate_sources() {
    let original = Store::default();
    let (one, id) = original.with_created("Zone.Identifier", 0, 4096).unwrap();
    assert_eq!(original, Store::default());
    assert_eq!(id, 1);
    assert_eq!(
        one.find("zone.identifier").unwrap().unwrap().name,
        "Zone.Identifier"
    );
    assert_eq!(
        one.with_created("ZONE.IDENTIFIER", 0, 4096)
            .unwrap_err()
            .status,
        Status::Collision
    );
    let (empty, retained) = one.without(id).unwrap();
    let (two, next) = empty.with_created("ZONE.IDENTIFIER", 0, 4096).unwrap();
    assert_eq!(retained.id, 1);
    assert_eq!(next, 2);
    assert_eq!(two.next_id, 3);
    assert_eq!(one.streams.len(), 1);
    assert_eq!(empty.next_id, 2);
    assert_eq!(two.without(1).unwrap_err().status, Status::NotFound);
    let (three, _) = two.with_created("é", 0, 4096).unwrap();
    let (four, _) = three.with_created("e\u{301}", 0, 4096).unwrap();
    assert_eq!(four.streams.len(), 3);
    valid(&four);
}
#[test]
fn data_append_holes_constrained_writes_and_zero_requests_are_bounded() {
    let (a, id) = Store::default().with_created("stream", 0, 4096).unwrap();
    let (b, n) = a.with_write(id, 100, b"abc", false, false, 4096).unwrap();
    assert_eq!(n, 3);
    assert_eq!(&b.streams[0].data[..100], &[0; 100]);
    let (c, n) = b
        .with_write(id, u64::MAX, b"def", true, false, 4096)
        .unwrap();
    assert_eq!(n, 3);
    assert_eq!(&c.streams[0].data[100..], b"abcdef");
    let (d, n) = c.with_write(id, 104, b"12345", false, true, 4096).unwrap();
    assert_eq!(n, 2);
    assert_eq!(&d.streams[0].data[100..], b"abcd12");
    for (offset, append) in [(u64::MAX, false), (0, true)] {
        let (unchanged, n) = d.with_write(id, offset, b"x", append, true, 4096).unwrap();
        assert_eq!(n, 0);
        assert_eq!(unchanged, d);
    }
    assert_eq!(
        d.with_write(id, u64::MAX, b"", false, false, 4096).unwrap(),
        (d.clone(), 0)
    );
    assert!(
        d.with_write(id, u64::MAX, b"x", false, false, 4096)
            .is_err()
    );
    assert!(a.streams[0].data.is_empty());
    valid(&d);
}
#[test]
fn allocation_and_eof_follow_observed_nonresident_ntfs_sequence() {
    let (a, id) = Store::default().with_created("probe", 0, 4096).unwrap();
    let b = a.with_allocation(id, 20019, 4096).unwrap();
    assert_eq!(
        (b.streams[0].allocation, b.streams[0].data.len()),
        (20480, 0)
    );
    let c = b
        .with_size(id, 12001, 4096)
        .unwrap()
        .with_write(id, 0, &vec![29; 12001], false, false, 4096)
        .unwrap()
        .0;
    let d = c.with_allocation(id, 4097, 4096).unwrap();
    assert_eq!(
        (d.streams[0].allocation, d.streams[0].data.len()),
        (8192, 8192)
    );
    let e = d.with_size(id, 10001, 4096).unwrap();
    assert_eq!(e.streams[0].allocation, 12288);
    assert!(e.streams[0].data[8192..].iter().all(|&b| b == 0));
    let f = e.with_size(id, 100, 4096).unwrap();
    assert_eq!(f.streams[0].allocation, 12288);
    let g = f.with_trimmed_allocation(id, 4096).unwrap();
    assert_eq!(g.streams[0].allocation, 4096);
    let h = g.with_allocation(id, 0, 4096).unwrap();
    assert_eq!((h.streams[0].allocation, h.streams[0].data.len()), (0, 0));
    for store in [&a, &b, &c, &d, &e, &f, &g, &h] {
        valid(store);
    }
}
#[test]
fn limits_exhaustion_invalid_inputs_and_aggregate_bounds_leave_original_unchanged() {
    let (one, id) = Store::default().with_created("one", 0, 4096).unwrap();
    let before = wire::encode(&one).unwrap();
    for size in [u64::MAX, wire::MAX_BYTES as u64] {
        assert!(one.with_allocation(id, size, 4096).is_err());
        assert!(one.with_size(id, size, 4096).is_err());
        assert!(one.with_created("other", size, 4096).is_err());
        assert!(one.with_write(id, size, b"x", false, false, 4096).is_err());
    }
    for unit in [0, 1, 511, 513, 131072] {
        assert!(one.with_size(id, 1, unit).is_err());
    }
    let mut full = one.clone();
    for n in 1..wire::MAX_STREAMS {
        full = full.with_created(&format!("s{n}"), 0, 512).unwrap().0;
    }
    assert!(full.with_created("extra", 0, 512).is_err());
    valid(&full);
    let exhausted = Store {
        next_id: u64::MAX,
        streams: vec![],
    };
    assert!(exhausted.with_created("last", 0, 4096).is_err());
    let corrupt = Store {
        next_id: 1,
        streams: vec![Stream {
            id: 1,
            name: "bad".into(),
            data: vec![1],
            allocation: 0,
        }],
    };
    assert!(corrupt.without(1).is_err());
    assert!(corrupt.with_write(1, 0, b"", false, false, 4096).is_err());
    let (large, second) = one
        .with_created("large", (wire::MAX_BYTES - 4096) as u64, 4096)
        .unwrap();
    assert!(large.with_allocation(id, 4096, 4096).is_err());
    assert!(
        large
            .with_size(second, wire::MAX_BYTES as u64, 4096)
            .is_err()
    );
    assert_eq!(wire::encode(&one).unwrap(), before);
    valid(&large);
}

#[test]
fn deterministic_mixed_edits_match_independent_byte_model_across_allocation_units() {
    let mut cases = 0;
    for unit in [512, 4096, 65536] {
        let (mut store, id) = Store::default().with_created("model", 0, unit).unwrap();
        let mut bytes = Vec::new();
        let mut allocation = 0usize;
        let mut seed = 0x12345678u32;
        for _ in 0..2000 {
            seed = seed.wrapping_mul(1664525).wrapping_add(1013904223);
            let size = (seed as usize >> 8) % 20000;
            let round = |n: usize| n.div_ceil(unit as usize) * unit as usize;
            match seed % 4 {
                0 => {
                    store = store.with_size(id, size as u64, unit).unwrap();
                    bytes.resize(size, 0);
                    allocation = allocation.max(round(size));
                }
                1 => {
                    store = store.with_allocation(id, size as u64, unit).unwrap();
                    allocation = round(size);
                    bytes.truncate(allocation);
                }
                2 => {
                    let payload = seed.to_le_bytes();
                    store = store
                        .with_write(id, size as u64, &payload, false, false, unit)
                        .unwrap()
                        .0;
                    bytes.resize(bytes.len().max(size + 4), 0);
                    bytes[size..size + 4].copy_from_slice(&payload);
                    allocation = allocation.max(round(size + 4));
                }
                _ => {
                    store = store.with_trimmed_allocation(id, unit).unwrap();
                    allocation = round(bytes.len());
                }
            }
            assert_eq!(store.streams[0].data, bytes);
            assert_eq!(store.streams[0].allocation, allocation as u64);
            valid(&store);
            cases += 1;
        }
    }
    eprintln!("NAMED_MUTATION_MODEL: {cases} bounded operations passed");
}
