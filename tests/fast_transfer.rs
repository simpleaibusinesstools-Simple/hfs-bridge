use fstool::{
    block::{BlockDevice, MemoryBackend},
    fs::hfs_plus::{FormatOpts, HfsPlus},
};
use hfs_bridge::{engine, transfer, volume};
use std::io::{self, Read};
#[path = "support/fault_disk.rs"]
mod fault;

fn fixture(journaled: bool) -> Vec<u8> {
    let mut d = MemoryBackend::new(8 * 1024 * 1024);
    let mut fs = HfsPlus::format(
        &mut d,
        &FormatOpts {
            journaled,
            ..Default::default()
        },
    )
    .unwrap();
    fs.create_file(
        &mut d,
        "/keep.txt",
        &mut b"protected reference".as_slice(),
        19,
        0o640,
        501,
        20,
        1700000000,
    )
    .unwrap();
    fs.flush(&mut d).unwrap();
    d.into_bytes()
}
fn payload(d: &mut dyn BlockDevice, path: &str) -> Option<Vec<u8>> {
    let fs = HfsPlus::open(d).unwrap();
    if fs.catalog_record(path).is_err() {
        return None;
    }
    let mut bytes = Vec::new();
    fs.open_file_reader(d, path)
        .unwrap()
        .read_to_end(&mut bytes)
        .unwrap();
    Some(bytes)
}
#[test]
fn complete_file_is_streamed_verified_and_existing_metadata_is_preserved() {
    for journaled in [false, true] {
        for size in [0, 1, 4095, 4096, 1048599] {
            let mut d = MemoryBackend::from_bytes(fixture(journaled));
            let old = engine::snapshot_device(&mut d, "/keep.txt", &[]).unwrap();
            let data = (0..size).map(|i| (i * 31) as u8).collect::<Vec<_>>();
            let mut events = Vec::new();
            let result = transfer::copy_file(
                &mut d,
                &mut data.as_slice(),
                size as u64,
                "/Transfer check/é file.bin",
                1700000000,
                |phase, bytes, total| events.push((phase.to_owned(), bytes, total)),
            )
            .unwrap();
            assert_eq!(result.bytes, size as u64);
            assert_eq!(
                result.sha256,
                engine::sha256(&mut data.as_slice()).unwrap().to_uppercase()
            );
            assert_eq!(payload(&mut d, "/Transfer check/é file.bin"), Some(data));
            assert_eq!(
                engine::snapshot_device(&mut d, "/keep.txt", &[]).unwrap(),
                old
            );
            assert!(events.iter().any(|(phase, _, _)| phase == "committing"));
            assert!(events.iter().all(|(_, n, total)| *n <= *total));
            volume::require_engine_access(&volume::inspect(&mut d).unwrap()).unwrap();
        }
    }
}
#[test]
fn collision_and_case_alias_never_change_existing_folder_or_file() {
    let mut d = MemoryBackend::from_bytes(fixture(true));
    transfer::copy_file(
        &mut d,
        &mut b"first".as_slice(),
        5,
        "/Copies/file.bin",
        1700000000,
        |_, _, _| {},
    )
    .unwrap();
    let before = d.as_slice().to_vec();
    for path in ["/Copies/file.bin", "/copies/another.bin"] {
        assert!(
            transfer::copy_file(
                &mut d,
                &mut b"replacement".as_slice(),
                11,
                path,
                1700000000,
                |_, _, _| {}
            )
            .is_err()
        );
        assert_eq!(d.as_slice(), before);
    }
}
#[test]
fn malformed_destinations_and_insufficient_space_do_not_write() {
    for path in [
        "/file",
        "/a/b/c",
        "/../file",
        "/new/CON",
        "/new/file:stream",
        "/new/../bad",
        "/new//file",
        "relative",
    ] {
        assert!(transfer::validate_destination(path).is_err(), "{path}");
    }
    let mut d = MemoryBackend::from_bytes(fixture(true));
    let before = d.as_slice().to_vec();
    assert!(
        transfer::copy_file(
            &mut d,
            &mut io::empty(),
            u64::MAX,
            "/new/file",
            1700000000,
            |_, _, _| {}
        )
        .is_err()
    );
    assert_eq!(d.as_slice(), before);
}
#[test]
fn short_growing_or_failing_sources_never_publish_an_incomplete_file() {
    struct Fails;
    impl Read for Fails {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::other("source failed"))
        }
    }
    for variant in 0..3 {
        let mut d = MemoryBackend::from_bytes(fixture(true));
        let data = b"length";
        let mut input: Box<dyn Read> = if variant == 2 {
            Box::new(Fails)
        } else {
            Box::new(data.as_slice())
        };
        let length = if variant == 0 { 7 } else { 5 };
        assert!(
            transfer::copy_file(
                &mut d,
                &mut input,
                length,
                "/new/file",
                1700000000,
                |_, _, _| {}
            )
            .is_err()
        );
        assert!(payload(&mut d, "/new/file").is_none());
        assert_eq!(
            payload(&mut d, "/keep.txt"),
            Some(b"protected reference".to_vec())
        );
        volume::require_engine_access(&volume::inspect(&mut d).unwrap()).unwrap();
    }
}
#[test]
fn interrupted_publication_recovers_only_absent_or_complete_payload() {
    let original = fixture(true);
    let data = vec![0xA7; 131101];
    let info = volume::be32(&original, 1036) as usize * 4096;
    let journal = volume::be64(&original, info + 36) as usize;
    let mut baseline = fault::Disk::new(&original);
    baseline.arm(None);
    transfer::copy_file(
        &mut baseline,
        &mut data.as_slice(),
        data.len() as u64,
        "/new/payload.bin",
        1700000000,
        |_, _, _| {},
    )
    .unwrap();
    let calls = baseline.0.lock().unwrap().calls;
    let mut snapshots = 0;
    for failure in 0..calls {
        let mut d = fault::Disk::new(&original);
        d.arm(Some(failure));
        assert!(
            transfer::copy_file(
                &mut d,
                &mut data.as_slice(),
                data.len() as u64,
                "/new/payload.bin",
                1700000000,
                |_, _, _| {}
            )
            .is_err()
        );
        for policy in 0..6 {
            let mut recovered = MemoryBackend::from_bytes(d.snapshot(policy, journal));
            assert_eq!(
                payload(&mut recovered, "/keep.txt"),
                Some(b"protected reference".to_vec())
            );
            let saved = payload(&mut recovered, "/new/payload.bin");
            assert!(
                saved.is_none() || saved == Some(data.clone()),
                "partial payload at {failure}/{policy}"
            );
            snapshots += 1;
        }
    }
    println!("FAST_TRANSFER_RECOVERY: {calls} boundaries, {snapshots} persistence snapshots");
}
