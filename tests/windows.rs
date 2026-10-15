use fstool::{
    block::{BlockDevice, MemoryBackend},
    fs::hfs_plus::{FormatOpts, HfsPlus},
};
use hfs_bridge::{
    engine,
    image::Image,
    volume,
    windows::{
        Access, Adapter, BasicTimes, Handle, Kind, OpenRequest, Share, Status, filetime_to_hfs,
        hfs_to_filetime,
    },
};
use std::{
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

fn all() -> OpenRequest {
    OpenRequest {
        access: Access::ALL,
        ..Default::default()
    }
}
fn fixture(journaled: bool, sensitive: bool) -> MemoryBackend {
    let mut disk = MemoryBackend::new(32 * 1024 * 1024);
    let mut fs = HfsPlus::format(
        &mut disk,
        &FormatOpts {
            journaled,
            ..Default::default()
        },
    )
    .unwrap();
    if sensitive {
        drop(fs);
        let mut bytes = disk.into_bytes();
        bytes[1024..1026].copy_from_slice(b"HX");
        bytes[1026..1028].copy_from_slice(&5u16.to_be_bytes());
        let cat = volume::be32(&bytes, 1312) as usize * 4096;
        bytes[cat + 51] = 0xbc;
        let header = bytes[1024..1536].to_vec();
        let alternate = bytes.len() - 1024;
        bytes[alternate..alternate + 512].copy_from_slice(&header);
        disk = MemoryBackend::from_bytes(bytes);
        fs = HfsPlus::open(&mut disk).unwrap();
    }
    fs.create_dir(&mut disk, "/Folder", 0o755, 501, 20, 1_700_000_000)
        .unwrap();
    for (name, data) in [
        ("file.txt", &b"original"[..]),
        ("CON.txt", &b"reserved"[..]),
        ("slash:name.bin", &b"mac slash"[..]),
    ] {
        fs.create_file(
            &mut disk,
            &format!("/Folder/{name}"),
            &mut &data[..],
            data.len() as u64,
            0o640,
            501,
            20,
            1_700_000_000,
        )
        .unwrap();
    }
    if sensitive {
        for name in ["case.txt", "CASE.txt"] {
            fs.create_file(
                &mut disk,
                &format!("/Folder/{name}"),
                &mut name.as_bytes(),
                name.len() as u64,
                0o644,
                0,
                0,
                0,
            )
            .unwrap();
        }
    }
    fs.flush(&mut disk).unwrap();
    disk
}
fn read<D: BlockDevice>(adapter: &mut Adapter<D>, handle: Handle) -> Vec<u8> {
    let mut bytes = vec![0; adapter.file_info(handle).unwrap().size as usize];
    let mut offset = 0;
    while offset < bytes.len() {
        let count = adapter
            .read(handle, offset as u64, &mut bytes[offset..])
            .unwrap();
        assert!(count > 0);
        offset += count;
    }
    bytes
}

#[test]
fn readonly_repeated_directory_views_preserve_aliases_and_case_collisions() {
    let request = OpenRequest {
        access: Access::READ,
        ..Default::default()
    };
    for sensitive in [false, true] {
        let bytes = fixture(true, sensitive).into_bytes();
        let mut original = Adapter::from_device(MemoryBackend::from_bytes(bytes.clone())).unwrap();
        let folder = original.open(r"\Folder", request).unwrap();
        let entries = original.read_directory(folder).unwrap();
        assert_eq!(
            entries.iter().filter(|entry| entry.aliased).count(),
            if sensitive { 4 } else { 2 }
        );
        let mut expected = Vec::new();
        for entry in entries {
            let path = format!(r"\Folder\{}", entry.name);
            let file = original.open(&path, request).unwrap();
            expected.push((path, entry.info.cnid, read(&mut original, file)));
            original.close(file).unwrap();
        }
        let mut cached = Adapter::from_read_only_device(MemoryBackend::from_bytes(bytes)).unwrap();
        for _ in 0..4 {
            for (path, cnid, data) in &expected {
                let handle = cached.open(path, request).unwrap();
                assert_eq!(cached.file_info(handle).unwrap().cnid, *cnid);
                assert_eq!(&read(&mut cached, handle), data);
                cached.close(handle).unwrap();
            }
            assert!(cached.open(r"\Folder\~HFS-DEADBEEF.txt", request).is_err());
            assert!(cached.open(r"\Folder\CON.txt", request).is_err());
        }
        cached.shutdown().unwrap();
    }
}
fn retain(disk: &MemoryBackend, name: &str) {
    if let Some(directory) = std::env::var_os("HFS_CRASH_ARTIFACT_DIR") {
        let path = Path::new(&directory).join(name);
        let mut file = hfs_bridge::image::create_output(&path).unwrap();
        file.write_all(disk.as_slice()).unwrap();
        file.sync_all().unwrap();
    }
}

#[test]
fn constructor_attribute_and_data_allocations_preflight_combined_space() {
    let mut adapter = Adapter::from_device(fixture(true, false)).unwrap();
    let free = adapter.volume_info().unwrap().free_bytes;
    let filler = adapter
        .create_initialized(r"\filler", Kind::File, all(), None, free - 32768)
        .unwrap();
    let changes = [hfs_bridge::ea::Change {
        name: "com.example.initial".into(),
        value: Some(b"metadata".to_vec()),
    }];
    assert_eq!(
        adapter
            .create_initialized_with_ea(r"\refused", Kind::File, all(), None, 32768, &changes)
            .unwrap_err()
            .status,
        Status::DiskFull
    );
    assert!(adapter.open(r"\refused", all()).is_err());
    let old = adapter.open(r"\Folder\file.txt", all()).unwrap();
    assert_eq!(
        adapter
            .overwrite_with_ea(old, 0x80, true, 32768, &changes)
            .unwrap_err()
            .status,
        Status::DiskFull
    );
    assert_eq!(read(&mut adapter, old), b"original");
    assert!(adapter.extended_attributes(old).unwrap().is_empty());
    assert!(adapter.failure().is_none());
    adapter.close(old).unwrap();
    adapter.close(filler).unwrap();
    adapter.shutdown().unwrap();
}
#[test]
fn finder_stream_and_eas_share_catalog_metadata_without_touching_forks() {
    for (journal, sensitive) in [(false, false), (true, false), (true, true)] {
        let mut adapter = Adapter::from_device(fixture(journal, sensitive)).unwrap();
        let main = adapter.open(r"\Folder\file.txt", all()).unwrap();
        let finder = adapter
            .create(r"\Folder\file.txt:AFP_AfpInfo", Kind::File, all())
            .unwrap();
        let mut metadata = [0; 32];
        metadata[..8].copy_from_slice(b"TEXTttxt");
        metadata[8] = 0x40;
        metadata[26] = 17;
        let bytes = hfs_bridge::afp::encode(&metadata, 3_900_000_000).unwrap();
        adapter.write(finder, 0, &bytes, false, false).unwrap();
        assert_eq!(adapter.file_info(finder).unwrap().size, 60);
        assert_eq!(adapter.file_info(main).unwrap().attributes & 2, 2);
        assert_eq!(read(&mut adapter, main), b"original");
        assert_eq!(read(&mut adapter, finder), bytes);
        let values = hfs_bridge::ea::encode(&adapter.extended_attributes(main).unwrap()).unwrap();
        assert_eq!(
            hfs_bridge::ea::changes(&values, &[]).unwrap()[0]
                .value
                .as_deref(),
            Some(metadata.as_slice())
        );
        let mut bad = bytes;
        bad[48] = 1;
        assert!(adapter.write(finder, 0, &bad, false, false).is_err());
        assert!(adapter.set_size(finder, 61).is_err());
        assert!(adapter.rename(finder, r"\renamed").is_err());
        assert_eq!(read(&mut adapter, finder), bytes);
        adapter.rename(main, r"\Folder\renamed.txt").unwrap();
        assert_eq!(read(&mut adapter, finder), bytes);
        adapter.close(finder).unwrap();
        adapter.close(main).unwrap();
        let disk = adapter.shutdown().unwrap();
        retain(&disk, &format!("finder-{}-{}.img", journal, sensitive));
        let mut adapter = Adapter::from_device(disk).unwrap();
        let finder = adapter
            .open(r"\Folder\renamed.txt:AFP_AfpInfo:$DATA", all())
            .unwrap();
        assert_eq!(read(&mut adapter, finder), bytes);
        adapter.cleanup(finder, true).unwrap();
        adapter.close(finder).unwrap();
        assert!(
            adapter
                .open(r"\Folder\renamed.txt:AFP_AfpInfo", all())
                .is_err()
        );
        let main = adapter.open(r"\Folder\renamed.txt", all()).unwrap();
        assert_eq!(read(&mut adapter, main), b"original");
        assert!(adapter.extended_attributes(main).unwrap().is_empty());
        adapter.close(main).unwrap();
        adapter.shutdown().unwrap();
    }
}
#[test]
fn extended_attribute_batches_preserve_payload_and_enforce_ea_specific_rights() {
    for (journaled, sensitive) in [(false, false), (true, false), (true, true)] {
        let mut adapter = Adapter::from_device(fixture(journaled, sensitive)).unwrap();
        let file = adapter.open(r"\Folder\file.txt", all()).unwrap();
        let original = adapter.file_info(file).unwrap();
        let values = vec![
            ("com.example.CASE".to_owned(), b"UPPER\0\xff".to_vec()),
            ("com.example.case".to_owned(), b"lower".to_vec()),
            ("com.example.empty".to_owned(), vec![]),
            ("com.example.large".to_owned(), vec![0x39; 20_019]),
        ];
        let packet = hfs_bridge::ea::encode(&hfs_bridge::ea::records(&values).unwrap()).unwrap();
        adapter.set_extended_attributes(file, &packet).unwrap();
        let info = adapter.file_info_with_ea(file).unwrap();
        assert_eq!(info.ea_size, packet.len() as u32);
        assert_eq!(
            (
                info.cnid,
                info.size,
                info.mac_uid,
                info.mac_gid,
                info.mac_mode
            ),
            (
                original.cnid,
                original.size,
                original.mac_uid,
                original.mac_gid,
                original.mac_mode
            )
        );
        let read = adapter
            .open(
                r"\Folder\file.txt",
                OpenRequest {
                    access: Access::READ,
                    ..Default::default()
                },
            )
            .unwrap();
        let copied = hfs_bridge::ea::encode(&adapter.extended_attributes(read).unwrap()).unwrap();
        let mut got = hfs_bridge::ea::changes(&copied, &[]).unwrap();
        got.sort_by(|a, b| a.name.cmp(&b.name));
        let mut expected = values
            .iter()
            .map(|(name, value)| hfs_bridge::ea::Change {
                name: name.clone(),
                value: Some(value.clone()),
            })
            .collect::<Vec<_>>();
        expected.sort_by(|a, b| a.name.cmp(&b.name));
        assert_eq!(got, expected);
        assert_eq!(
            adapter
                .set_extended_attributes(read, &packet)
                .unwrap_err()
                .status,
            Status::AccessDenied
        );
        let metadata = adapter
            .open(
                r"\Folder\file.txt",
                OpenRequest {
                    access: Access {
                        metadata: true,
                        ..Access::READ
                    },
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(
            adapter
                .set_extended_attributes(metadata, &packet)
                .unwrap_err()
                .status,
            Status::AccessDenied
        );
        let data_only = adapter
            .open(
                r"\Folder\file.txt",
                OpenRequest {
                    access: Access {
                        read: true,
                        ..Default::default()
                    },
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(
            adapter.extended_attributes(data_only).unwrap_err().status,
            Status::AccessDenied
        );
        assert!(adapter.set_extended_attributes(file, &[0; 8]).is_err());
        assert!(adapter.failure().is_none());
        assert_eq!(
            adapter.extended_attributes(file).unwrap(),
            adapter.extended_attributes(read).unwrap()
        );
        let deletion = hfs_bridge::ea::encode(&[hfs_bridge::ea::Record {
            name: hfs_bridge::ea::alias("com.example.CASE").unwrap(),
            value: vec![],
        }])
        .unwrap();
        adapter.set_extended_attributes(file, &deletion).unwrap();
        adapter.rename(file, r"\Folder\ea-renamed.txt").unwrap();
        let remaining = hfs_bridge::ea::changes(
            &hfs_bridge::ea::encode(&adapter.extended_attributes(file).unwrap()).unwrap(),
            &[],
        )
        .unwrap();
        assert_eq!(remaining.len(), 3);
        assert!(remaining.iter().all(|c| c.name != "com.example.CASE"));
        assert!(
            remaining
                .iter()
                .any(|c| c.name == "com.example.empty" && c.value == Some(vec![]))
        );
        let directory = adapter.open(r"\Folder", all()).unwrap();
        adapter.set_extended_attributes(directory, &packet).unwrap();
        assert_eq!(adapter.extended_attributes(directory).unwrap().len(), 4);
        for handle in [file, read, metadata, data_only, directory] {
            adapter.close(handle).unwrap();
        }
        let disk = adapter.shutdown().unwrap();
        retain(&disk, &format!("windows-ea-{journaled}-{sensitive}.img"));
        let mut disk = disk;
        let mut payload = Vec::new();
        HfsPlus::open(&mut disk)
            .unwrap()
            .open_file_reader(&mut disk, "/Folder/ea-renamed.txt")
            .unwrap()
            .read_to_end(&mut payload)
            .unwrap();
        assert_eq!(payload, b"original");
    }
}

#[test]
fn live_handles_follow_file_and_parent_renames() {
    for journaled in [false, true] {
        let mut adapter = Adapter::from_device(fixture(journaled, false)).unwrap();
        let file = adapter.open(r"\Folder\file.txt", all()).unwrap();
        let second = adapter
            .open(r"\folder\FILE.TXT", Default::default())
            .unwrap();
        let original = adapter.file_info(file).unwrap();
        let directory = adapter.open(r"\Folder", all()).unwrap();
        adapter.rename(file, r"\Folder\renamed.txt").unwrap();
        adapter.rename(directory, r"\Moved").unwrap();
        assert_eq!(adapter.file_info(second).unwrap().cnid, original.cnid);
        assert_eq!(read(&mut adapter, second), b"original");
        adapter.write(file, 3, b"PATCH", false, false).unwrap();
        assert_eq!(read(&mut adapter, second), b"oriPATCH");
        assert_eq!(
            adapter.open(r"\Folder\file.txt", all()).unwrap_err().status,
            Status::NotFound
        );
        assert_eq!(
            adapter
                .read_directory(directory)
                .unwrap()
                .iter()
                .find(|e| e.info.cnid == original.cnid)
                .unwrap()
                .name,
            "renamed.txt"
        );
        adapter.close(file).unwrap();
        adapter.close(second).unwrap();
        adapter.close(directory).unwrap();
        let mut disk = adapter.shutdown().unwrap();
        let fs = engine::open_checked(&mut disk).unwrap();
        let body = fs.catalog_record("/Moved/renamed.txt").unwrap();
        assert_eq!(volume::be32(&body, 8), original.cnid);
        assert_eq!(volume::be16(&body, 42), original.mac_mode);
        assert_eq!(volume::be32(&body, 32), original.mac_uid);
        assert_eq!(volume::be32(&body, 36), original.mac_gid);
        assert_eq!(
            volume::be32(&body, 12),
            filetime_to_hfs(original.creation_time).unwrap()
        );
        retain(
            &disk,
            &format!(
                "windows-renames-{}.img",
                if journaled { "journaled" } else { "plain" }
            ),
        );
    }
}

#[test]
fn new_windows_entries_inherit_destination_mac_owner_without_special_permissions() {
    for journaled in [false, true] {
        let mut disk = fixture(journaled, false);
        let mut fs = engine::open_checked(&mut disk).unwrap();
        use fstool::fs::SetAttrs;
        fs.set_attrs(
            &mut disk,
            "/Folder",
            SetAttrs {
                mode: Some(0o2770),
                uid: Some(1234),
                gid: Some(4321),
                ..Default::default()
            },
        )
        .unwrap();
        fs.flush(&mut disk).unwrap();
        let before_parent = fs.catalog_record("/Folder").unwrap();
        let mut adapter = Adapter::from_device(disk).unwrap();
        let folder = adapter
            .create(r"\Folder\New", Kind::Directory, all())
            .unwrap();
        let file = adapter
            .create(r"\Folder\New\Data", Kind::File, all())
            .unwrap();
        let top_file = adapter
            .create(r"\Folder\Direct", Kind::File, all())
            .unwrap();
        for handle in [folder, file, top_file] {
            let info = adapter.file_info(handle).unwrap();
            assert_eq!((info.mac_uid, info.mac_gid), (1234, 4321));
            assert_eq!(info.mac_mode & 0o7000, 0);
        }
        assert_eq!(adapter.file_info(file).unwrap().mac_mode & 0o777, 0o644);
        assert_eq!(adapter.file_info(folder).unwrap().mac_mode & 0o777, 0o755);
        adapter
            .write(file, 0, b"Mac owner survives reopen", false, false)
            .unwrap();
        for handle in [folder, file, top_file] {
            adapter.close(handle).unwrap();
        }
        let mut disk = adapter.shutdown().unwrap();
        let fs = engine::open_checked(&mut disk).unwrap();
        for path in ["/Folder/New", "/Folder/New/Data", "/Folder/Direct"] {
            let body = fs.catalog_record(path).unwrap();
            assert_eq!(
                (volume::be32(&body, 32), volume::be32(&body, 36)),
                (1234, 4321)
            );
        }
        let after_parent = fs.catalog_record("/Folder").unwrap();
        assert_eq!(&before_parent[32..48], &after_parent[32..48]);
        assert_eq!(
            &fs.catalog_record("/Folder/file.txt").unwrap()[32..40],
            &[0, 0, 1, 245, 0, 0, 0, 20]
        );
        retain(
            &disk,
            &format!(
                "windows-owner-{}.img",
                if journaled { "journaled" } else { "plain" }
            ),
        );
    }
}

#[test]
fn native_attributes_survive_reopen_and_preserve_mac_metadata() {
    for journaled in [false, true] {
        let disk = fixture(journaled, false);
        let mut adapter = Adapter::from_device(disk).unwrap();
        let handle = adapter.open(r"\Folder\file.txt", all()).unwrap();
        let before = adapter.file_info(handle).unwrap();
        assert_ne!(before.attributes & 0x20, 0);
        adapter
            .set_basic_info(handle, Default::default(), Some(0x23))
            .unwrap();
        assert_eq!(adapter.file_info(handle).unwrap().attributes, 0x23);
        assert_eq!(
            adapter
                .write(handle, 0, b"blocked", false, false)
                .unwrap_err()
                .status,
            Status::AccessDenied
        );
        adapter
            .set_basic_info(handle, Default::default(), Some(2))
            .unwrap();
        assert_eq!(adapter.file_info(handle).unwrap().attributes, 2);
        adapter.write(handle, 0, b"new", false, false).unwrap();
        assert_eq!(adapter.file_info(handle).unwrap().attributes, 0x22);
        adapter
            .set_basic_info(handle, Default::default(), Some(2))
            .unwrap();
        adapter.close(handle).unwrap();
        let mut disk = adapter.shutdown().unwrap();
        let fs = engine::open_checked(&mut disk).unwrap();
        let body = fs.catalog_record("/Folder/file.txt").unwrap();
        assert_eq!(volume::be32(&body, 28), volume::be32(&body, 16));
        assert_eq!(volume::be16(&body, 56) & 0x4000, 0x4000);
        assert_eq!(volume::be16(&body, 42), before.mac_mode);
        assert_eq!(volume::be32(&body, 32), before.mac_uid);
        assert_eq!(volume::be32(&body, 36), before.mac_gid);
        let mut reopened = Adapter::from_device(disk).unwrap();
        let handle = reopened.open(r"\Folder\file.txt", all()).unwrap();
        assert_eq!(reopened.file_info(handle).unwrap().attributes, 2);
        assert_eq!(read(&mut reopened, handle), b"newginal");
        reopened.close(handle).unwrap();
        retain(
            &reopened.shutdown().unwrap(),
            &format!("windows-attributes-{journaled}.img"),
        );
    }
}

#[test]
fn readonly_copy_constructors_finish_data_and_streams_before_locking() {
    for journaled in [false, true] {
        let mut adapter = Adapter::from_device(fixture(journaled, false)).unwrap();
        let base = adapter
            .create_initialized(r"\readonly-copy.bin", Kind::File, all(), Some(0x21), 4096)
            .unwrap();
        adapter
            .write(base, 0, b"copied payload", false, false)
            .unwrap();
        adapter.set_size(base, 14).unwrap();
        let resource = adapter
            .create(r"\readonly-copy.bin:AFP_Resource", Kind::File, all())
            .unwrap();
        adapter
            .write(resource, 0, b"user resource", false, false)
            .unwrap();
        adapter
            .set_basic_info(base, Default::default(), Some(0x21))
            .unwrap();
        adapter.cleanup(base, false).unwrap();
        adapter.close(base).unwrap();
        // A stream/cache context may outlive the base constructor context.
        adapter.write(resource, 0, b"R", false, false).unwrap();
        adapter.close(resource).unwrap();
        assert_eq!(
            adapter
                .open(r"\readonly-copy.bin", all())
                .unwrap_err()
                .status,
            Status::AccessDenied
        );
        let read = adapter
            .open(
                r"\readonly-copy.bin",
                OpenRequest {
                    access: Access::READ,
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(adapter.file_info(read).unwrap().attributes & 1, 1);
        let mut data = [0; 20];
        let got = adapter.read(read, 0, &mut data).unwrap();
        assert_eq!(&data[..got], b"copied payload");
        adapter.close(read).unwrap();
        let clear = adapter
            .create_initialized(r"\cancel-readonly.bin", Kind::File, all(), Some(0x21), 0)
            .unwrap();
        adapter
            .set_basic_info(clear, Default::default(), Some(0x20))
            .unwrap();
        adapter.close(clear).unwrap();
        let clear = adapter.open(r"\cancel-readonly.bin", all()).unwrap();
        adapter.close(clear).unwrap();
        let replace = adapter.open(r"\Folder\file.txt", all()).unwrap();
        adapter.overwrite(replace, 0x21, true, 0).unwrap();
        adapter
            .write(replace, 0, b"replacement", false, false)
            .unwrap();
        adapter.close(replace).unwrap();
        assert_eq!(
            adapter.open(r"\Folder\file.txt", all()).unwrap_err().status,
            Status::AccessDenied
        );
        let mut disk = adapter.shutdown().unwrap();
        let fs = HfsPlus::open(&mut disk).unwrap();
        assert_ne!(
            volume::be16(&fs.catalog_record("/readonly-copy.bin").unwrap(), 2) & 1,
            0
        );
        let mut data = Vec::new();
        fs.open_resource_fork_reader(&mut disk, "/readonly-copy.bin")
            .unwrap()
            .read_to_end(&mut data)
            .unwrap();
        assert_eq!(data, b"Rser resource");
        retain(&disk, &format!("readonly-copy-{journaled}.img"));
    }
}

#[test]
fn readonly_final_close_never_acknowledges_failed_publication_or_retries() {
    let mut checkpoints = 0;
    for journaled in [false, true] {
        let base = fixture(journaled, false);
        let prepare = |adapter: &mut Adapter<FaultDisk>| {
            let handle = adapter
                .create_initialized(r"\readonly-copy.bin", Kind::File, all(), Some(0x21), 0)
                .unwrap();
            adapter
                .write(handle, 0, b"complete payload", false, false)
                .unwrap();
            handle
        };
        let disk = fault_disk(&base, None);
        let state = Arc::clone(&disk.0);
        let mut adapter = Adapter::from_device(disk).unwrap();
        let handle = prepare(&mut adapter);
        state.lock().unwrap().calls = 0;
        adapter.close(handle).unwrap();
        let count = state.lock().unwrap().calls;
        assert!(count > 0);
        drop(adapter);
        for failure in 1..=count {
            let disk = fault_disk(&base, None);
            let state = Arc::clone(&disk.0);
            let mut adapter = Adapter::from_device(disk).unwrap();
            let handle = prepare(&mut adapter);
            {
                let mut state = state.lock().unwrap();
                state.calls = 0;
                state.fail = Some(failure);
            }
            assert!(adapter.close(handle).is_err());
            assert!(adapter.failure().is_some());
            let calls = state.lock().unwrap().calls;
            assert_eq!(
                adapter.flush(None).unwrap_err().status,
                Status::FailedVolume
            );
            assert_eq!(
                adapter
                    .open(r"\readonly-copy.bin", all())
                    .unwrap_err()
                    .status,
                Status::FailedVolume
            );
            drop(adapter);
            assert_eq!(state.lock().unwrap().calls, calls);
            checkpoints += 1;
        }
    }
    println!("READONLY_CLOSE_FAULTS: {checkpoints} write/sync checkpoints passed");
}

#[test]
fn preallocation_changes_space_without_exposing_bytes_and_truncates_below_eof() {
    for journaled in [false, true] {
        let mut adapter = Adapter::from_device(fixture(journaled, false)).unwrap();
        let handle = adapter.open(r"\Folder\file.txt", all()).unwrap();
        let before = adapter.file_info(handle).unwrap();
        let free = adapter.volume_info().unwrap().free_bytes;
        adapter.set_allocation_size(handle, 65536).unwrap();
        let reserved = adapter.file_info(handle).unwrap();
        assert_eq!(reserved.size, 8);
        assert_eq!(reserved.allocation_size, 65536);
        assert_eq!(read(&mut adapter, handle), b"original");
        assert_eq!(
            adapter.volume_info().unwrap().free_bytes,
            // The first Windows mutation also allocates the formatter's eight
            // 4 KiB attribute-tree nodes for the persistent generation marker.
            free - 65536 + before.allocation_size - 32768
        );
        adapter.close(handle).unwrap();
        let mut adapter = Adapter::from_device(adapter.shutdown().unwrap()).unwrap();
        let handle = adapter.open(r"\Folder\file.txt", all()).unwrap();
        assert_eq!(adapter.file_info(handle).unwrap().allocation_size, 65536);
        adapter.write(handle, 16000, b"end", false, false).unwrap();
        let data = read(&mut adapter, handle);
        assert_eq!(&data[..8], b"original");
        assert!(data[8..16000].iter().all(|b| *b == 0));
        assert_eq!(&data[16000..], b"end");
        adapter.set_allocation_size(handle, 4096).unwrap();
        assert_eq!(adapter.file_info(handle).unwrap().size, 4096);
        assert_eq!(adapter.file_info(handle).unwrap().allocation_size, 4096);
        adapter.overwrite(handle, 2, true, 8192).unwrap();
        assert_eq!(adapter.file_info(handle).unwrap().size, 0);
        assert_eq!(adapter.file_info(handle).unwrap().allocation_size, 8192);
        adapter.set_size(handle, 8192).unwrap();
        assert!(read(&mut adapter, handle).iter().all(|b| *b == 0));
        assert_eq!(adapter.file_info(handle).unwrap().attributes, 0x22);
        adapter.overwrite(handle, 0x20, false, 0).unwrap();
        assert_eq!(adapter.file_info(handle).unwrap().attributes, 0x22);
        adapter.close(handle).unwrap();
        retain(
            &adapter.shutdown().unwrap(),
            &format!("windows-allocation-{journaled}.img"),
        );
    }
}

#[test]
fn full_volume_refusals_preserve_payload_and_leave_metadata_and_shrink_usable() {
    for journaled in [false, true] {
        let mut adapter = Adapter::from_device(fixture(journaled, false)).unwrap();
        let file = adapter.open(r"\Folder\file.txt", all()).unwrap();
        let filler = adapter.create(r"\Folder\Fill", Kind::File, all()).unwrap();
        let free = adapter.volume_info().unwrap().free_bytes;
        adapter.set_allocation_size(filler, free).unwrap();
        assert_eq!(adapter.volume_info().unwrap().free_bytes, 0);
        let before = adapter.file_info(file).unwrap();
        assert_eq!(
            adapter
                .write(file, 0, b"X", false, false)
                .unwrap_err()
                .status,
            Status::DiskFull
        );
        assert_eq!(
            adapter
                .write(file, 16384, b"X", false, false)
                .unwrap_err()
                .status,
            Status::DiskFull
        );
        assert_eq!(
            adapter.set_size(file, 16384).unwrap_err().status,
            Status::DiskFull
        );
        assert_eq!(
            adapter.set_size(file, u64::MAX).unwrap_err().status,
            Status::DiskFull
        );
        assert_eq!(
            adapter
                .write(file, u64::MAX, b"X", false, false)
                .unwrap_err()
                .status,
            Status::InvalidParameter
        );
        assert_eq!(adapter.file_info(file).unwrap().size, before.size);
        assert_eq!(read(&mut adapter, file), b"original");
        assert!(adapter.failure().is_none());
        adapter
            .set_basic_info(file, Default::default(), Some(2))
            .unwrap();
        adapter.set_allocation_size(filler, free - 4096).unwrap();
        adapter.write(file, 0, b"X", false, false).unwrap();
        assert_eq!(read(&mut adapter, file), b"Xriginal");
        assert_eq!(adapter.volume_info().unwrap().free_bytes, 4096);
        adapter.close(file).unwrap();
        adapter.close(filler).unwrap();
        retain(
            &adapter.shutdown().unwrap(),
            &format!("windows-full-{journaled}.img"),
        );
    }
}

#[test]
fn one_free_block_allows_one_block_edit_but_refuses_cross_block_growth() {
    for journaled in [false, true] {
        let mut adapter = Adapter::from_device(fixture(journaled, false)).unwrap();
        let file = adapter.open(r"\Folder\file.txt", all()).unwrap();
        let filler = adapter.create(r"\Folder\Fill", Kind::File, all()).unwrap();
        let free = adapter.volume_info().unwrap().free_bytes;
        adapter.set_allocation_size(filler, free - 4096).unwrap();
        // Bytes 4095..4097 require one new block and one committed replacement.
        assert_eq!(
            adapter
                .write(file, 4095, b"AB", false, false)
                .unwrap_err()
                .status,
            Status::DiskFull
        );
        assert_eq!(read(&mut adapter, file), b"original");
        assert!(adapter.failure().is_none());
        adapter.write(file, 0, b"Z", false, false).unwrap();
        assert_eq!(read(&mut adapter, file), b"Zriginal");
        assert_eq!(adapter.volume_info().unwrap().free_bytes, 4096);
        adapter.close(file).unwrap();
        adapter.close(filler).unwrap();
        retain(
            &adapter.shutdown().unwrap(),
            &format!("windows-near-full-{journaled}.img"),
        );
    }
}

#[test]
fn invalid_metadata_and_allocation_are_refused_without_poisoning_or_partial_changes() {
    let mut adapter = Adapter::from_device(fixture(true, false)).unwrap();
    let handle = adapter.open(r"\Folder\file.txt", all()).unwrap();
    let before = adapter.file_info(handle).unwrap();
    let free = adapter.volume_info().unwrap().free_bytes;
    assert_eq!(
        adapter
            .set_allocation_size(handle, 4097)
            .unwrap_err()
            .status,
        Status::InvalidParameter
    );
    assert_eq!(
        adapter
            .set_allocation_size(handle, 32 * 1024 * 1024)
            .unwrap_err()
            .status,
        Status::DiskFull
    );
    assert_eq!(
        adapter
            .overwrite(handle, 0x800, true, 0)
            .unwrap_err()
            .status,
        Status::Unsupported
    );
    assert_eq!(
        adapter
            .create_initialized(r"\bad", Kind::File, all(), Some(0x800), 0)
            .unwrap_err()
            .status,
        Status::Unsupported
    );
    assert!(adapter.path_info(r"\bad").is_err());
    assert!(
        adapter
            .set_basic_info(
                handle,
                BasicTimes {
                    creation: Some(u64::MAX),
                    ..Default::default()
                },
                Some(2)
            )
            .is_err()
    );
    assert_eq!(
        adapter.file_info(handle).unwrap().attributes,
        before.attributes
    );
    assert_eq!(
        adapter.file_info(handle).unwrap().creation_time,
        before.creation_time
    );
    assert_eq!(adapter.volume_info().unwrap().free_bytes, free);
    assert_eq!(read(&mut adapter, handle), b"original");
    assert!(adapter.failure().is_none());
    adapter.close(handle).unwrap();
}

#[test]
fn rename_replacement_keeps_source_identity_and_refuses_live_or_locked_targets() {
    for journaled in [false, true] {
        let mut adapter = Adapter::from_device(fixture(journaled, false)).unwrap();
        let source = adapter.open(r"\Folder\file.txt", all()).unwrap();
        let original = adapter.file_info(source).unwrap();
        let folder = adapter.open(r"\Folder", Default::default()).unwrap();
        let alias = adapter
            .read_directory(folder)
            .unwrap()
            .into_iter()
            .find(|e| e.aliased && e.name.ends_with(".txt"))
            .unwrap()
            .name;
        let destination = format!(r"\Folder\{alias}");
        let target = adapter.open(&destination, all()).unwrap();
        let target_id = adapter.file_info(target).unwrap().cnid;
        assert_eq!(
            adapter
                .rename_with_replace(source, &destination, true)
                .unwrap_err()
                .status,
            Status::SharingViolation
        );
        adapter
            .set_basic_info(target, Default::default(), Some(0x21))
            .unwrap();
        adapter.close(target).unwrap();
        assert_eq!(
            adapter
                .rename_with_replace(source, &destination, true)
                .unwrap_err()
                .status,
            Status::AccessDenied
        );
        let target = adapter
            .open(
                &destination,
                OpenRequest {
                    access: Access {
                        metadata: true,
                        ..Access::READ
                    },
                    ..Default::default()
                },
            )
            .unwrap();
        adapter
            .set_basic_info(target, Default::default(), Some(0x20))
            .unwrap();
        adapter.close(target).unwrap();
        assert_eq!(
            adapter.rename(source, &destination).unwrap_err().status,
            Status::Collision
        );
        adapter
            .rename_with_replace(source, &destination, true)
            .unwrap();
        assert_eq!(adapter.file_info(source).unwrap().cnid, original.cnid);
        assert_eq!(read(&mut adapter, source), b"original");
        assert!(adapter.path_info(r"\Folder\file.txt").is_err());
        adapter.close(source).unwrap();
        adapter.close(folder).unwrap();
        let mut disk = adapter.shutdown().unwrap();
        let fs = engine::open_checked(&mut disk).unwrap();
        let body = fs.catalog_record("/Folder/CON.txt").unwrap();
        assert_eq!(volume::be32(&body, 8), original.cnid);
        assert_eq!(volume::be32(&body, 32), original.mac_uid);
        assert!(fs.catalog_record_cnid(target_id).is_err());
        retain(&disk, &format!("windows-replace-{journaled}.img"));
    }
}

#[test]
fn access_and_sharing_are_checked_in_both_directions() {
    let mut adapter = Adapter::from_device(fixture(true, false)).unwrap();
    let read_only = adapter
        .open(
            r"\Folder\file.txt",
            OpenRequest {
                share: Share {
                    write: false,
                    ..Share::ALL
                },
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(
        adapter.open(r"\Folder\file.txt", all()).unwrap_err().status,
        Status::SharingViolation
    );
    assert_eq!(
        adapter
            .write(read_only, 0, b"no", false, false)
            .unwrap_err()
            .status,
        Status::AccessDenied
    );
    assert_eq!(
        adapter.set_size(read_only, 0).unwrap_err().status,
        Status::AccessDenied
    );
    assert_eq!(
        adapter
            .rename(read_only, r"\renamed.txt")
            .unwrap_err()
            .status,
        Status::AccessDenied
    );
    adapter.close(read_only).unwrap();
    let writer = adapter.open(r"\Folder\file.txt", all()).unwrap();
    assert_eq!(
        adapter
            .open(
                r"\Folder\file.txt",
                OpenRequest {
                    share: Share {
                        write: false,
                        ..Share::ALL
                    },
                    ..Default::default()
                }
            )
            .unwrap_err()
            .status,
        Status::SharingViolation
    );
    assert_eq!(
        adapter
            .open(
                r"\Folder\file.txt",
                OpenRequest {
                    share: Share {
                        delete: false,
                        ..Share::ALL
                    },
                    ..Default::default()
                },
            )
            .unwrap_err()
            .status,
        Status::SharingViolation
    );
    adapter.close(writer).unwrap();
    let blocked = adapter
        .open(
            r"\Folder\file.txt",
            OpenRequest {
                share: Share {
                    delete: false,
                    ..Share::ALL
                },
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(
        adapter.open(r"\Folder\file.txt", all()).unwrap_err().status,
        Status::SharingViolation
    );
    adapter.cleanup(blocked, false).unwrap();
    let writer = adapter
        .open(
            r"\Folder\file.txt",
            OpenRequest {
                share: Share {
                    delete: false,
                    ..Share::ALL
                },
                ..all()
            },
        )
        .unwrap();
    adapter.rename(writer, r"\moved.txt").unwrap();
    assert_eq!(read(&mut adapter, blocked), b"original");
    assert_eq!(
        adapter.flush_for_shutdown().unwrap_err().status,
        Status::Busy
    );
    adapter.close(blocked).unwrap();
    adapter.close(writer).unwrap();
    assert!(adapter.failure().is_none());
    adapter.shutdown().unwrap();
}

#[test]
fn append_constrained_writes_sparse_growth_and_resize() {
    for journaled in [false, true] {
        let mut adapter = Adapter::from_device(fixture(journaled, false)).unwrap();
        let file = adapter.open(r"\Folder\file.txt", all()).unwrap();
        assert_eq!(adapter.write(file, 5, b"ABCDE", false, true).unwrap(), 3);
        assert_eq!(read(&mut adapter, file), b"origiABC");
        assert_eq!(adapter.write(file, u64::MAX, b"X", true, true).unwrap(), 0);
        assert_eq!(adapter.write(file, u64::MAX, b"X", true, false).unwrap(), 1);
        assert_eq!(
            adapter
                .write(file, u64::MAX, b"bad", false, false)
                .unwrap_err()
                .status,
            Status::InvalidParameter
        );
        assert!(adapter.failure().is_none());
        adapter.write(file, 8193, b"tail", false, false).unwrap();
        let bytes = read(&mut adapter, file);
        assert_eq!(&bytes[..9], b"origiABCX");
        assert!(bytes[9..8193].iter().all(|b| *b == 0));
        assert_eq!(&bytes[8193..], b"tail");
        adapter.set_size(file, 3).unwrap();
        adapter.set_size(file, 8197).unwrap();
        let bytes = read(&mut adapter, file);
        assert_eq!(&bytes[..3], b"ori");
        assert!(bytes[3..].iter().all(|b| *b == 0));
        assert_eq!(adapter.read(file, 9000, &mut [0; 5]).unwrap(), 0);
        adapter.close(file).unwrap();
        let append = adapter
            .open(
                r"\Folder\file.txt",
                OpenRequest {
                    access: Access {
                        append: true,
                        ..Access::default()
                    },
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(
            adapter
                .write(append, 0, b"no", false, false)
                .unwrap_err()
                .status,
            Status::AccessDenied
        );
        adapter.write(append, 0, b"OK", true, false).unwrap();
        adapter.close(append).unwrap();
        let disk = adapter.shutdown().unwrap();
        retain(
            &disk,
            &format!(
                "windows-editing-{}.img",
                if journaled { "journaled" } else { "plain" }
            ),
        );
    }
}

#[test]
fn delete_eligibility_cleanup_and_final_close_preserve_live_data() {
    for journaled in [false, true] {
        let mut adapter = Adapter::from_device(fixture(journaled, false)).unwrap();
        let file = adapter.open(r"\Folder\file.txt", all()).unwrap();
        let second = adapter
            .open(r"\Folder\file.txt", Default::default())
            .unwrap();
        let directory = adapter.open(r"\Folder", all()).unwrap();
        adapter.can_delete(file).unwrap();
        assert_eq!(read(&mut adapter, file), b"original");
        assert_eq!(
            adapter.can_delete(directory).unwrap_err().status,
            Status::DirectoryNotEmpty
        );
        adapter.cleanup(file, true).unwrap();
        assert_eq!(
            adapter.open(r"\Folder\file.txt", all()).unwrap_err().status,
            Status::DeletePending
        );
        assert_eq!(
            adapter
                .create(r"\Folder\file.txt", Kind::File, all())
                .unwrap_err()
                .status,
            Status::DeletePending
        );
        assert!(
            !adapter
                .read_directory(directory)
                .unwrap()
                .iter()
                .any(|e| e.name == "file.txt")
        );
        assert_eq!(read(&mut adapter, second), b"original");
        adapter.write(file, 0, b"after", false, false).unwrap();
        adapter.close(file).unwrap();
        assert_eq!(read(&mut adapter, second), b"afternal");
        adapter.cleanup(second, false).unwrap();
        adapter.close(second).unwrap();
        assert_eq!(
            adapter.open(r"\Folder\file.txt", all()).unwrap_err().status,
            Status::NotFound
        );
        adapter.close(directory).unwrap();
        let empty = adapter.create(r"\Empty", Kind::Directory, all()).unwrap();
        adapter.cleanup(empty, true).unwrap();
        assert_eq!(
            adapter
                .create(r"\Empty\child", Kind::File, all())
                .unwrap_err()
                .status,
            Status::DeletePending
        );
        adapter.close(empty).unwrap();
        assert_eq!(
            adapter.file_info(empty).unwrap_err().status,
            Status::InvalidHandle
        );
        let disk = adapter.shutdown().unwrap();
        retain(
            &disk,
            &format!(
                "windows-delete-{}.img",
                if journaled { "journaled" } else { "plain" }
            ),
        );
    }
}

#[test]
fn nested_aliases_hfsx_collisions_and_reserved_names() {
    let mut disk = fixture(true, true);
    let mut fs = HfsPlus::open(&mut disk).unwrap();
    fs.create_dir(&mut disk, "/CON", 0o755, 0, 0, 0).unwrap();
    fs.rename(&mut disk, "/Folder", "/CON/Folder").unwrap();
    fs.flush(&mut disk).unwrap();
    let mut adapter = Adapter::from_device(disk).unwrap();
    let root = adapter.open(r"\", Default::default()).unwrap();
    let con = adapter
        .read_directory(root)
        .unwrap()
        .into_iter()
        .find(|e| e.aliased)
        .unwrap();
    let directory_path = format!("\\{}\\Folder", con.name);
    let dir = adapter.open(&directory_path, all()).unwrap();
    let listing = adapter.read_directory(dir).unwrap();
    assert_eq!(listing.iter().filter(|e| e.aliased).count(), 4);
    assert_eq!(
        adapter
            .open(&format!("{directory_path}\\case.txt"), all())
            .unwrap_err()
            .status,
        Status::NotFound
    );
    for entry in &listing {
        let single = adapter.directory_entry(dir, &entry.name).unwrap();
        assert_eq!(single.name, entry.name);
        assert_eq!(single.aliased, entry.aliased);
        assert_eq!(single.info.cnid, entry.info.cnid);
        assert_eq!(single.info.size, entry.info.size);
        let file = adapter
            .open(&format!("{directory_path}\\{}", entry.name), all())
            .unwrap();
        assert_eq!(adapter.file_info(file).unwrap().cnid, entry.info.cnid);
        assert!(!read(&mut adapter, file).is_empty());
        adapter.close(file).unwrap();
    }
    let case = listing
        .iter()
        .find(|e| e.aliased && e.name.ends_with(".txt"))
        .unwrap();
    let file = adapter
        .open(&format!("{directory_path}\\{}", case.name), all())
        .unwrap();
    adapter
        .rename(file, &format!("{directory_path}\\ordinary.txt"))
        .unwrap();
    assert_eq!(
        adapter.directory_entry(dir, &case.name).unwrap_err().status,
        Status::NotFound
    );
    assert_eq!(
        adapter.directory_entry(dir, "ORDINARY.TXT").unwrap().name,
        "ordinary.txt"
    );
    assert_eq!(
        adapter
            .open(&format!("{directory_path}\\{}", case.name), all())
            .unwrap_err()
            .status,
        Status::NotFound
    );
    adapter.close(file).unwrap();
    for name in ["CON", "..", "ends.", "~HFS-00000099", "a/b"] {
        assert_eq!(
            adapter
                .create(&format!("{directory_path}\\{name}"), Kind::File, all())
                .unwrap_err()
                .status,
            Status::InvalidName
        );
    }
    assert_eq!(
        adapter
            .create(&format!("{directory_path}\\foo:stream"), Kind::File, all())
            .unwrap_err()
            .status,
        Status::NotFound
    );
    let first = adapter
        .create(&format!("{directory_path}\\café.txt"), Kind::File, all())
        .unwrap();
    adapter.close(first).unwrap();
    assert_eq!(
        adapter
            .create(
                &format!("{directory_path}\\cafe\u{301}.txt"),
                Kind::File,
                all()
            )
            .unwrap_err()
            .status,
        Status::Collision
    );
    adapter.close(dir).unwrap();
    adapter.close(root).unwrap();
    let disk = adapter.shutdown().unwrap();
    retain(&disk, "windows-aliases-hfsx.img");
}

#[test]
fn independent_timestamps_and_invalid_ranges_preserve_mac_metadata() {
    assert_eq!(hfs_to_filetime(2_082_844_800), 116_444_736_000_000_000);
    assert_eq!(
        filetime_to_hfs(116_444_736_000_000_000).unwrap(),
        2_082_844_800
    );
    assert!(filetime_to_hfs(1).is_err());
    assert!(filetime_to_hfs(hfs_to_filetime(u32::MAX) + 10_000_000).is_err());
    let mut disk = fixture(true, false);
    let fs = HfsPlus::open(&mut disk).unwrap();
    let before = fs.catalog_record("/Folder/file.txt").unwrap();
    let mut adapter = Adapter::from_device(disk).unwrap();
    let file = adapter.open(r"\Folder\file.txt", all()).unwrap();
    let initial = adapter.file_info(file).unwrap();
    assert_eq!(
        adapter
            .set_basic_times(
                file,
                BasicTimes {
                    creation: Some(hfs_to_filetime(3_000_000_001)),
                    access: Some(u64::MAX),
                    ..Default::default()
                }
            )
            .unwrap_err()
            .status,
        Status::InvalidParameter
    );
    assert_eq!(
        adapter.file_info(file).unwrap().creation_time,
        initial.creation_time
    );
    let native = [3_000_000_001, 3_000_000_002, 3_000_000_003, 3_000_000_004];
    adapter
        .set_basic_times(
            file,
            BasicTimes {
                creation: Some(hfs_to_filetime(native[0])),
                access: Some(hfs_to_filetime(native[1])),
                write: Some(hfs_to_filetime(native[2])),
                change: Some(hfs_to_filetime(native[3])),
            },
        )
        .unwrap();
    adapter.flush(Some(file)).unwrap();
    adapter.close(file).unwrap();
    let mut disk = adapter.shutdown().unwrap();
    let fs = HfsPlus::open(&mut disk).unwrap();
    let after = fs.catalog_record("/Folder/file.txt").unwrap();
    for (offset, expected) in [12, 24, 16, 20].into_iter().zip(native) {
        assert_eq!(volume::be32(&after, offset), expected);
    }
    let mut before_identity = before[..12].to_vec();
    before_identity[3] |= 4; // A precision attribute now exists on this file.
    assert_eq!(&before_identity, &after[..12]);
    assert_eq!(&before[28..], &after[28..]);
    retain(&disk, "windows-timestamps.img");
}

#[test]
fn serialized_concurrent_appends_keep_all_records() {
    let mut adapter = Adapter::from_device(fixture(true, false)).unwrap();
    let file = adapter.create(r"\append.bin", Kind::File, all()).unwrap();
    let adapter = Arc::new(Mutex::new(adapter));
    let workers: Vec<_> = (0..4u8)
        .map(|worker| {
            let adapter = Arc::clone(&adapter);
            std::thread::spawn(move || {
                for i in 0..8 {
                    adapter
                        .lock()
                        .unwrap()
                        .write(file, 0, &[worker, i], true, false)
                        .unwrap();
                }
            })
        })
        .collect();
    for worker in workers {
        worker.join().unwrap();
    }
    let mut adapter = Arc::try_unwrap(adapter).ok().unwrap().into_inner().unwrap();
    let bytes = read(&mut adapter, file);
    assert_eq!(bytes.len(), 64);
    let mut records: Vec<_> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|b| (b[0], b[1]))
        .collect();
    records.sort_unstable();
    assert_eq!(
        records,
        (0..4)
            .flat_map(|w| (0..8).map(move |i| (w, i)))
            .collect::<Vec<_>>()
    );
    adapter.close(file).unwrap();
    let disk = adapter.shutdown().unwrap();
    retain(&disk, "windows-concurrent.img");
}

struct OwnedImageTestDirectory {
    path: PathBuf,
    root: PathBuf,
}
impl OwnedImageTestDirectory {
    fn new() -> Self {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join(".cache/tests");
        std::fs::create_dir_all(&root).unwrap();
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = root.join(format!("windows-copy-{}-{unique}", std::process::id()));
        std::fs::create_dir(&path).unwrap();
        // Keep ordinary absolute paths for the image harness, which deliberately
        // rejects Windows device paths (including canonicalize's \\?\ prefix).
        let root = std::fs::canonicalize(root).unwrap();
        Self { path, root }
    }
}
impl Drop for OwnedImageTestDirectory {
    fn drop(&mut self) {
        // Retained acceptance images are copied elsewhere before this guard drops.
        // Do not follow a replacement link outside the exact owned child path.
        if let Ok(resolved) = std::fs::canonicalize(&self.path)
            && resolved == self.root.join(self.path.file_name().unwrap())
            && resolved.parent() == Some(self.root.as_path())
            && let Err(error) = std::fs::remove_dir_all(&resolved)
        {
            eprintln!("Could not remove owned test directory {resolved:?}: {error}");
        }
    }
}

#[test]
fn image_factory_keeps_source_read_only_across_multiple_operations() {
    let directory = OwnedImageTestDirectory::new();
    let source = directory.path.join("source.img");
    let output = directory.path.join("session.img");
    engine::fixture(&source, true).unwrap();
    let hash = engine::sha256(&mut std::fs::File::open(&source).unwrap()).unwrap();
    let mut adapter = Adapter::<Image>::copy_image(&source, &output, 0, None).unwrap();
    let file = adapter.create(r"\live.txt", Kind::File, all()).unwrap();
    adapter
        .write(file, 0, b"one owned image", false, false)
        .unwrap();
    adapter.rename(file, r"\Transfer\renamed.txt").unwrap();
    adapter.close(file).unwrap();
    drop(adapter.shutdown().unwrap());
    assert_eq!(
        engine::sha256(&mut std::fs::File::open(&source).unwrap()).unwrap(),
        hash
    );
    assert!(Adapter::<Image>::copy_image(&source, &output, 0, None).is_err());
    let mut disk = Image::read_only(&output, 0, None).unwrap();
    let fs = engine::open_checked(&mut disk).unwrap();
    let mut data = Vec::new();
    fs.open_file_reader(&mut disk, "/Transfer/renamed.txt")
        .unwrap()
        .read_to_end(&mut data)
        .unwrap();
    assert_eq!(data, b"one owned image");
    if let Some(target) = std::env::var_os("HFS_CRASH_ARTIFACT_DIR") {
        std::fs::copy(
            &output,
            Path::new(&target).join("windows-image-session.img"),
        )
        .unwrap();
    }
    drop(fs);
    drop(disk);
    let scratch_path = directory.path.clone();
    drop(directory);
    assert!(
        !scratch_path.exists(),
        "owned scratch images were not removed"
    );
}

struct FaultState {
    visible: MemoryBackend,
    durable: Vec<u8>,
    calls: usize,
    fail: Option<usize>,
}
#[derive(Clone)]
struct FaultDisk(Arc<Mutex<FaultState>>);
impl Read for FaultDisk {
    fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
        self.0.lock().unwrap().visible.read(b)
    }
}
impl Seek for FaultDisk {
    fn seek(&mut self, p: SeekFrom) -> io::Result<u64> {
        self.0.lock().unwrap().visible.seek(p)
    }
}
impl Write for FaultDisk {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        let mut s = self.0.lock().unwrap();
        s.calls += 1;
        if s.fail == Some(s.calls) {
            return Err(io::Error::other("injected write failure"));
        }
        s.visible.write(b)
    }
    fn flush(&mut self) -> io::Result<()> {
        let mut s = self.0.lock().unwrap();
        s.calls += 1;
        if s.fail == Some(s.calls) {
            return Err(io::Error::other("injected sync failure"));
        }
        s.durable = s.visible.as_slice().to_vec();
        Ok(())
    }
}
impl BlockDevice for FaultDisk {
    fn block_size(&self) -> u32 {
        512
    }
    fn total_size(&self) -> u64 {
        self.0.lock().unwrap().visible.total_size()
    }
    fn sync(&mut self) -> fstool::Result<()> {
        Ok(self.flush()?)
    }
}
fn fault_disk(base: &MemoryBackend, fail: Option<usize>) -> FaultDisk {
    FaultDisk(Arc::new(Mutex::new(FaultState {
        visible: base.clone(),
        durable: base.as_slice().to_vec(),
        calls: 0,
        fail,
    })))
}

#[test]
fn resource_streams_preserve_data_follow_parent_lifetime_and_reopen() {
    for (journaled, sensitive) in [(false, false), (true, false), (true, true)] {
        let mut adapter = Adapter::from_device(fixture(journaled, sensitive)).unwrap();
        let data = adapter.open(r"\Folder\file.txt::$DATA", all()).unwrap();
        let before = adapter.file_info(data).unwrap();
        assert_eq!(adapter.streams(data).unwrap().len(), 1);
        assert_eq!(
            adapter
                .open(r"\Folder\file.txt:AFP_Resource", all())
                .unwrap_err()
                .status,
            Status::NotFound
        );
        let resource = adapter
            .create_initialized(
                r"\Folder\file.txt:AFP_Resource:$DATA",
                Kind::File,
                all(),
                None,
                16384,
            )
            .unwrap();
        assert_eq!(adapter.file_info(resource).unwrap().size, 0);
        assert_eq!(adapter.file_info(resource).unwrap().allocation_size, 16384);
        assert_eq!(adapter.streams(resource).unwrap().len(), 2);
        let mut expected = vec![0; 4094];
        expected.extend_from_slice(b"resource\0\xff");
        adapter
            .write(resource, 4094, b"resource\0\xff", false, false)
            .unwrap();
        adapter.set_size(resource, 8193).unwrap();
        expected.resize(8193, 0);
        assert_eq!(read(&mut adapter, resource), expected);
        adapter.set_allocation_size(resource, 12288).unwrap();
        assert_eq!(read(&mut adapter, data), b"original");
        assert_eq!(adapter.file_info(data).unwrap().cnid, before.cnid);
        assert_eq!(
            adapter.rename(resource, r"\renamed").unwrap_err().status,
            Status::Unsupported
        );
        adapter.can_delete(resource).unwrap();
        assert!(adapter.failure().is_none());
        adapter.rename(data, r"\Folder\moved.txt").unwrap();
        let second = adapter
            .open(r"\Folder\moved.txt:afp_resource:$data", all())
            .unwrap();
        assert_eq!(read(&mut adapter, second), expected);
        adapter.overwrite(resource, 0x20, false, 4096).unwrap();
        adapter
            .write(second, 0, b"replacement", false, false)
            .unwrap();
        assert_eq!(read(&mut adapter, resource), b"replacement");
        adapter.close(second).unwrap();
        adapter.close(resource).unwrap();
        adapter.close(data).unwrap();
        let mut disk = adapter.shutdown().unwrap();
        let fs = engine::open_checked(&mut disk).unwrap();
        assert_eq!(fs.file_size(&mut disk, "/Folder/moved.txt").unwrap(), 8);
        let snapshot = engine::snapshot_device(&mut disk, "/Folder/moved.txt", &[]).unwrap();
        assert_eq!(
            snapshot.resource_sha256,
            Some(engine::sha256(&mut &b"replacement"[..]).unwrap())
        );
        retain(
            &disk,
            &format!("windows-resource-stream-{journaled}-{sensitive}.img"),
        );
        let mut adapter = Adapter::from_device(disk).unwrap();
        let data = adapter.open(r"\Folder\moved.txt", all()).unwrap();
        let resource = adapter
            .open(r"\Folder\moved.txt:AFP_Resource", all())
            .unwrap();
        adapter.cleanup(data, true).unwrap();
        assert_eq!(read(&mut adapter, resource), b"replacement");
        adapter.write(resource, 0, b"live", false, false).unwrap();
        adapter.close(data).unwrap();
        assert_eq!(read(&mut adapter, resource), b"liveacement");
        adapter.close(resource).unwrap();
        let mut disk = adapter.shutdown().unwrap();
        let fs = engine::open_checked(&mut disk).unwrap();
        assert!(fs.catalog_record("/Folder/moved.txt").is_err());
    }
}

#[test]
fn resource_callbacks_never_acknowledge_write_or_sync_failures_or_retry() {
    let mut checkpoints = 0;
    for journaled in [false, true] {
        for operation in 0..6 {
            let mut base = fixture(journaled, false);
            if operation != 0 {
                let mut fs = HfsPlus::open(&mut base).unwrap();
                let mut resource = fs
                    .open_resource_fork_rw(&mut base, Path::new("/Folder/file.txt"))
                    .unwrap();
                resource.write_all(&vec![0x57; 4099]).unwrap();
                resource.sync().unwrap();
            }
            let run = |adapter: &mut Adapter<FaultDisk>| -> hfs_bridge::windows::Result<()> {
                if operation == 0 {
                    return adapter
                        .create_initialized(
                            r"\Folder\file.txt:AFP_Resource",
                            Kind::File,
                            all(),
                            None,
                            8192,
                        )
                        .map(|_| ());
                }
                let resource = adapter.open(r"\Folder\file.txt:AFP_Resource", all())?;
                match operation {
                    1 => adapter
                        .write(resource, 4094, b"new content", false, false)
                        .map(|_| ()),
                    2 => adapter.set_size(resource, 12291),
                    3 => adapter.set_allocation_size(resource, 4096),
                    4 => adapter.overwrite(resource, 2, true, 8192),
                    5 => adapter.cleanup(resource, true),
                    _ => unreachable!(),
                }
            };
            let disk = fault_disk(&base, None);
            let state = Arc::clone(&disk.0);
            let mut adapter = Adapter::from_device(disk).unwrap();
            run(&mut adapter).unwrap();
            let count = state.lock().unwrap().calls;
            let mut disk = MemoryBackend::from_bytes(state.lock().unwrap().durable.clone());
            let snapshot = engine::snapshot_device(&mut disk, "/Folder/file.txt", &[]).unwrap();
            assert_eq!(
                snapshot.data_sha256,
                engine::sha256(&mut &b"original"[..]).unwrap()
            );
            let fs = engine::open_checked(&mut disk).unwrap();
            let body = fs.catalog_record("/Folder/file.txt").unwrap();
            assert_eq!(
                volume::be64(&body, 168),
                [0, 4105, 12291, 4096, 0, 0][operation]
            );
            assert_eq!(volume::be32(&body, 180), [2, 2, 4, 1, 2, 0][operation]);
            retain(
                &disk,
                &format!("windows-resource-durable-{operation}-{journaled}.img"),
            );
            for fail in 1..=count {
                let disk = fault_disk(&base, Some(fail));
                let state = Arc::clone(&disk.0);
                let mut adapter = Adapter::from_device(disk).unwrap();
                assert!(
                    run(&mut adapter).is_err(),
                    "resource operation {operation}, fault {fail}/{count}"
                );
                assert!(adapter.failure().is_some());
                let calls = state.lock().unwrap().calls;
                assert_eq!(
                    adapter.flush(None).unwrap_err().status,
                    Status::FailedVolume
                );
                drop(adapter);
                assert_eq!(state.lock().unwrap().calls, calls);
                checkpoints += 1;
            }
        }
    }
    println!("Resource adapter: {checkpoints} write/sync failure checkpoints passed");
}

#[test]
fn resource_unlink_retains_old_handles_allows_recreation_and_recovers_after_restart() {
    for (journaled, sensitive) in [(false, false), (true, false), (true, true)] {
        let mut adapter = Adapter::from_device(fixture(journaled, sensitive)).unwrap();
        let base = adapter.open(r"\Folder\file.txt", all()).unwrap();
        let resource = adapter
            .create(r"\Folder\file.txt:AFP_Resource", Kind::File, all())
            .unwrap();
        let id = adapter.file_info(resource).unwrap().cnid;
        adapter
            .write(resource, 0, b"old resource", false, false)
            .unwrap();
        let other = adapter
            .open(r"\Folder\file.txt:AFP_Resource", all())
            .unwrap();
        adapter.cleanup(resource, true).unwrap();
        assert_eq!(adapter.file_info(resource).unwrap().cnid, id);
        assert_eq!(read(&mut adapter, base), b"original");
        assert_eq!(
            adapter
                .open(r"\Folder\file.txt:AFP_Resource", all())
                .unwrap_err()
                .status,
            Status::NotFound
        );
        assert_eq!(read(&mut adapter, other), b"old resource");
        let new = adapter
            .create(r"\Folder\file.txt:AFP_Resource", Kind::File, all())
            .unwrap();
        adapter
            .write(new, 0, b"new resource", false, false)
            .unwrap();
        adapter.write(other, 0, b"OLD", false, false).unwrap();
        assert_eq!(read(&mut adapter, resource), b"OLD resource");
        assert_eq!(read(&mut adapter, new), b"new resource");
        adapter.close(resource).unwrap();
        adapter.close(other).unwrap();
        adapter.close(new).unwrap();
        adapter.close(base).unwrap();
        let disk = adapter.shutdown().unwrap();
        retain(
            &disk,
            &format!("resource-unlink-recreate-{journaled}-{sensitive}.img"),
        );

        let disk = fault_disk(&disk, None);
        let state = Arc::clone(&disk.0);
        let mut adapter = Adapter::from_device(disk).unwrap();
        let resource = adapter
            .open(r"\Folder\file.txt:AFP_Resource", all())
            .unwrap();
        adapter.cleanup(resource, true).unwrap();
        let old_bytes = state.lock().unwrap().durable.clone();
        let before = state.lock().unwrap().calls;
        drop(adapter);
        assert_eq!(state.lock().unwrap().calls, before);
        let adapter = Adapter::from_device(MemoryBackend::from_bytes(old_bytes)).unwrap();
        let mut disk = adapter.shutdown().unwrap();
        let fs = engine::open_checked(&mut disk).unwrap();
        assert!(fs.catalog_record("/.hfs-bridge-orphans-v1").is_err());
        assert_eq!(
            fs.resource_fork_size(&mut disk, "/Folder/file.txt")
                .unwrap(),
            None
        );
        let snap = engine::snapshot_device(&mut disk, "/Folder/file.txt", &[]).unwrap();
        assert_eq!(
            snap.data_sha256,
            engine::sha256(&mut &b"original"[..]).unwrap()
        );
        retain(
            &disk,
            &format!("resource-unlink-recovered-{journaled}-{sensitive}.img"),
        );
    }
}

#[test]
fn every_write_and_sync_failure_prevents_success_and_poison_retries() {
    let mut checkpoints = 0;
    for journaled in [false, true] {
        let base = fixture(journaled, false);
        for operation in 0..14 {
            let disk = fault_disk(&base, None);
            let state = Arc::clone(&disk.0);
            let mut adapter = Adapter::from_device(disk).unwrap();
            let file = adapter.open(r"\Folder\file.txt", all()).unwrap();
            if operation == 8 {
                adapter.cleanup(file, true).unwrap();
                state.lock().unwrap().calls = 0;
            }
            fault_operation(&mut adapter, file, operation).unwrap();
            let count = state.lock().unwrap().calls;
            let bytes = state.lock().unwrap().durable.clone();
            let mut durable = MemoryBackend::from_bytes(bytes);
            let fs = engine::open_checked(&mut durable).unwrap();
            let path = if operation == 2 {
                "/Folder/renamed.txt"
            } else {
                "/Folder/file.txt"
            };
            match operation {
                0 => {
                    let mut data = Vec::new();
                    fs.open_file_reader(&mut durable, path)
                        .unwrap()
                        .read_to_end(&mut data)
                        .unwrap();
                    assert_eq!(&data[4095..], b"acknowledged durable bytes");
                }
                1 => assert_eq!(fs.file_size(&mut durable, path).unwrap(), 8193),
                2 => assert!(fs.catalog_record(path).is_ok()),
                3 => assert!(fs.catalog_record("/created.txt").is_ok()),
                4 => assert!(fs.catalog_record("/Created").is_ok()),
                5 => assert_eq!(
                    volume::be32(&fs.catalog_record(path).unwrap(), 24),
                    3_000_000_099
                ),
                6 => assert_eq!(fs.file_size(&mut durable, path).unwrap(), 8),
                7 => {
                    assert!(fs.catalog_record(path).is_err());
                    assert!(fs.catalog_record("/.hfs-bridge-orphans-v1").is_ok());
                }
                8 => {
                    assert!(fs.catalog_record(path).is_err());
                    assert!(fs.catalog_record("/.hfs-bridge-orphans-v1").is_err());
                }
                9 => {
                    let body = fs.catalog_record(path).unwrap();
                    assert_ne!(volume::be16(&body, 56) & 0x4000, 0);
                    assert_eq!(volume::be32(&body, 28), volume::be32(&body, 16));
                }
                10 => {
                    let body = fs.catalog_record(path).unwrap();
                    assert_eq!(volume::be64(&body, 88), 8);
                    assert_eq!(volume::be32(&body, 100), 4);
                }
                11 => {
                    let body = fs.catalog_record(path).unwrap();
                    assert_eq!(volume::be64(&body, 88), 0);
                    assert_eq!(volume::be32(&body, 100), 2);
                }
                12 => {
                    let body = fs.catalog_record("/allocated.txt").unwrap();
                    assert_eq!(volume::be64(&body, 88), 0);
                    assert_eq!(volume::be32(&body, 100), 4);
                    assert_ne!(volume::be16(&body, 56) & 0x4000, 0);
                }
                13 => {
                    assert!(fs.catalog_record(path).is_err());
                    let body = fs.catalog_record("/Folder/CON.txt").unwrap();
                    let original = engine::open_checked(&mut base.clone())
                        .unwrap()
                        .catalog_record(path)
                        .unwrap();
                    assert_eq!(volume::be32(&body, 8), volume::be32(&original, 8));
                }
                _ => unreachable!(),
            }
            retain(
                &durable,
                &format!(
                    "windows-durable-{operation}-{}.img",
                    if journaled { "journaled" } else { "plain" }
                ),
            );
            for failure in 1..=count {
                let disk = fault_disk(&base, (operation != 8).then_some(failure));
                let state = Arc::clone(&disk.0);
                let mut adapter = Adapter::from_device(disk).unwrap();
                let file = adapter.open(r"\Folder\file.txt", all()).unwrap();
                if operation == 8 {
                    adapter.cleanup(file, true).unwrap();
                    let mut state = state.lock().unwrap();
                    state.calls = 0;
                    state.fail = Some(failure);
                }
                assert!(
                    fault_operation(&mut adapter, file, operation).is_err(),
                    "operation {operation}, failure {failure}/{count}"
                );
                assert!(adapter.failure().is_some());
                let failed_calls = state.lock().unwrap().calls;
                assert_eq!(
                    adapter.flush(Some(file)).unwrap_err().status,
                    Status::FailedVolume
                );
                assert_eq!(
                    adapter
                        .write(file, 0, b"retry", false, false)
                        .unwrap_err()
                        .status,
                    Status::FailedVolume
                );
                assert_eq!(
                    adapter.open(r"\Folder\file.txt", all()).unwrap_err().status,
                    Status::FailedVolume
                );
                if operation != 8 {
                    assert_eq!(
                        adapter.close(file).unwrap_err().status,
                        Status::FailedVolume
                    );
                }
                drop(adapter);
                assert_eq!(
                    state.lock().unwrap().calls,
                    failed_calls,
                    "implicit retry after failure"
                );
                checkpoints += 1;
            }
        }
    }
    println!("Windows adapter: {checkpoints} write/sync failure checkpoints passed");
}

fn fault_operation(
    adapter: &mut Adapter<FaultDisk>,
    file: Handle,
    operation: usize,
) -> hfs_bridge::windows::Result<()> {
    match operation {
        0 => adapter
            .write(file, 4095, b"acknowledged durable bytes", false, false)
            .map(|_| ()),
        1 => adapter.set_size(file, 8193),
        2 => adapter.rename(file, r"\Folder\renamed.txt"),
        3 => adapter
            .create(r"\created.txt", Kind::File, all())
            .map(|_| ()),
        4 => adapter
            .create(r"\Created", Kind::Directory, all())
            .map(|_| ()),
        5 => adapter.set_basic_times(
            file,
            BasicTimes {
                access: Some(hfs_to_filetime(3_000_000_099)),
                ..Default::default()
            },
        ),
        6 => adapter.flush(Some(file)),
        7 => adapter.cleanup(file, true),
        8 => adapter.close(file),
        9 => adapter.set_basic_info(file, Default::default(), Some(2)),
        10 => adapter.set_allocation_size(file, 16384),
        11 => adapter.overwrite(file, 2, true, 8192),
        12 => adapter
            .create_initialized(r"\allocated.txt", Kind::File, all(), Some(0x22), 16384)
            .map(|_| ()),
        13 => {
            let folder = adapter.open(r"\Folder", Default::default())?;
            let destination = adapter
                .read_directory(folder)?
                .into_iter()
                .find(|e| e.aliased && e.name.ends_with(".txt"))
                .unwrap()
                .name;
            adapter.close(folder)?;
            adapter.rename_with_replace(file, &format!(r"\Folder\{destination}"), true)
        }
        _ => unreachable!(),
    }
}

#[test]
fn successful_cleanup_survives_restart_and_reclaims_validated_orphans() {
    for (journaled, sensitive) in [(false, false), (true, false), (true, true)] {
        let disk = fault_disk(&fixture(journaled, sensitive), None);
        let state = Arc::clone(&disk.0);
        let mut adapter = Adapter::from_device(disk).unwrap();
        let file = adapter.open(r"\Folder\file.txt", all()).unwrap();
        let cnid = adapter.file_info(file).unwrap().cnid;
        adapter.cleanup(file, true).unwrap();
        adapter
            .write(file, 0, b"live after cleanup", false, false)
            .unwrap();
        assert_eq!(read(&mut adapter, file), b"live after cleanup");
        let root = adapter.open(r"\", Default::default()).unwrap();
        assert!(
            !adapter
                .read_directory(root)
                .unwrap()
                .iter()
                .any(|entry| entry.name.contains("orphans"))
        );
        let orphaned = MemoryBackend::from_bytes(state.lock().unwrap().durable.clone());
        let label = if sensitive {
            "hfsx"
        } else if journaled {
            "journaled"
        } else {
            "plain"
        };
        retain(&orphaned, &format!("windows-orphan-{label}.img"));
        let mut probe = orphaned.clone();
        let fs = engine::open_checked(&mut probe).unwrap();
        assert!(fs.catalog_record("/Folder/file.txt").is_err());
        let orphan_path = format!("/.hfs-bridge-orphans-v1/{cnid:08X}");
        assert_eq!(fs.file_size(&mut probe, &orphan_path).unwrap(), 18);
        drop(adapter); // A process exit does not implicitly close/reclaim.
        let mut reopened = Adapter::from_device(orphaned).unwrap();
        assert_eq!(
            reopened
                .open(r"\Folder\file.txt", all())
                .unwrap_err()
                .status,
            Status::NotFound
        );
        let replacement = reopened
            .create(r"\Folder\file.txt", Kind::File, all())
            .unwrap();
        assert_ne!(reopened.file_info(replacement).unwrap().cnid, cnid);
        reopened.close(replacement).unwrap();
        let mut recovered = reopened.shutdown().unwrap();
        assert!(
            engine::open_checked(&mut recovered)
                .unwrap()
                .catalog_record("/.hfs-bridge-orphans-v1")
                .is_err()
        );
        retain(&recovered, &format!("windows-recovered-{label}.img"));
    }
}

#[test]
fn several_pending_names_follow_parent_renames_and_release_after_close() {
    for journaled in [false, true] {
        let mut adapter = Adapter::from_device(fixture(journaled, false)).unwrap();
        let directory = adapter.open(r"\Folder", all()).unwrap();
        let reserved = adapter
            .read_directory(directory)
            .unwrap()
            .into_iter()
            .find(|entry| entry.aliased && entry.name.ends_with(".txt"))
            .unwrap();
        let first = adapter.open(r"\Folder\file.txt", all()).unwrap();
        let second = adapter
            .open(&format!(r"\Folder\{}", reserved.name), all())
            .unwrap();
        adapter.cleanup(first, true).unwrap();
        adapter.cleanup(second, true).unwrap();
        adapter.rename(directory, r"\Renamed").unwrap();
        assert_eq!(
            adapter
                .open(r"\Renamed\FILE.TXT", all())
                .unwrap_err()
                .status,
            Status::DeletePending
        );
        assert_eq!(
            adapter
                .open(&format!(r"\Renamed\{}", reserved.name), all())
                .unwrap_err()
                .status,
            Status::DeletePending
        );
        assert_eq!(read(&mut adapter, first), b"original");
        assert_eq!(read(&mut adapter, second), b"reserved");
        adapter.close(first).unwrap();
        let replacement = adapter
            .create(r"\Renamed\file.txt", Kind::File, all())
            .unwrap();
        adapter
            .write(replacement, 0, b"replacement", false, false)
            .unwrap();
        adapter.close(replacement).unwrap();
        assert_eq!(read(&mut adapter, second), b"reserved");
        adapter.close(second).unwrap();
        adapter.close(directory).unwrap();
        let disk = adapter.shutdown().unwrap();
        retain(
            &disk,
            &format!(
                "windows-multiple-deletes-{}.img",
                if journaled { "journaled" } else { "plain" }
            ),
        );
    }
}

fn orphan_fixture(journaled: bool) -> MemoryBackend {
    let disk = fault_disk(&fixture(journaled, false), None);
    let state = Arc::clone(&disk.0);
    let mut adapter = Adapter::from_device(disk).unwrap();
    let file = adapter.open(r"\Folder\file.txt", all()).unwrap();
    adapter.cleanup(file, true).unwrap();
    let snapshot = state.lock().unwrap().durable.clone();
    drop(adapter);
    MemoryBackend::from_bytes(snapshot)
}

#[test]
fn malformed_or_conflicting_holding_store_is_refused_before_any_write() {
    for variant in 0..7 {
        let mut base = orphan_fixture(true);
        let mut fs = HfsPlus::open(&mut base).unwrap();
        match variant {
            0 => fs
                .create_file(
                    &mut base,
                    "/.hfs-bridge-orphans-v1/unknown",
                    &mut &b"user data"[..],
                    9,
                    0o644,
                    0,
                    0,
                    0,
                )
                .map(|_| ())
                .unwrap(),
            1 => fs
                .remove(&mut base, "/.hfs-bridge-orphans-v1/owner")
                .unwrap(),
            2 => {
                use fstool::fs::{Filesystem, OpenFlags};
                let mut marker = fs
                    .open_file_rw(
                        &mut base,
                        Path::new("/.hfs-bridge-orphans-v1/owner"),
                        OpenFlags::default(),
                        None,
                    )
                    .unwrap();
                marker.write_all(b"INVALID!").unwrap();
                marker.sync().unwrap();
            }
            3 => {
                let node = fs
                    .list_path(&mut base, "/.hfs-bridge-orphans-v1")
                    .unwrap()
                    .into_iter()
                    .find(|entry| entry.name != "owner")
                    .unwrap();
                fs.rename(
                    &mut base,
                    &format!("/.hfs-bridge-orphans-v1/{}", node.name),
                    "/.hfs-bridge-orphans-v1/00000000",
                )
                .unwrap();
            }
            4 => {
                let dir = fs
                    .create_dir(&mut base, "/.hfs-bridge-orphans-v1/temp", 0o755, 0, 0, 0)
                    .unwrap();
                fs.create_dir(
                    &mut base,
                    "/.hfs-bridge-orphans-v1/temp/user-folder",
                    0o755,
                    0,
                    0,
                    0,
                )
                .unwrap();
                fs.rename(
                    &mut base,
                    "/.hfs-bridge-orphans-v1/temp",
                    &format!("/.hfs-bridge-orphans-v1/{dir:08X}"),
                )
                .unwrap();
            }
            5 => fs
                .rename(
                    &mut base,
                    "/.hfs-bridge-orphans-v1",
                    "/.HFS-BRIDGE-ORPHANS-V1",
                )
                .unwrap(),
            6 => {}
            _ => unreachable!(),
        }
        fs.flush(&mut base).unwrap();
        if variant == 6 {
            // Copying a marker to a different volume cannot authorize recovery.
            let mut bytes = base.into_bytes();
            bytes[1024 + 104] ^= 0x5a;
            let header = bytes[1024..1536].to_vec();
            let alternate = bytes.len() - 1024;
            bytes[alternate..alternate + 512].copy_from_slice(&header);
            base = MemoryBackend::from_bytes(bytes);
        }
        let disk = fault_disk(&base, None);
        let state = Arc::clone(&disk.0);
        let failed = Adapter::from_device(disk).err().unwrap();
        assert_eq!(
            failed.status,
            Status::Unsupported,
            "variant {variant}: {failed}"
        );
        assert_eq!(
            state.lock().unwrap().calls,
            0,
            "mutation before complete validation"
        );
        assert_eq!(state.lock().unwrap().visible.as_slice(), base.as_slice());
        retain(&base, &format!("windows-refused-store-{variant}.img"));
    }
}

#[test]
fn recovery_failures_never_retry_or_report_a_successful_open() {
    let mut checkpoints = 0;
    for journaled in [false, true] {
        let base = orphan_fixture(journaled);
        let disk = fault_disk(&base, None);
        let state = Arc::clone(&disk.0);
        let adapter = Adapter::from_device(disk).unwrap();
        let count = state.lock().unwrap().calls;
        let recovered = MemoryBackend::from_bytes(state.lock().unwrap().durable.clone());
        drop(adapter);
        retain(
            &recovered,
            &format!(
                "windows-durable-recovery-{}.img",
                if journaled { "journaled" } else { "plain" }
            ),
        );
        for failure in 1..=count {
            let disk = fault_disk(&base, Some(failure));
            let state = Arc::clone(&disk.0);
            assert!(Adapter::from_device(disk).is_err());
            assert_eq!(
                state.lock().unwrap().calls,
                failure,
                "drop retried recovery"
            );
            checkpoints += 1;
        }
    }
    println!("Deferred recovery: {checkpoints} write/sync failure checkpoints passed");
}

#[test]
fn catalog_file_lock_bit_blocks_engine_and_adapter_writes() {
    use fstool::fs::{Filesystem, OpenFlags};
    let mut disk = fixture(true, false);
    let fs = HfsPlus::open(&mut disk).unwrap();
    let record = fs.catalog_record("/Folder/file.txt").unwrap();
    let mut bytes = disk.into_bytes();
    let offset = bytes
        .windows(record.len())
        .position(|b| b == record)
        .unwrap();
    bytes[offset + 3] |= 1;
    let mut disk = MemoryBackend::from_bytes(bytes);
    let mut fs = HfsPlus::open(&mut disk).unwrap();
    assert!(
        fs.open_file_rw(
            &mut disk,
            Path::new("/Folder/file.txt"),
            OpenFlags::default(),
            None
        )
        .is_err()
    );
    let mut adapter = Adapter::from_device(disk).unwrap();
    assert_eq!(
        adapter.open(r"\Folder\file.txt", all()).unwrap_err().status,
        Status::AccessDenied
    );
    let file = adapter
        .open(r"\Folder\file.txt", Default::default())
        .unwrap();
    assert_eq!(read(&mut adapter, file), b"original");
    assert_eq!(adapter.file_info(file).unwrap().attributes & 1, 1);
    adapter.close(file).unwrap();
    adapter.shutdown().unwrap();
}

#[test]
fn mismatched_catalog_threads_refuse_stable_identity_resolution() {
    let mut base = fixture(true, false);
    let fs = HfsPlus::open(&mut base).unwrap();
    let record = fs.catalog_record("/Folder/file.txt").unwrap();
    let cnid = volume::be32(&record, 8);
    let parent = volume::be32(&fs.catalog_record("/Folder").unwrap(), 8);
    assert_eq!(fs.catalog_path(cnid).unwrap(), "/Folder/file.txt");
    assert_eq!(fs.catalog_path(2).unwrap(), "/");
    assert!(fs.catalog_path(u32::MAX).is_err());
    let mut wire = Vec::new();
    wire.extend_from_slice(&6u16.to_be_bytes());
    wire.extend_from_slice(&cnid.to_be_bytes());
    wire.extend_from_slice(&0u16.to_be_bytes());
    wire.extend_from_slice(&4u16.to_be_bytes());
    wire.extend_from_slice(&0u16.to_be_bytes());
    wire.extend_from_slice(&parent.to_be_bytes());
    wire.extend_from_slice(&8u16.to_be_bytes());
    for unit in "file.txt".encode_utf16() {
        wire.extend_from_slice(&unit.to_be_bytes());
    }
    let thread = base
        .as_slice()
        .windows(wire.len())
        .position(|b| b == wire)
        .unwrap();
    let forward = base
        .as_slice()
        .windows(record.len())
        .position(|b| b == record)
        .unwrap();
    for variant in 0..3 {
        let mut bytes = base.as_slice().to_vec();
        match variant {
            0 => bytes[thread + 8..thread + 10].copy_from_slice(&3u16.to_be_bytes()),
            1 => bytes[forward + 8..forward + 12].copy_from_slice(&(cnid + 99).to_be_bytes()),
            2 => bytes[thread + 12..thread + 16].copy_from_slice(&u32::MAX.to_be_bytes()),
            _ => unreachable!(),
        }
        let mut disk = MemoryBackend::from_bytes(bytes.clone());
        let fs = HfsPlus::open(&mut disk).unwrap();
        assert!(fs.catalog_path(cnid).is_err());
        assert!(fs.catalog_record_cnid(cnid).is_err());
        assert_eq!(disk.as_slice(), bytes);
    }
}

#[test]
fn locked_parent_blocks_create_move_and_delete_without_poisoning_volume() {
    let mut disk = fixture(true, false);
    let fs = HfsPlus::open(&mut disk).unwrap();
    let record = fs.catalog_record("/Folder").unwrap();
    let mut bytes = disk.into_bytes();
    let offset = bytes
        .windows(record.len())
        .position(|b| b == record)
        .unwrap();
    bytes[offset + 41] |= 2; // BSD UF_IMMUTABLE on the parent, not the file.
    let mut adapter = Adapter::from_device(MemoryBackend::from_bytes(bytes)).unwrap();
    let file = adapter.open(r"\Folder\file.txt", all()).unwrap();
    assert_eq!(
        adapter
            .create(r"\Folder\new.txt", Kind::File, all())
            .unwrap_err()
            .status,
        Status::AccessDenied
    );
    assert_eq!(
        adapter.rename(file, r"\moved.txt").unwrap_err().status,
        Status::AccessDenied
    );
    assert_eq!(
        adapter.can_delete(file).unwrap_err().status,
        Status::AccessDenied
    );
    assert!(adapter.failure().is_none());
    assert_eq!(read(&mut adapter, file), b"original");
    adapter.close(file).unwrap();
    adapter.shutdown().unwrap();
}
