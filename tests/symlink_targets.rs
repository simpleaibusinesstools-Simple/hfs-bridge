use fstool::{
    block::MemoryBackend,
    fs::hfs_plus::{FormatOpts, HfsPlus},
};
use hfs_bridge::{
    links::symbolic_packet,
    names,
    windows::{Adapter, OpenRequest, Status},
};
use std::{io::Write, path::Path};
#[path = "support/fault_disk.rs"]
#[allow(dead_code)]
mod fault;

fn fixture() -> (Adapter<fault::Disk>, fault::Disk) {
    let mut disk = MemoryBackend::new(4 * 1024 * 1024);
    let mut fs = HfsPlus::format(
        &mut disk,
        &FormatOpts {
            journaled: true,
            ..Default::default()
        },
    )
    .unwrap();
    for path in ["/Folder", "/Folder/Sub", "/Other"] {
        fs.create_dir(&mut disk, path, 0o755, 501, 20, 1_700_000_000)
            .unwrap();
    }
    for path in [
        "/Folder/Sub/link",
        "/root-link",
        "/Folder/CON.txt",
        "/Folder/MixedCase.txt",
        "/Folder/café.txt",
        "/Folder/slash:name",
        "/Folder/file",
    ] {
        fs.create_file(
            &mut disk,
            path,
            &mut &b""[..],
            0,
            0o644,
            501,
            20,
            1_700_000_000,
        )
        .unwrap();
    }
    fs.create_symlink(
        &mut disk,
        "/Folder/indirect",
        "Sub",
        0o777,
        501,
        20,
        1_700_000_000,
    )
    .unwrap();
    fs.flush(&mut disk).unwrap();
    let mut resource = fs
        .open_resource_fork_rw(&mut disk, Path::new("/root-link"))
        .unwrap();
    resource.write_all(b"resource").unwrap();
    resource.sync().unwrap();
    drop(resource);
    let disk = fault::Disk::new(&disk.into_bytes());
    let adapter = Adapter::from_device(disk.clone()).unwrap();
    (adapter, disk)
}

#[test]
fn resolves_real_aliases_unicode_case_and_relative_ancestors_without_writes() {
    let (mut a, disk) = fixture();
    let handle = a.open(r"\Folder\Sub\link", OpenRequest::default()).unwrap();
    let folder = a.open(r"\Folder", OpenRequest::default()).unwrap();
    let entries = a.read_directory(folder).unwrap();
    // Match stable CNIDs through the fixture's distinct payload-independent
    // alias spelling. Actual alias names come from the live directory map.
    let aliases: Vec<_> = entries.iter().filter(|entry| entry.aliased).collect();
    assert_eq!(aliases.len(), 2);
    disk.arm(None);
    for (target, expected) in [
        (r"..\mixedcase.TXT", "../MixedCase.txt".to_owned()),
        (
            r"..\café.txt",
            format!("../{}", names::new_windows_component("café.txt").unwrap()),
        ),
        (r"..\..\Other", "../../Other".to_owned()),
        (r".\new.txt", "./new.txt".to_owned()),
        (r"missing\child", "missing/child".to_owned()),
        (r"..\indirect", "../indirect".to_owned()),
        (r"..\Sub\..\file", "../Sub/../file".to_owned()),
        (".", ".".to_owned()),
    ] {
        assert_eq!(
            a.plan_symbolic_target(handle, &symbolic_packet(target).unwrap())
                .unwrap(),
            expected
        );
    }
    let mut translated = aliases
        .iter()
        .map(|entry| {
            a.plan_symbolic_target(
                handle,
                &symbolic_packet(&format!("..\\{}", entry.name)).unwrap(),
            )
            .unwrap()
        })
        .collect::<Vec<_>>();
    translated.sort();
    assert_eq!(translated, ["../CON.txt", "../slash:name"]);
    assert_eq!(
        disk.0.lock().unwrap().calls,
        0,
        "planner attempted a write or sync"
    );
}

#[test]
fn refuses_root_escape_reserved_names_and_non_directory_traversal_without_writes() {
    let (mut a, disk) = fixture();
    let handle = a.open(r"\Folder\Sub\link", OpenRequest::default()).unwrap();
    disk.arm(None);
    for (target, status) in [
        (r"..\..\..\outside", Status::AccessDenied),
        (r"..\..\.HFS-BRIDGE-ORPHANS-V1\new", Status::AccessDenied),
        (r"..\file\..\Sub", Status::NotDirectory),
        (r"..\indirect\new", Status::NotDirectory),
        (r"..\indirect\..\Sub", Status::NotDirectory),
        (r"missing\..\link", Status::Unsupported),
        (r"missing\.", Status::Unsupported),
        (r"..\~HFS-00000099-stale", Status::InvalidName),
        (r"..\CON", Status::InvalidName),
        (r"..\file\\new", Status::InvalidName),
        ("trailing\\", Status::InvalidName),
        ("bad/name", Status::AccessDenied),
    ] {
        assert_eq!(
            a.plan_symbolic_target(handle, &symbolic_packet(target).unwrap())
                .unwrap_err()
                .status,
            status,
            "{target}"
        );
    }
    let long = vec!["猫".repeat(120); 3].join("\\");
    assert_eq!(
        a.plan_symbolic_target(handle, &symbolic_packet(&long).unwrap())
            .unwrap_err()
            .status,
        Status::Unsupported
    );
    assert_eq!(disk.0.lock().unwrap().calls, 0);
}

#[test]
fn root_dangling_target_and_handle_boundaries() {
    let (mut a, disk) = fixture();
    let handle = a.open(r"\root-link", OpenRequest::default()).unwrap();
    let stream = a
        .open(r"\root-link:AFP_Resource", OpenRequest::default())
        .unwrap();
    let folder = a.open(r"\Folder", OpenRequest::default()).unwrap();
    disk.arm(None);
    let packet = symbolic_packet("new\\child").unwrap();
    assert_eq!(
        a.plan_symbolic_target(handle, &packet).unwrap(),
        "new/child"
    );
    assert_eq!(
        a.plan_symbolic_target(stream, &packet).unwrap_err().status,
        Status::InvalidHandle
    );
    assert_eq!(
        a.plan_symbolic_target(folder, &packet).unwrap_err().status,
        Status::Unsupported
    );
    assert_eq!(disk.0.lock().unwrap().calls, 0);
    a.cleanup(handle, false).unwrap();
    assert_eq!(
        a.plan_symbolic_target(handle, &packet).unwrap_err().status,
        Status::InvalidHandle
    );
    a.close(handle).unwrap();
    assert_eq!(
        a.plan_symbolic_target(handle, &packet).unwrap_err().status,
        Status::InvalidHandle
    );
}
