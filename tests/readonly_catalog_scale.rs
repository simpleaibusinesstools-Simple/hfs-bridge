//! Explicit diagnostic on the preserved Mac-generated 259039-file image.
//! No physical devices, image writes or native mounts.
use hfs_bridge::{
    image::Image,
    windows::{Access, Adapter, Kind, OpenRequest},
};
use std::{path::Path, time::Instant};

#[test]
#[ignore = "explicit large disposable image diagnostic"]
fn readonly_catalog_scale() {
    let source = Path::new("artifacts/milestone-23/native-metadata-fixture/metadata-scale.img");
    let started = Instant::now();
    let mut a = Adapter::from_read_only_device(Image::read_only(source, 0, None).unwrap()).unwrap();
    println!("SCALE open_seconds={:.3}", started.elapsed().as_secs_f64());
    let request = OpenRequest {
        access: Access::READ,
        kind: Some(Kind::Directory),
        ..Default::default()
    };
    let groups: usize = std::env::var("HFS_SCALE_GROUPS")
        .unwrap_or_else(|_| "1".into())
        .parse()
        .unwrap();
    assert!((1..=260).contains(&groups));
    for group in 0..groups {
        let at = Instant::now();
        let path = format!(r"\Benchmark\Group-{group:03}");
        let h = a.open(&path, request).unwrap();
        let entries = a.read_directory(h).unwrap();
        assert_eq!(entries.len(), (259039 - group * 1000).min(1000));
        a.close(h).unwrap();
        let h = a
            .open(
                &format!("{path}\\File-0000.bin"),
                OpenRequest {
                    access: Access::READ,
                    ..Default::default()
                },
            )
            .unwrap();
        let mut bytes = [0; 258];
        assert_eq!(a.read(h, 0, &mut bytes).unwrap(), 257);
        for (i, byte) in bytes[..257].iter().enumerate() {
            assert_eq!(*byte, ((i * 31 + group) % 251) as u8);
        }
        a.close(h).unwrap();
        println!(
            "SCALE group={group} entries={} seconds={:.3}",
            entries.len(),
            at.elapsed().as_secs_f64()
        );
    }
    println!(
        "SCALE PASS groups={groups} seconds={:.3}",
        started.elapsed().as_secs_f64()
    );
}

#[test]
#[ignore = "explicit repeated-open performance diagnostic on a disposable image"]
fn readonly_thumbnail_style_opens() {
    let source = Path::new("artifacts/milestone-23/native-metadata-fixture/metadata-scale.img");
    let mut a = Adapter::from_read_only_device(Image::read_only(source, 0, None).unwrap()).unwrap();
    let request = OpenRequest {
        access: Access::READ,
        ..Default::default()
    };
    let at = Instant::now();
    for index in 0..1000 {
        let h = a
            .open(
                &format!(r"\Benchmark\Group-000\File-{index:04}.bin"),
                request,
            )
            .unwrap();
        let size = a.file_info_with_ea(h).unwrap().size;
        assert!(size <= 257);
        assert_eq!(a.streams(h).unwrap().len(), 1);
        let mut data = [0; 257];
        assert_eq!(a.read(h, 0, &mut data).unwrap(), size as usize);
        a.close(h).unwrap();
    }
    println!(
        "THUMBNAIL_STYLE PASS files=1000 seconds={:.3}",
        at.elapsed().as_secs_f64()
    );
    a.shutdown().unwrap();
}
