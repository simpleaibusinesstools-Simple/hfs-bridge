use fstool::{
    block::MemoryBackend,
    fs::hfs_plus::{FormatOpts, HfsPlus},
};
use hfs_bridge::{
    engine, image,
    partitions::{self, Scheme},
};
use std::{
    io::{Cursor, Write},
    path::Path,
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
};

const HFS: [u8; 16] = [
    0, 0x53, 0x46, 0x48, 0, 0, 0xaa, 0x11, 0xaa, 0x11, 0, 0x30, 0x65, 0x43, 0xec, 0xac,
];
fn put32(b: &mut [u8], o: usize, x: u32) {
    b[o..o + 4].copy_from_slice(&x.to_le_bytes());
}
fn put64(b: &mut [u8], o: usize, x: u64) {
    b[o..o + 8].copy_from_slice(&x.to_le_bytes());
}
fn big32(b: &mut [u8], o: usize, x: u32) {
    b[o..o + 4].copy_from_slice(&x.to_be_bytes());
}
// Independent table-based encoder; production CRC uses a bit-at-a-time loop.
fn checksum(bytes: &[u8]) -> u32 {
    let table: Vec<u32> = (0..256u32)
        .map(|mut n| {
            for _ in 0..8 {
                n = if n & 1 != 0 {
                    (n >> 1) ^ 0xedb88320
                } else {
                    n >> 1
                };
            }
            n
        })
        .collect();
    !bytes.iter().fold(!0u32, |sum, b| {
        (sum >> 8) ^ table[((sum as u8) ^ b) as usize]
    })
}
fn raw() -> Vec<u8> {
    let mut disk = MemoryBackend::new(32 * 1024 * 1024);
    let mut fs = HfsPlus::format(
        &mut disk,
        &FormatOpts {
            journaled: true,
            ..Default::default()
        },
    )
    .unwrap();
    fs.create_file(
        &mut disk,
        "/original",
        &mut &b"Mac partition payload"[..],
        21,
        0o640,
        501,
        20,
        1_700_000_000,
    )
    .unwrap();
    fs.flush(&mut disk).unwrap();
    disk.into_bytes()
}
fn entry(entries: &mut [u8], slot: usize, start: u64, end: u64, hfs: bool) {
    let e = &mut entries[slot * 128..(slot + 1) * 128];
    e[..16].copy_from_slice(&if hfs { HFS } else { [0x33; 16] });
    e[16..32].fill(slot as u8 + 1);
    put64(e, 32, start);
    put64(e, 40, end);
    for (i, c) in "Mac Ω".encode_utf16().enumerate() {
        e[56 + i * 2..58 + i * 2].copy_from_slice(&c.to_le_bytes());
    }
}
fn gpt_image(block: usize) -> Vec<u8> {
    let volume = raw();
    let size = volume.len() + 4 * 1024 * 1024;
    let mut image = vec![0xab; size];
    image[..block * 2 + 16384].fill(0);
    image[size - block - 16384..].fill(0);
    image[510..512].copy_from_slice(&[0x55, 0xaa]);
    image[450] = 0xee;
    put32(&mut image, 454, 1);
    put32(&mut image, 458, (size / block - 1) as u32);
    image[1024 * 1024..1024 * 1024 + volume.len()].copy_from_slice(&volume);
    let mut entries = vec![0; 16384];
    entry(
        &mut entries,
        0,
        128 * 1024 / block as u64,
        256 * 1024 / block as u64 - 1,
        false,
    );
    entry(
        &mut entries,
        2,
        1024 * 1024 / block as u64,
        (1024 * 1024 + volume.len()) as u64 / block as u64 - 1,
        true,
    );
    write_gpt(&mut image, block, &entries);
    image
}
fn write_gpt(image: &mut [u8], block: usize, entries: &[u8]) {
    let last = image.len() / block - 1;
    let table_blocks = entries.len() / block;
    for (lba, other, table) in [(1, last, 2), (last, 1, last - table_blocks)] {
        image[table * block..table * block + entries.len()].copy_from_slice(entries);
        let mut h = vec![0; block];
        h[..8].copy_from_slice(b"EFI PART");
        put32(&mut h, 8, 0x10000);
        put32(&mut h, 12, 92);
        put64(&mut h, 24, lba as u64);
        put64(&mut h, 32, other as u64);
        put64(&mut h, 40, (2 + table_blocks) as u64);
        put64(&mut h, 48, (last - table_blocks - 1) as u64);
        h[56..72].fill(7);
        put64(&mut h, 72, table as u64);
        put32(&mut h, 80, 128);
        put32(&mut h, 84, 128);
        put32(&mut h, 88, checksum(entries));
        let crc = checksum(&h[..92]);
        put32(&mut h, 16, crc);
        image[lba * block..(lba + 1) * block].copy_from_slice(&h);
    }
}
fn discover(bytes: &[u8], block: u32) -> std::io::Result<partitions::Layout> {
    partitions::discover(&mut Cursor::new(bytes), bytes.len() as u64, block)
}
fn apm(block: usize) -> Vec<u8> {
    let volume = raw();
    let size = volume.len() + 1024 * 1024;
    let mut image = vec![0; size];
    image[..2].copy_from_slice(b"ER");
    image[2..4].copy_from_slice(&(block as u16).to_be_bytes());
    big32(&mut image, 4, (size / block) as u32);
    for (slot, start, blocks, name, kind) in [
        (1, 1, 63, "Apple", "Apple_partition_map"),
        (
            2,
            1024 * 1024 / block,
            volume.len() / block,
            "Mac",
            "Apple_HFS",
        ),
    ] {
        let e = &mut image[slot * block..slot * block + 512];
        e[..2].copy_from_slice(b"PM");
        big32(e, 4, 2);
        big32(e, 8, start as u32);
        big32(e, 12, blocks as u32);
        e[16..16 + name.len()].copy_from_slice(name.as_bytes());
        e[48..48 + kind.len()].copy_from_slice(kind.as_bytes());
        big32(e, 84, blocks as u32);
        big32(e, 88, 0x37);
    }
    image[1024 * 1024..].copy_from_slice(&volume);
    image
}
#[test]
fn known_crc_reference_and_gpt_512_and_4k_bounds() {
    assert_eq!(checksum(b"123456789"), 0xcbf43926);
    for block in [512, 4096] {
        let bytes = gpt_image(block);
        let layout = discover(&bytes, block as u32).unwrap();
        assert_eq!(layout.scheme, Scheme::Gpt);
        assert_eq!(layout.partitions.len(), 2);
        assert!(layout.select(1, false).is_err());
        let selected = layout.select(3, true).unwrap();
        assert_eq!(
            (selected.offset, selected.length),
            (1024 * 1024, 32 * 1024 * 1024)
        );
        assert_eq!(selected.name, "Mac Ω");
        let mut bounded = MemoryBackend::from_bytes(
            bytes[selected.offset as usize..(selected.offset + selected.length) as usize].to_vec(),
        );
        let fs = engine::open_checked(&mut bounded).unwrap();
        assert_eq!(fs.catalog_record("/original").unwrap().len(), 248);
    }
}
#[test]
fn corrupt_header_table_backup_and_hybrid_are_refused_without_fallback() {
    let bytes = gpt_image(512);
    for offset in [
        512 + 16,
        1024 + 128,
        bytes.len() - 512 + 16,
        bytes.len() - 512 - 16384 + 128,
        446 + 16 + 4,
    ] {
        let mut bad = bytes.clone();
        bad[offset] ^= 1;
        assert!(discover(&bad, 512).is_err(), "offset {offset}");
    }
    let mut missing = bytes.clone();
    missing[510] = 0;
    assert!(discover(&missing, 512).is_err());
    assert!(discover(&gpt_image(4096), 512).is_err());
}
#[test]
fn valid_crc_cannot_hide_overlap_identity_bounds_or_flags() {
    let original = gpt_image(512);
    for variant in 0..9 {
        let mut bytes = original.clone();
        let mut entries = bytes[1024..1024 + 16384].to_vec();
        let e = &mut entries[256..384];
        match variant {
            0 => put64(e, 32, 128 * 1024 / 512),
            1 => e[16..32].fill(1),
            2 => put64(e, 40, u64::MAX),
            3 => e[16..32].fill(0),
            4 => put64(e, 32, 1),
            5 => put64(e, 48, 8),
            6 => e[56..58].copy_from_slice(&0xd800u16.to_le_bytes()),
            7 => put64(e, 48, 1u64 << 60),
            8 => put64(e, 48, 1),
            _ => unreachable!(),
        }
        write_gpt(&mut bytes, 512, &entries);
        if variant >= 7 {
            let layout = discover(&bytes, 512).unwrap();
            assert!(layout.select(3, false).is_ok());
            assert!(layout.select(3, true).is_err());
        } else {
            assert!(discover(&bytes, 512).is_err(), "variant {variant}");
        }
    }
}
#[test]
fn apple_maps_respect_device_blocks_flags_and_map_reservation() {
    for block in [512, 1024, 2048, 4096] {
        let bytes = apm(block);
        let layout = discover(&bytes, 512).unwrap();
        assert_eq!(layout.scheme, Scheme::Apple);
        assert_eq!(layout.block_size, block as u32);
        assert_eq!(layout.select(2, true).unwrap().offset, 1024 * 1024);
        for (offset, value) in [
            (block * 2 + 4, 3),
            (block * 2 + 8, 1),
            (block * 2 + 80, 1),
            (4, 1),
        ] {
            let mut bad = bytes.clone();
            big32(&mut bad, offset, value);
            assert!(discover(&bad, 512).is_err());
        }
        let mut readonly = bytes.clone();
        big32(&mut readonly, block * 2 + 88, 0x17);
        let layout = discover(&readonly, 512).unwrap();
        assert!(layout.select(2, false).is_ok());
        assert!(layout.select(2, true).is_err());
    }
}
#[test]
fn mbr_primary_ranges_and_raw_volume_are_distinct() {
    let volume = raw();
    let mut bytes = vec![0; volume.len() + 1024 * 1024];
    bytes[510..512].copy_from_slice(&[0x55, 0xaa]);
    bytes[450] = 0xaf;
    put32(&mut bytes, 454, 2048);
    put32(&mut bytes, 458, (volume.len() / 512) as u32);
    bytes[1024 * 1024..].copy_from_slice(&volume);
    let layout = discover(&bytes, 512).unwrap();
    assert_eq!(layout.scheme, Scheme::Mbr);
    assert_eq!(layout.select(1, true).unwrap().length, volume.len() as u64);
    for kind in [0x05, 0x0f, 0x85, 0xee] {
        let mut bad = bytes.clone();
        bad[450] = kind;
        assert!(discover(&bad, 512).is_err());
    }
    let layout = discover(&volume, 512).unwrap();
    assert_eq!(layout.scheme, Scheme::Raw);
    assert!(layout.select(0, true).is_ok());
    assert!(layout.select(1, true).is_err());
    assert!(discover(&vec![0; 4096], 512).is_err());
}
#[test]
fn malformed_geometry_and_truncated_reads_return_errors() {
    let bytes = gpt_image(512);
    for size in [0, 512, 1024, bytes.len() as u64 - 1, u64::MAX] {
        assert!(partitions::discover(&mut Cursor::new(&bytes), size, 512).is_err());
    }
    assert!(discover(&bytes, 1024).is_err());
    let mut bounded = Cursor::new(&bytes[..1536]);
    assert!(partitions::discover(&mut bounded, bytes.len() as u64, 512).is_err());
}
static NEXT: AtomicU64 = AtomicU64::new(0);
fn fresh() -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "hfs-partitions-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir(&dir).unwrap();
    dir
}
fn cli(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_hfs-bridge"))
        .args(args)
        .output()
        .unwrap()
}
fn path(p: &Path) -> &str {
    p.to_str().unwrap()
}
#[test]
fn cli_selection_preserves_source_and_all_bytes_outside_partition() {
    let dir = fresh();
    let source = dir.join("disk.img");
    let output = dir.join("edited.img");
    let extracted = dir.join("payload.bin");
    let before = gpt_image(512);
    let mut file = image::create_output(&source).unwrap();
    file.write_all(&before).unwrap();
    file.sync_all().unwrap();
    drop(file);
    assert!(cli(&["partitions", path(&source)]).status.success());
    assert!(
        cli(&["list", path(&source), "--partition", "3"])
            .status
            .success()
    );
    let result = cli(&[
        "mkdir",
        path(&source),
        "/Windows",
        "--partition",
        "3",
        "--output",
        path(&output),
    ]);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let after = std::fs::read(&output).unwrap();
    assert_eq!(before[..1024 * 1024], after[..1024 * 1024]);
    let end = 1024 * 1024 + 32 * 1024 * 1024;
    assert_eq!(before[end..], after[end..]);
    assert_eq!(std::fs::read(&source).unwrap(), before);
    assert!(
        cli(&[
            "extract",
            path(&output),
            "/original",
            path(&extracted),
            "--partition",
            "3"
        ])
        .status
        .success()
    );
    assert_eq!(std::fs::read(&extracted).unwrap(), b"Mac partition payload");
    if let Some(directory) = std::env::var_os("HFS_PARTITION_ARTIFACT_DIR") {
        std::fs::copy(&source, Path::new(&directory).join("gpt-source.img")).unwrap();
        std::fs::copy(&output, Path::new(&directory).join("gpt-edited.img")).unwrap();
        std::fs::write(
            Path::new(&directory).join("gpt-volume.img"),
            &after[1024 * 1024..end],
        )
        .unwrap();
    }
}
#[test]
fn invalid_cli_selection_creates_no_output() {
    let dir = fresh();
    let source = dir.join("disk.img");
    std::fs::write(&source, gpt_image(512)).unwrap();
    for extra in [
        vec!["--partition", "1"],
        vec!["--partition", "2"],
        vec!["--partition", "3", "--offset", "0"],
        vec!["--partition", "3", "--length", "512"],
        vec!["--partition", "3", "--partition", "3"],
        vec!["--sector-size", "4096"],
    ] {
        let output = dir.join(format!(
            "refused-{}.img",
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let mut args = vec![
            "mkdir",
            path(&source),
            "/refused",
            "--output",
            path(&output),
        ];
        args.extend(extra);
        assert!(!cli(&args).status.success());
        assert!(!output.exists());
    }
}
