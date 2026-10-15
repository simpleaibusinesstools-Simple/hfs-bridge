//! Independent Unicode 3.2 vectors and raw catalog-byte assertions.
use fstool::block::MemoryBackend;
use fstool::fs::hfs_plus::{FormatOpts, HfsPlus, catalog::UniStr, unicode::normalize_units};
use fstool::fs::{Filesystem, OpenFlags};
use hfs_bridge::{
    engine,
    names::{DirectoryNames, new_windows_component, windows_component},
    volume,
};
use std::io::{Read, Write};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

fn units(text: &str) -> Vec<u16> {
    text.encode_utf16().collect()
}
fn text(units: &[u16]) -> String {
    String::from_utf16(units).unwrap()
}

#[test]
fn official_unicode_32_bmp_normalization_vectors() {
    let source = include_str!("../research/evidence/unicode-3.2/NormalizationTest-3.2.0.txt");
    let mut checked = 0;
    let mut skipped = 0;
    for line in source.lines() {
        let content = line.split('#').next().unwrap().trim();
        if content.is_empty() || content.starts_with('@') {
            continue;
        }
        let columns: Vec<Vec<u32>> = content
            .split(';')
            .take(3)
            .map(|column| {
                column
                    .split_whitespace()
                    .map(|unit| u32::from_str_radix(unit, 16).unwrap())
                    .collect()
            })
            .collect();
        if columns.iter().flatten().any(|&unit| {
            unit > 0xFFFF || (0x2000..=0x2FFF).contains(&unit) || (0xF900..=0xFAFF).contains(&unit)
        }) {
            skipped += 1;
            continue;
        }
        let expected: Vec<u16> = columns[2].iter().map(|&unit| unit as u16).collect();
        for input in &columns {
            let input: Vec<u16> = input.iter().map(|&unit| unit as u16).collect();
            assert_eq!(normalize_units(&text(&input)), expected, "{content}");
        }
        checked += 1;
    }
    assert!(checked > 12000 && skipped > 100);
    println!(
        "UNICODE_VECTORS: {checked} official BMP rows passed; {skipped} excluded/supplementary rows handled by separate HFS tests"
    );
}

#[test]
fn hfs_exclusions_supplementary_and_fixed_version_are_preserved() {
    for input in [
        "\u{212B}",
        "\u{2126}",
        "\u{F900}",
        "\u{FA10}",
        "\u{2F800}",
        "\u{1D15E}",
        "\u{1B06}",
        "🙂",
    ] {
        assert_eq!(normalize_units(input), units(input), "{input:?}");
    }
    assert_eq!(
        normalize_units("Café 가 각"),
        units("Cafe\u{301} \u{1100}\u{1161} \u{1100}\u{1161}\u{11A8}")
    );
    assert_eq!(normalize_units("D\u{307}\u{323}"), units("D\u{323}\u{307}"));
    assert_eq!(normalize_units("\u{307}\u{323}a"), units("\u{323}\u{307}a"));
    assert_eq!(normalize_units("a\u{301}\u{300}"), units("a\u{301}\u{300}"));
    assert_eq!(normalize_units("\u{FB01}"), units("\u{FB01}")); // compatibility ligature
}

#[test]
fn normalized_length_and_utf16_boundaries_are_enforced() {
    let valid = format!("{}é", "a".repeat(253));
    let invalid = format!("{}é", "a".repeat(254));
    assert_eq!(
        UniStr::from_path_component_checked(&valid)
            .unwrap()
            .code_units
            .len(),
        255
    );
    assert!(UniStr::from_path_component_checked(&invalid).is_err());
    assert!(engine::validate_hfs_path(&format!("/{invalid}")).is_err());
    assert!(new_windows_component(&invalid).is_err());
    assert!(UniStr::from_path_component_checked(&format!("{}🙂", "a".repeat(253))).is_ok());
    assert!(UniStr::from_path_component_checked(&format!("{}🙂", "a".repeat(254))).is_err());
    for name in ["", "a\0b", "a\u{FFFE}", "a\u{FFFF}"] {
        assert!(UniStr::from_path_component_checked(name).is_err());
    }
}

fn base(journaled: bool) -> MemoryBackend {
    let mut disk = MemoryBackend::new(32 * 1024 * 1024);
    let mut fs = HfsPlus::format(
        &mut disk,
        &FormatOpts {
            journaled,
            ..Default::default()
        },
    )
    .unwrap();
    fs.create_dir(&mut disk, "/Café", 0o755, 501, 20, 1_700_000_000)
        .unwrap();
    fs.flush(&mut disk).unwrap();
    disk
}
fn create(fs: &mut HfsPlus, disk: &mut MemoryBackend, path: &str, payload: &[u8]) -> u32 {
    fs.create_file(
        disk,
        path,
        &mut &payload[..],
        payload.len() as u64,
        0o644,
        501,
        20,
        1_700_000_000,
    )
    .unwrap()
}
fn read(fs: &mut HfsPlus, disk: &mut MemoryBackend, path: &str) -> Vec<u8> {
    let mut out = Vec::new();
    Filesystem::read_file(fs, disk, Path::new(path))
        .unwrap()
        .read_to_end(&mut out)
        .unwrap();
    out
}
fn retain(name: &str, disk: &MemoryBackend) {
    if let Some(directory) = std::env::var_os("HFS_CRASH_ARTIFACT_DIR") {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(Path::new(&directory).join(name))
            .unwrap();
        file.write_all(disk.as_slice()).unwrap();
        file.sync_all().unwrap();
    }
}
// Inspect catalog keys independently of UniStr/candidate catalog decoders.
fn wire_key(disk: &MemoryBackend, cnid: u32) -> usize {
    let bytes = disk.as_slice();
    let cat = volume::be32(bytes, 1024 + 272 + 16) as usize * volume::be32(bytes, 1064) as usize;
    let ns = volume::be16(bytes, cat + 32) as usize;
    let mut leaf = volume::be32(bytes, cat + 24);
    while leaf != 0 {
        let node = cat + leaf as usize * ns;
        for i in 0..volume::be16(bytes, node + 10) as usize {
            let key = node + volume::be16(bytes, node + ns - 2 * (i + 1)) as usize;
            let body = key + 2 + volume::be16(bytes, key) as usize;
            if [1, 2].contains(&volume::be16(bytes, body)) && volume::be32(bytes, body + 8) == cnid
            {
                return key;
            }
        }
        leaf = volume::be32(bytes, node);
    }
    panic!("catalog identity absent");
}
fn wire_name(disk: &MemoryBackend, cnid: u32) -> Vec<u16> {
    let key = wire_key(disk, cnid);
    (0..volume::be16(disk.as_slice(), key + 6) as usize)
        .map(|i| volume::be16(disk.as_slice(), key + 8 + 2 * i))
        .collect()
}

#[test]
fn nfc_paths_persist_decomposed_wire_names_and_support_edit_move_delete() {
    for journaled in [false, true] {
        let mut disk = base(journaled);
        let mut fs = HfsPlus::open(&mut disk).unwrap();
        let cnid = create(
            &mut fs,
            &mut disk,
            "/Café/Música-각.txt",
            b"original payload",
        );
        fs.flush(&mut disk).unwrap();
        assert_eq!(
            wire_name(&disk, cnid),
            units("Mu\u{301}sica-\u{1100}\u{1161}\u{11A8}.txt")
        );
        let before = fs
            .catalog_record("/Cafe\u{301}/Mu\u{301}sica-각.txt")
            .unwrap();
        {
            let mut handle = fs
                .open_file_rw(
                    &mut disk,
                    Path::new("/CAFÉ/MÚSICA-각.txt"),
                    OpenFlags::default(),
                    None,
                )
                .unwrap();
            handle.write_all(b"EDIT").unwrap();
            handle.sync().unwrap();
        }
        fs.rename(&mut disk, "/Café/Música-각.txt", "/Café/Résumé.txt")
            .unwrap();
        fs.flush(&mut disk).unwrap();
        let mut fs = HfsPlus::open(&mut disk).unwrap();
        assert_eq!(
            volume::be32(&fs.catalog_record("/Café/Résumé.txt").unwrap(), 8),
            volume::be32(&before, 8)
        );
        assert_eq!(
            read(&mut fs, &mut disk, "/Café/Résumé.txt"),
            b"EDITinal payload"
        );
        assert_eq!(wire_name(&disk, cnid), units("Re\u{301}sume\u{301}.txt"));
        retain(
            if journaled {
                "unicode-journaled.img"
            } else {
                "unicode-plain.img"
            },
            &disk,
        );
        fs.remove(&mut disk, "/Cafe\u{301}/Résumé.txt").unwrap();
        fs.flush(&mut disk).unwrap();
        assert!(
            HfsPlus::open(&mut disk)
                .unwrap()
                .catalog_record("/Café/Résumé.txt")
                .is_err()
        );
    }
}

#[test]
fn canonical_collisions_and_expansion_refuse_before_payload_or_allocation_changes() {
    let mut disk = base(true);
    let mut fs = HfsPlus::open(&mut disk).unwrap();
    create(&mut fs, &mut disk, "/Café/é.txt", b"keep original");
    fs.flush(&mut disk).unwrap();
    let before = disk.as_slice().to_vec();
    for path in [
        "/Café/e\u{301}.txt".to_string(),
        format!("/Café/{}é", "a".repeat(254)),
    ] {
        assert!(
            fs.create_file(
                &mut disk,
                &path,
                &mut &b"do not write"[..],
                12,
                0o644,
                0,
                0,
                0
            )
            .is_err()
        );
        assert!(
            disk.as_slice() == before,
            "rejected creation changed image bytes"
        );
    }
    fs.flush(&mut disk).unwrap();
    let after = volume::inspect(&mut disk).unwrap();
    assert_eq!(after.header.free_blocks, volume::be32(&before, 1072));
    assert_eq!(
        volume::be32(disk.as_slice(), 1088),
        volume::be32(&before, 1088)
    );
    assert_eq!(read(&mut fs, &mut disk, "/Café/é.txt"), b"keep original");
}

#[test]
fn volume_name_is_normalized_and_invalid_expansion_does_not_format() {
    let mut disk = MemoryBackend::new(32 * 1024 * 1024);
    let fs = HfsPlus::format(
        &mut disk,
        &FormatOpts {
            volume_name: "Café 각".into(),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(fs.volume_name(), "Cafe\u{301} \u{1100}\u{1161}\u{11A8}");
    assert_eq!(wire_name(&disk, 2), units(fs.volume_name()));
    let before = disk.as_slice().to_vec();
    assert!(
        HfsPlus::format(
            &mut disk,
            &FormatOpts {
                volume_name: "é".repeat(128),
                ..Default::default()
            }
        )
        .is_err()
    );
    assert!(
        disk.as_slice() == before,
        "invalid volume name wrote image bytes"
    );
}

#[test]
fn windows_rules_cover_reserved_devices_controls_and_shell_suffixes() {
    for name in [
        "CON",
        "con.txt",
        "NUL.tar.gz",
        "COM¹.txt",
        "LPT³",
        "CONIN$",
        "CON .txt",
        "a:",
        "a\\b",
        "a/b",
        "a?b",
        "a*b",
        "a|b",
        "a<b",
        "a>b",
        "a\"b",
        "a\0b",
        "a\u{1f}b",
        "trail ",
        "trail.",
        ".",
        "..",
        "",
    ] {
        assert!(!windows_component(name), "{name:?}");
    }
    for name in [
        "normal.txt",
        ".git",
        "Café.txt",
        "🙂.png",
        "COM10.txt",
        " leading space",
        "a~b",
    ] {
        assert!(windows_component(name), "{name:?}");
    }
    assert_eq!(new_windows_component("Café").unwrap(), "Cafe\u{301}");
    for name in ["~HFS-00000010.txt", "~hfs-test"] {
        assert!(new_windows_component(name).is_err());
    }
}

#[test]
fn directory_aliases_are_unique_stable_and_resolve_only_current_entries() {
    let input: Vec<(u32, String)> = [
        "normal.txt",
        "CON.txt",
        "bad:name.txt",
        "back\\slash",
        "trail. ",
        "Case.txt",
        "CASE.txt",
        "~HFS-00000011.txt",
        "~HFſ-00000011.txt",
    ]
    .iter()
    .enumerate()
    .map(|(i, name)| (16 + i as u32, (*name).into()))
    .collect();
    let map = DirectoryNames::build(input.clone()).unwrap();
    assert!(!map.entries()[0].aliased);
    for entry in &map.entries()[1..8] {
        assert!(entry.aliased);
        assert!(windows_component(&entry.windows_name));
        assert_eq!(
            map.resolve(&entry.windows_name.to_lowercase())
                .unwrap()
                .cnid,
            entry.cnid
        );
    }
    // Win32 ordinal comparison, unlike full Unicode uppercase, does not fold
    // long s into ASCII S on this host. Either result must resolve uniquely.
    let long_s = &map.entries()[8];
    assert_eq!(map.resolve(&long_s.windows_name).unwrap().cnid, long_s.cnid);
    assert!(map.resolve("~HFS-FFFFFFFF.txt").is_err());
    assert!(map.resolve("CON.txt").is_err());
    assert!(map.resolve("Case.txt").is_err());
    let reversed = DirectoryNames::build(input.into_iter().rev()).unwrap();
    for entry in map.entries() {
        assert_eq!(reversed.resolve(&entry.windows_name).unwrap(), entry);
    }
}

#[test]
fn invalid_or_ambiguous_directory_inputs_fail_closed() {
    for name in ["", ".", "..", "a/b", "a\0b", "Café", "a\u{FFFE}"] {
        assert!(DirectoryNames::build([(16, name.to_string())]).is_err());
    }
    assert!(DirectoryNames::build([(15, "a".into())]).is_err());
    assert!(DirectoryNames::build([(16, "a".into()), (16, "b".into())]).is_err());
    assert!(DirectoryNames::build([(16, "a".repeat(256))]).is_err());
    assert!(
        DirectoryNames::build(Vec::<(u32, String)>::new())
            .unwrap()
            .resolve("file")
            .is_err()
    );
}

#[test]
fn hfsx_case_collisions_get_distinct_windows_aliases() {
    let mut bytes = base(false).as_slice().to_vec();
    bytes[1024..1026].copy_from_slice(b"HX");
    bytes[1026..1028].copy_from_slice(&5u16.to_be_bytes());
    let cat = volume::be32(&bytes, 1024 + 272 + 16) as usize * volume::be32(&bytes, 1064) as usize;
    bytes[cat + 51] = 0xbc;
    let alternate = bytes.len() - 1024;
    let header = bytes[1024..1536].to_vec();
    bytes[alternate..alternate + 512].copy_from_slice(&header);
    let mut disk = MemoryBackend::from_bytes(bytes);
    let mut fs = HfsPlus::open(&mut disk).unwrap();
    create(&mut fs, &mut disk, "/Café/Case.txt", b"first");
    create(&mut fs, &mut disk, "/Café/CASE.txt", b"second");
    fs.flush(&mut disk).unwrap();
    let mut fs = HfsPlus::open(&mut disk).unwrap();
    let entries = fs.list_path(&mut disk, "/Café").unwrap();
    let map =
        DirectoryNames::build(entries.into_iter().map(|entry| (entry.inode, entry.name))).unwrap();
    for entry in map.entries() {
        assert!(entry.aliased);
        assert!(matches!(
            read(
                &mut fs,
                &mut disk,
                &format!("/Café/{}", entry.hfs_component)
            )
            .as_slice(),
            b"first" | b"second"
        ));
    }
    assert_ne!(map.entries()[0].windows_name, map.entries()[1].windows_name);
    retain("unicode-hfsx.img", &disk);
}

static NEXT: AtomicU64 = AtomicU64::new(0);
struct TestDir {
    path: std::path::PathBuf,
    root: std::path::PathBuf,
}
impl TestDir {
    fn new() -> Self {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join(".cache/tests");
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join(format!(
            "unicode-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        let root = std::fs::canonicalize(root).unwrap();
        Self { path, root }
    }
}
impl Drop for TestDir {
    fn drop(&mut self) {
        if let Ok(resolved) = std::fs::canonicalize(&self.path)
            && resolved.starts_with(&self.root)
            && resolved != self.root
        {
            let _ = std::fs::remove_dir_all(resolved);
        }
    }
}

#[test]
fn windows_alias_exports_preserve_contents_identity_and_input_hash() {
    for journaled in [false, true] {
        let directory = TestDir::new();
        let image = directory.path.join("input.img");
        let mut disk = base(journaled);
        let mut fs = HfsPlus::open(&mut disk).unwrap();
        let inputs = [
            "CON.txt",
            "bad:name.txt",
            "back\\slash.txt",
            "trail. ",
            "résumé.txt",
            "~HFS-00000010.txt",
        ];
        for (i, name) in inputs.iter().enumerate() {
            create(
                &mut fs,
                &mut disk,
                &format!("/Café/{name}"),
                &[i as u8, 0, 255],
            );
        }
        fs.flush(&mut disk).unwrap();
        let raw_slash = fs.catalog_record("/Café/bad:name.txt").unwrap();
        assert_eq!(
            wire_name(&disk, volume::be32(&raw_slash, 8)),
            units("bad/name.txt")
        );
        std::fs::write(&image, disk.as_slice()).unwrap();
        let original_hash = engine::sha256(&mut std::fs::File::open(&image).unwrap()).unwrap();
        let map = engine::windows_names(&image, "/Café", 0, None).unwrap();
        for (i, name) in inputs.iter().enumerate() {
            let canonical = UniStr::from_path_component_checked(name)
                .unwrap()
                .to_display_name();
            let entry = map
                .entries()
                .iter()
                .find(|entry| entry.hfs_component == canonical)
                .unwrap();
            let output = directory.path.join(&entry.windows_name);
            let digest =
                engine::extract_windows(&image, "/Café", &entry.windows_name, &output, 0, None)
                    .unwrap();
            assert_eq!(std::fs::read(&output).unwrap(), [i as u8, 0, 255]);
            assert_eq!(
                digest,
                engine::sha256(&mut std::fs::File::open(&output).unwrap()).unwrap()
            );
        }
        assert_eq!(
            map.resolve("résumé.txt").unwrap().hfs_component,
            "re\u{301}sume\u{301}.txt"
        );
        let absent = directory.path.join("absent.bin");
        assert!(
            engine::extract_windows(&image, "/Café", "~HFS-FFFFFFFF.txt", &absent, 0, None)
                .is_err()
        );
        assert!(!absent.exists());
        assert_eq!(
            engine::sha256(&mut std::fs::File::open(&image).unwrap()).unwrap(),
            original_hash
        );
        retain(
            if journaled {
                "windows-alias-journaled.img"
            } else {
                "windows-alias-plain.img"
            },
            &disk,
        );
    }
}

#[test]
fn cli_adapter_checks_normalized_destination_spelling_and_invalid_output_preflight() {
    let directory = TestDir::new();
    let original = directory.path.join("input.img");
    let output = directory.path.join("renamed.img");
    let payload = directory.path.join("payload.bin");
    std::fs::write(&payload, b"unicode payload").unwrap();
    engine::fixture(&original, true).unwrap();
    let inserted = directory.path.join("inserted.img");
    engine::mutate(
        &original,
        &inserted,
        0,
        None,
        engine::Mutation::Put {
            source: &payload,
            destination: "/Transfer/Café.txt",
        },
    )
    .unwrap();
    engine::mutate(
        &inserted,
        &output,
        0,
        None,
        engine::Mutation::Rename {
            source: "/Transfer/Café.txt",
            destination: "/Transfer/Résumé.txt",
        },
    )
    .unwrap();
    let map = engine::windows_names(&output, "/Transfer", 0, None).unwrap();
    assert_eq!(
        map.resolve("Résumé.txt").unwrap().hfs_component,
        "Re\u{301}sume\u{301}.txt"
    );
    let invalid = directory.path.join("invalid.img");
    assert!(
        engine::mutate(
            &original,
            &invalid,
            0,
            None,
            engine::Mutation::Mkdir(&format!("/{}", "é".repeat(128)))
        )
        .is_err()
    );
    assert!(!invalid.exists());
}

#[test]
fn lossy_raw_utf16_names_cannot_export_the_wrong_file() {
    let directory = TestDir::new();
    let image = directory.path.join("invalid-name.img");
    let mut disk = base(false);
    let mut fs = HfsPlus::open(&mut disk).unwrap();
    let invalid = create(&mut fs, &mut disk, "/Café/nameX", b"invalid wire identity");
    create(
        &mut fs,
        &mut disk,
        "/Café/name\u{FFFD}",
        b"different valid file",
    );
    fs.flush(&mut disk).unwrap();
    let key = wire_key(&disk, invalid);
    let mut bytes = disk.into_bytes();
    // A lone surrogate displays as U+FFFD through a lossy String interface.
    // The real U+FFFD file must never be exported under the other identity.
    bytes[key + 8 + 8..key + 8 + 10].copy_from_slice(&0xD800u16.to_be_bytes());
    std::fs::write(&image, &bytes).unwrap();
    let output = directory.path.join("wrong.bin");
    assert!(engine::windows_names(&image, "/Café", 0, None).is_err());
    assert!(engine::extract_windows(&image, "/Café", "name\u{FFFD}", &output, 0, None).is_err());
    assert!(!output.exists());
    assert!(std::fs::read(&image).unwrap() == bytes);
}
