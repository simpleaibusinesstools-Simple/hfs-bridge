use hfs_bridge::{
    Result,
    engine::{self, FileEdit, FileFork, Mutation},
    image::Image,
    partitions, volume,
};
use std::path::Path;

const HELP: &str = "HFS Bridge 0.1 — experimental Windows filesystem\n\
disk-inspect DISK_NUMBER [--json] (Windows; read-only identity and partition discovery)\n\
disk-volume DISK_NUMBER --partition NUMBER --identity TOKEN (read-only HFS header/journal JSON)\n\
disk-list DISK_NUMBER --partition NUMBER --identity TOKEN /DIRECTORY (read-only)\n\
disk-hash DISK_NUMBER --partition NUMBER --identity TOKEN /FILE (read-only data-fork SHA256)\n\
disk-extract DISK_NUMBER --partition NUMBER --identity TOKEN /FILE NEW_HOST_FILE (read-only source)\n\
mount-disk DISK_NUMBER DRIVE_LETTER --partition NUMBER --identity TOKEN (native-mount build)\n\
mount-disk-readonly DISK_NUMBER DRIVE_LETTER --partition NUMBER --identity TOKEN (browse/copy; source unchanged)\n\
mount-readonly IMAGE DRIVE_LETTER [--offset BYTES --length BYTES] (source unchanged)\n\
mount-volume DISK_NUMBER DRIVE_LETTER --partition NUMBER --identity TOKEN (locked removable USB; experimental)\n\
recover-journal IMAGE --output NEW_IMAGE [--offset BYTES --length BYTES]\n\
partitions IMAGE [--sector-size 512|4096]\n\
snapshot IMAGE /FILE [ATTRIBUTE ...] [--partition NUMBER | --offset BYTES --length BYTES]\n\
inspect IMAGE [--json] [--offset BYTES] [--length BYTES]\n\
list IMAGE [/DIRECTORY] [--offset BYTES] [--length BYTES]\n\
list-windows IMAGE [/DIRECTORY] [--offset BYTES] [--length BYTES]\n\
extract-windows IMAGE /DIRECTORY WINDOWS_NAME NEW_HOST_FILE [--offset BYTES] [--length BYTES]\n\
extract IMAGE /FILE NEW_HOST_FILE [--offset BYTES] [--length BYTES]\n\
fixture NEW_IMAGE [--journaled]\n\
put IMAGE HOST_FILE /NEW_FILE --output NEW_IMAGE [--offset BYTES] [--length BYTES]\n\
transfer-image IMAGE HOST_FILE /NEW_FOLDER/FILE --output NEW_IMAGE (whole-file copy and verification)\n\
transfer-disk NUMBER --partition NUMBER --identity TOKEN HOST_FILE /NEW_FOLDER/FILE (prepared exclusive transfer)\n\
mkdir IMAGE /NEW_DIRECTORY --output NEW_IMAGE [--offset BYTES] [--length BYTES]\n\
delete IMAGE /ENTRY --output NEW_IMAGE [--offset BYTES] [--length BYTES]\n\
rename IMAGE /SOURCE /DESTINATION --output NEW_IMAGE [--offset BYTES] [--length BYTES]\n\
move IMAGE /SOURCE /DESTINATION --output NEW_IMAGE [--offset BYTES] [--length BYTES]\n\
overwrite IMAGE HOST_FILE /FILE --output NEW_IMAGE [--offset BYTES] [--length BYTES]\n\
patch IMAGE HOST_FILE /FILE --at BYTES --output NEW_IMAGE [--offset BYTES] [--length BYTES]\n\
truncate IMAGE /FILE SIZE --output NEW_IMAGE [--offset BYTES] [--length BYTES]\n\n\
resource-extract IMAGE /FILE NEW_HOST_FILE\n\
resource-overwrite IMAGE HOST_FILE /FILE --output NEW_IMAGE\n\
resource-patch IMAGE HOST_FILE /FILE --at BYTES --output NEW_IMAGE\n\
resource-truncate IMAGE /FILE SIZE --output NEW_IMAGE\n\n\
attribute-set IMAGE HOST_VALUE /ENTRY ATTRIBUTE --output NEW_IMAGE\n\
attribute-remove IMAGE /ENTRY ATTRIBUTE --output NEW_IMAGE\n\
attribute-extract IMAGE /ENTRY ATTRIBUTE NEW_HOST_FILE\n\n\
mount IMAGE DRIVE_LETTER --output NEW_IMAGE [--offset BYTES] [--length BYTES] (native-mount build)\n\n\
Image commands require regular files; their mutations always create a new copy.\n\
mount-disk requires an already-offline USB disk with native 512-byte sectors.\n\
mount-volume locks an online removable USB partition; logical sectors must be 512 bytes and physical sectors either 512 or explicitly unreported. Unknown geometry limits requests to 4 KiB and the adapter cap.\n\
Both routes require a stable serial, matching selection token and clean HFS preflight. Neither changes disk attributes. Full hardware acceptance remains pending.\n\
Image commands accept --partition NUMBER instead of --offset/--length; select an HFS candidate listed by partitions.\n\
GPT sector size defaults to 512; --sector-size 4096 selects a 4K-sector image explicitly.\n\
An output left by a failed command is incomplete and must not be used.";

fn run() -> Result<()> {
    let mut args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.is_empty() || matches!(args[0].as_str(), "--help" | "help" | "-h") {
        println!("{HELP}");
        return Ok(());
    }
    let command = args.remove(0);
    if matches!(
        command.as_str(),
        "disk-inspect"
            | "mount-disk"
            | "mount-disk-readonly"
            | "mount-volume"
            | "disk-volume"
            | "disk-list"
            | "disk-hash"
            | "disk-extract"
            | "transfer-disk"
    ) {
        return disk_command(&command, &args);
    }
    let mut offset = 0;
    let mut length = None;
    let mut output = None;
    let mut journaled = false;
    let mut at = None;
    let mut partition = None;
    let mut sector_size = None;
    let mut explicit_slice = false;
    let mut json = false;
    let mut positional = Vec::new();
    let mut iter = args.into_iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--json" => {
                if json || command != "inspect" {
                    return Err("--json is accepted once for inspect".into());
                }
                json = true;
            }
            "--offset" => {
                explicit_slice = true;
                offset = iter.next().ok_or("missing offset")?.parse::<u64>()?;
            }
            "--length" => {
                explicit_slice = true;
                length = Some(iter.next().ok_or("missing length")?.parse::<u64>()?);
            }
            "--partition" => {
                if partition.is_some() {
                    return Err("duplicate partition selection".into());
                }
                partition = Some(
                    iter.next()
                        .ok_or("missing partition number")?
                        .parse::<u32>()?,
                );
            }
            "--sector-size" => {
                if sector_size.is_some() {
                    return Err("duplicate sector size".into());
                }
                sector_size = Some(iter.next().ok_or("missing sector size")?.parse::<u32>()?);
            }
            "--output" => output = Some(iter.next().ok_or("missing output")?),
            "--journaled" => journaled = true,
            "--at" => {
                at = Some(
                    iter.next()
                        .ok_or("missing patch byte position")?
                        .parse::<u64>()?,
                )
            }
            flag if flag.starts_with('-') => return Err(format!("unknown option: {flag}").into()),
            _ => positional.push(arg),
        }
    }
    if journaled && command != "fixture" {
        return Err("--journaled only applies to fixture".into());
    }
    if at.is_some() && !matches!(command.as_str(), "patch" | "resource-patch") {
        return Err("--at only applies to patch".into());
    }
    if output.is_some()
        && !matches!(
            command.as_str(),
            "put"
                | "transfer-image"
                | "mkdir"
                | "delete"
                | "rename"
                | "move"
                | "overwrite"
                | "patch"
                | "truncate"
                | "resource-overwrite"
                | "resource-patch"
                | "resource-truncate"
                | "attribute-set"
                | "attribute-remove"
                | "mount"
                | "recover-journal"
        )
    {
        return Err("--output only applies to mutation commands".into());
    }
    if command == "fixture" && (offset != 0 || length.is_some()) {
        return Err(
            "fixture creates a complete 32 MiB raw volume; offset/length are not accepted".into(),
        );
    }
    let args = positional.iter().map(String::as_str).collect::<Vec<_>>();
    if (partition.is_some() || command == "partitions") && explicit_slice {
        return Err("partition discovery cannot be combined with --offset/--length".into());
    }
    if (command == "partitions" && partition.is_some())
        || (command == "fixture" && (partition.is_some() || sector_size.is_some()))
        || (sector_size.is_some() && partition.is_none() && command != "partitions")
    {
        return Err("partition/sector-size options do not apply to this command".into());
    }
    let mut discovered = None;
    // Keep the read-only source lock alive for the entire command. Selection and
    // copying cannot race a Windows writer or replacement of the source file.
    let _selected_source = if partition.is_some() || command == "partitions" {
        let source = args.first().ok_or("partition discovery requires IMAGE")?;
        let mut file = hfs_bridge::image::open_source(Path::new(source))?;
        let size = file.metadata()?.len();
        let layout = partitions::discover(&mut file, size, sector_size.unwrap_or(512))?;
        if let Some(number) = partition {
            let choice = layout.select(number, output.is_some())?;
            offset = choice.offset;
            length = Some(choice.length);
        }
        discovered = Some(layout);
        Some(file)
    } else {
        None
    };
    match (command.as_str(), args.as_slice()) {
        ("transfer-image", [image, host, destination]) => {
            let receipt = hfs_bridge::transfer::copy_image(
                Path::new(image),
                Path::new(&output.ok_or("transfer-image requires a NEW output image")?),
                Path::new(host),
                destination,
                offset,
                length,
                transfer_progress,
            )?;
            println!(
                "TRANSFER verified {} {} {}",
                receipt.bytes, receipt.bytes, receipt.sha256
            );
            println!("TRANSFER closed 0 0");
        }
        ("recover-journal", [image]) => {
            let result = hfs_bridge::recovery::recover_copy(
                Path::new(image),
                Path::new(&output.ok_or("recover-journal requires --output NEW_IMAGE")?),
                offset,
                length,
            )?;
            println!(
                "Journal replayed: {} block lists, {} blocks, {} payload bytes; engine access: {}",
                result.replay.block_lists,
                result.replay.blocks,
                result.replay.payload_bytes,
                if result.engine_accessible {
                    "permitted after structural checks"
                } else {
                    "refused until native checking; volume flags preserved"
                }
            );
        }
        ("attribute-set", [image, value, path, name]) => {
            engine::edit_attribute(
                Path::new(image),
                Path::new(&output.ok_or("attribute-set requires --output NEW_IMAGE")?),
                offset,
                length,
                path,
                name,
                Some(Path::new(value)),
            )?;
        }
        ("attribute-remove", [image, path, name]) => {
            engine::edit_attribute(
                Path::new(image),
                Path::new(&output.ok_or("attribute-remove requires --output NEW_IMAGE")?),
                offset,
                length,
                path,
                name,
                None,
            )?;
        }
        ("attribute-extract", [image, path, name, target]) => {
            engine::extract_attribute(
                Path::new(image),
                offset,
                length,
                path,
                name,
                Path::new(target),
            )?;
        }
        ("snapshot", [image, path, attributes @ ..]) => {
            println!(
                "{:#?}",
                engine::snapshot(Path::new(image), path, attributes, offset, length)?
            );
        }
        ("partitions", [_image]) => {
            println!("{:#?}", discovered.ok_or("disk layout unavailable")?);
            println!(
                "HFS candidates still require header/journal preflight; no repair or implicit selection."
            );
        }
        ("mount-readonly", [image, letter]) => {
            #[cfg(all(windows, feature = "native-mount"))]
            hfs_bridge::native::mount_read_only_image(Path::new(image), offset, length, letter)?;
            #[cfg(not(all(windows, feature = "native-mount")))]
            {
                let _ = (image, letter);
                return Err("mount-readonly requires native-mount on Windows".into());
            }
        }
        ("mount", [image, letter]) => {
            let output = output.ok_or("mount requires --output NEW_IMAGE")?;
            #[cfg(all(windows, feature = "native-mount"))]
            hfs_bridge::native::mount_image(
                Path::new(image),
                Path::new(&output),
                offset,
                length,
                letter,
            )?;
            #[cfg(not(all(windows, feature = "native-mount")))]
            {
                let _ = (image, letter, output);
                return Err("mount requires a Windows build with --features native-mount".into());
            }
        }
        ("list-windows", [image]) | ("list-windows", [image, "/"]) => {
            for entry in engine::windows_names(Path::new(image), "/", offset, length)?.entries() {
                println!(
                    "{:08X}\t{:?}\t{:?}",
                    entry.cnid, entry.windows_name, entry.hfs_component
                );
            }
        }
        ("list-windows", [image, directory]) => {
            for entry in
                engine::windows_names(Path::new(image), directory, offset, length)?.entries()
            {
                println!(
                    "{:08X}\t{:?}\t{:?}",
                    entry.cnid, entry.windows_name, entry.hfs_component
                );
            }
        }
        ("extract-windows", [image, directory, name, host]) => println!(
            "Extracted through Windows view; SHA-256 {}",
            engine::extract_windows(
                Path::new(image),
                directory,
                name,
                Path::new(host),
                offset,
                length
            )?
        ),
        ("inspect", [image]) => {
            let inspection =
                volume::inspect(&mut Image::read_only(Path::new(image), offset, length)?)?;
            if json {
                println!("{}", volume::inspection_json(&inspection));
                return Ok(());
            }
            println!("{inspection:#?}");
            match volume::require_engine_access(&inspection) {
                Ok(()) => println!(
                    "Header/journal preflight passed. This is not a complete filesystem consistency check."
                ),
                Err(error) => println!("Engine access refused: {error}"),
            };
        }
        ("fixture", [image]) => {
            engine::fixture(Path::new(image), journaled)?;
            println!("Created fixture; payload verified after reopen: {image}");
        }
        ("list", [image]) => {
            for entry in engine::list(Path::new(image), "/", offset, length)? {
                println!("{:?}\t{}\t{:?}", entry.kind, entry.size, entry.name);
            }
        }
        ("list", [image, path]) => {
            for entry in engine::list(Path::new(image), path, offset, length)? {
                println!("{:?}\t{}\t{:?}", entry.kind, entry.size, entry.name);
            }
        }
        ("extract", [image, path, host]) => println!(
            "Extracted; SHA-256 {}",
            engine::extract(Path::new(image), path, Path::new(host), offset, length)?
        ),
        ("put", [image, host, path]) => {
            let output = output.ok_or("put requires --output NEW_IMAGE")?;
            engine::mutate(
                Path::new(image),
                Path::new(&output),
                offset,
                length,
                Mutation::Put {
                    source: Path::new(host),
                    destination: path,
                },
            )?;
            println!("Copied file into {output}; payload verified after reopen.");
        }
        ("rename" | "move", [image, source, destination]) => {
            let output = output.ok_or("rename/move requires --output NEW_IMAGE")?;
            engine::mutate(
                Path::new(image),
                Path::new(&output),
                offset,
                length,
                Mutation::Rename {
                    source,
                    destination,
                },
            )?;
            println!(
                "Persisted {command} in {output}; identity and metadata verified after reopen."
            );
        }
        ("resource-extract", [image, path, host]) => println!(
            "Extracted resource fork; SHA-256 {}",
            engine::extract_resource(Path::new(image), path, Path::new(host), offset, length)?
        ),
        ("overwrite" | "patch" | "resource-overwrite" | "resource-patch", [image, host, path]) => {
            let output = output.ok_or("file editing requires --output NEW_IMAGE")?;
            let edit = if command.ends_with("overwrite") {
                FileEdit::Overwrite(Path::new(host))
            } else {
                FileEdit::Patch {
                    source: Path::new(host),
                    offset: at.ok_or("patch requires --at BYTES")?,
                }
            };
            engine::edit_fork(
                Path::new(image),
                Path::new(&output),
                offset,
                length,
                path,
                edit,
                if command.starts_with("resource-") {
                    FileFork::Resource
                } else {
                    FileFork::Data
                },
            )?;
            println!(
                "Persisted {command} in {output}; size, SHA256 and metadata verified after reopen."
            );
        }
        ("truncate" | "resource-truncate", [image, path, size]) => {
            let output = output.ok_or("truncate requires --output NEW_IMAGE")?;
            engine::edit_fork(
                Path::new(image),
                Path::new(&output),
                offset,
                length,
                path,
                FileEdit::Truncate(size.parse()?),
                if command.starts_with("resource-") {
                    FileFork::Resource
                } else {
                    FileFork::Data
                },
            )?;
            println!(
                "Persisted truncate in {output}; size, SHA256 and metadata verified after reopen."
            );
        }
        ("mkdir", [image, path]) | ("delete", [image, path]) => {
            let output = output.ok_or("mutation requires --output NEW_IMAGE")?;
            let operation = if command == "mkdir" {
                Mutation::Mkdir(path)
            } else {
                Mutation::Delete(path)
            };
            engine::mutate(
                Path::new(image),
                Path::new(&output),
                offset,
                length,
                operation,
            )?;
            println!("Persisted {command} in {output}; verified after reopen.");
        }
        _ => return Err(format!("invalid command or arguments\n{HELP}").into()),
    }
    Ok(())
}

fn disk_command(command: &str, args: &[String]) -> Result<()> {
    #[cfg(windows)]
    {
        if command == "transfer-disk"
            && args.len() == 7
            && args[1] == "--partition"
            && args[3] == "--identity"
        {
            use std::io::{BufRead, Write};
            let number = args[0].parse::<u32>()?;
            let partition = args[2].parse::<u32>()?;
            if number > 4095
                || !(1..=4095).contains(&partition)
                || args[4].len() != 64
                || !args[4].bytes().all(|b| b.is_ascii_hexdigit())
            {
                return Err("invalid transfer identity".into());
            }
            hfs_bridge::transfer::validate_destination(&args[6])?;
            let (mut source, size, modified) = hfs_bridge::transfer::source(Path::new(&args[5]))?;
            hfs_bridge::disk::source::require_other_disk(&source, number)?;
            transfer_progress("ready", 0, size);
            let mut request = String::new();
            if std::io::stdin().lock().read_line(&mut request)? == 0 {
                return Ok(());
            }
            // The desktop supervisor sends GO only after taking ownership and
            // revalidating identity, partition, geometry and clean HFS headers.
            let mut device: Box<dyn fstool::block::BlockDevice> = match request.trim_end() {
                "GO disk" => Box::new(hfs_bridge::disk::open_partition(
                    number, partition, &args[4],
                )?),
                "GO volume" => Box::new(hfs_bridge::disk::locked_volume::open(
                    number, partition, &args[4],
                )?),
                _ => return Err("transfer was not authorized by its owner".into()),
            };
            let receipt = hfs_bridge::transfer::copy_file(
                &mut *device,
                &mut source,
                size,
                &args[6],
                modified,
                transfer_progress,
            )?;
            drop(device);
            let mut out = std::io::stdout().lock();
            let _ = writeln!(
                out,
                "TRANSFER verified {} {} {}",
                receipt.bytes, receipt.bytes, receipt.sha256
            );
            let _ = writeln!(out, "TRANSFER closed 0 0");
            let _ = out.flush();
            return Ok(());
        }
        if command == "disk-inspect"
            && (args.len() == 1 || (args.len() == 2 && args[1] == "--json"))
        {
            let snapshot = hfs_bridge::disk::inspect_layout(args[0].parse()?)?;
            if args.len() == 2 {
                println!("{}", snapshot.json()?);
                return Ok(());
            }
            println!("{snapshot:#?}");
            for partition in &snapshot.layout.partitions {
                if partition.hfs_candidate {
                    println!(
                        "Partition {} selection token: {}",
                        partition.number,
                        snapshot.token(partition.number)?
                    );
                }
            }
            println!("Read-only snapshot. Revalidated on mount; no disk attributes changed.");
            return Ok(());
        }
        #[cfg(feature = "native-mount")]
        if matches!(
            command,
            "mount-disk" | "mount-volume" | "mount-disk-readonly"
        ) && args.len() == 6
            && args[2] == "--partition"
            && args[4] == "--identity"
        {
            let mount = if command == "mount-disk-readonly" {
                hfs_bridge::native::mount_read_only_disk
            } else if command == "mount-volume" {
                hfs_bridge::native::mount_locked_volume
            } else {
                hfs_bridge::native::mount_disk
            };
            return mount(args[0].parse()?, args[3].parse()?, &args[5], &args[1]);
        }
        let expected = match command {
            "disk-volume" => 5,
            "disk-list" | "disk-hash" => 6,
            "disk-extract" => 7,
            _ => 0,
        };
        if expected != 0
            && args.len() == expected
            && args[1] == "--partition"
            && args[3] == "--identity"
        {
            let mut device = hfs_bridge::disk::open_read_partition(
                args[0].parse()?,
                args[2].parse()?,
                &args[4],
            )?;
            match command {
                "disk-volume" => println!("{}", hfs_bridge::disk::read::inspect(&mut device)?),
                "disk-list" => println!(
                    "{}",
                    hfs_bridge::disk::read::list_json(&mut device, &args[5])?
                ),
                "disk-hash" => println!("{}", hfs_bridge::disk::read::hash(&mut device, &args[5])?),
                _ => println!(
                    "{}",
                    hfs_bridge::disk::read::extract(&mut device, &args[5], Path::new(&args[6]))?
                ),
            }
            return Ok(());
        }
    }
    let _ = (command, args);
    Err(format!("invalid disk command or arguments\n{HELP}").into())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("Failed: {error}");
        std::process::exit(1);
    }
}

fn transfer_progress(phase: &str, completed: u64, total: u64) {
    use std::io::Write;
    // Losing a consumer must never interrupt journal publication or clean close.
    let mut out = std::io::stdout().lock();
    let _ = writeln!(out, "TRANSFER {phase} {completed} {total}");
    let _ = out.flush();
}
