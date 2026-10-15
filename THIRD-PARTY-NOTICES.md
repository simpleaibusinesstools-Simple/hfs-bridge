# Third-party notices and corresponding source

Original HFS Bridge code is distributed under GPL-3.0-only. Existing upstream
notices remain in force for their respective files; the root license does not
replace those notices. Modified fstool files retain the upstream MIT license.
See `vendor/FSTOOL-PATCHES.md` for local modifications.

| Component | Version | License and source |
| --- | --- | --- |
| fstool fork | 0.4.35 | MIT; modified complete source in `vendor/fstool`, upstream https://github.com/KarpelesLab/fstool |
| winfsp-rs | 0.13.1+winfsp-2.1 | GPLv3; https://github.com/SnowflakePowered/winfsp-rs |
| winfsp-sys | 0.12.1+winfsp-2.1 | GPLv3; same upstream |
| WinFsp user-mode runtime | 2.1 | GPLv3 with upstream FLOSS exception; https://github.com/winfsp/winfsp/tree/v2.1 |
| Microsoft Fluent System Icons | preserved assets | MIT; `design/native-redesign/icons/LICENSE.txt` and provenance.json |
| Unicode data | 3.2 | `research/evidence/unicode-3.2/LICENSE.txt` |

The exact locked Rust dependency inventory, source URLs, copyright notices and
license texts are in `third-party/RUST-DEPENDENCIES.json` and
`third-party/RUST-DEPENDENCIES.txt`. Additional compression notices are retained
under `third-party/compression`. Microsoft .NET and Windows SDK/build tools are
prerequisites and are not included in the Windows application ZIP.

WinFsp - Windows File System Proxy, Copyright (C) Bill Zissimopoulos.
https://github.com/winfsp/winfsp

## Corresponding source for the release binaries

The release's `HFS-Bridge-0.1.0-alpha.1-complete-source.zip` contains this source
tree, the modified fstool fork, all locked Cargo dependencies (including the
WinFsp Rust bindings and their SDK/import libraries), and WinFsp v2.1 source
with its build scripts. It is provided alongside the Windows ZIP at no charge.

The unmodified WinFsp source archive was retrieved from
https://github.com/winfsp/winfsp/archive/refs/tags/v2.1.zip
and has SHA-256
`7B51F3C64FC5596EAB315C8812F8B13E96D6830DEEF66E30DF2019DAFD3E0DD4`.
The WinFsp runtime DLL in the Windows download is the unmodified pinned DLL;
the driver is installed separately from the official signed upstream installer.

The source ZIP includes `.cargo/config.toml` configured to use its local
`dependency-source/crates`. See BUILDING.md. Sources can also be fetched at their
locked crate versions and the upstream URLs above. No private development
images, physical disk profiles, SSH material or user diagnostics are included.
