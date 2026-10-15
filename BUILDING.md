# Building HFS Bridge

## Windows x64 prerequisites

Use PowerShell 7 or newer for scripts/build.ps1.

Use PowerShell 7 or newer for scripts/build.ps1.

- Rust 1.88 or newer, MSVC x64 toolchain.
- Visual Studio C++ Build Tools and Windows SDK. Use an **x64 Native Tools
  PowerShell** so the compiler, linker and SDK include paths are configured.
- LLVM/libclang for bindgen. Set `LIBCLANG_PATH` to the directory containing
  `libclang.dll` if it is not discoverable.
- .NET 10 SDK. Running the GUI also needs the .NET 10 Windows Desktop Runtime.
- Official signed WinFsp 2.1.25156 driver for native mounted tests/use.

## Build

From the repository root:

```powershell
./scripts/build.ps1 -OutputDirectory dist/app
```

The script builds the native engine and GUI from source, copies the pinned
user-mode DLL supplied by winfsp-sys, and writes a package manifest. It does not
install software, create startup tasks, mount drives or access physical disks.
The output folder must not already exist.

The shipped startup installer deliberately pins the accepted native executable
hash. A custom rebuilt native binary can be used for manual opening; enabling
startup for that custom writer requires reviewing and updating the native hash
in StartupInstall.cs and its validation cases. Do not remove the pin check.
The official alpha ZIP retains the accepted engine and GUI bytes.

For the complete-source ZIP, Cargo uses its included dependency-source/crates
through .cargo/config.toml; add `--offline` to Cargo commands when desired.
The Git repository itself uses crates.io with Cargo.lock. Vendored fstool is
always built from the local modified source, not replaced by the upstream crate.

## Tests

```powershell
cargo test --locked --lib
```

This runs in-memory library tests without physical-device access. Integration
tests under tests/ use generated fixtures; ignored diagnostics refer to private
development fixtures and are not release acceptance. Do not run ignored tests
or physical-device commands blindly.

The GUI supports `--validate-workflow <new-output-directory>` with
`--binary <packaged-native-executable>` for disposable-image controller checks.
Drive-controller checks additionally take `--validate-drive-workflow` and the
synthetic `tests/fixtures/desktop-protocol.json` via `--protocol-fixture`.
These native tests require WinFsp and a free test drive letter; they do not
certify real hardware. Retain logs and owned hosts if a test cannot close.

## Artwork

The checked-in PNG assets are the actual GUI resources. Optional icon
regeneration uses Node.js and the `sharp` package:

```powershell
npm install --no-save --package-lock=false sharp
node design/native-redesign/render-icons.cjs
```

Keep upstream icon attribution. Drive/transfer/background artwork and the
SimpleAI Tools logo are included in their preferred available PNG form.
