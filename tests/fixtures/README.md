# Native Mac link fixtures

These are compressed, disposable 64 MiB journaled HFS+ images created by
`scripts/mac-link-fixture.sh` on the user's Mac running macOS 15.7.4. They
contain generated test bytes and link names, with no user files. The metadata
variant adds a 70,019-byte resource fork, a 70,019-byte user attribute, a small
user attribute and FinderInfo to the shared hard-link inode.

`manifest.json` pins the compressed and expanded hashes. Rust tests accept
exactly 64 MiB, verify the expanded SHA-256, and wrap the in-memory image with
a device that refuses and counts every write. The images do not depend on
the engine under test to encode their catalogs or link records.

Native Mac read-only `fsck_hfs -fn` and payload/metadata checks accepted the
Windows-returned copies. Windows tests preserve original source hashes.
The initial native creation reports and independent return reports are kept
under `artifacts/milestone-24`. These fixtures provide format evidence, not
physical-drive, power-loss or full hard-link mutation acceptance.
