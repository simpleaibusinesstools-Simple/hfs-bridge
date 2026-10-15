# Reference compression fixtures

These three byte streams were produced by Apple's LZFSE reference encoder at
revision `e634ca58b4821d9f3d560cdc6df5dec02ffc93fd`, compiled locally from its
eight enumerated C sources. The source licence is retained verbatim in
`APPLE-LZFSE-LICENSE.txt`.

`apple-1024-constant.lzfse` encodes 1,024 bytes of 0x41.
`apple-1024-constant.lzvn` is the raw LZVN unit from that reference output's
single `bvxn` block, with its 12-byte frame header and terminal LZFSE marker
removed. It retains the LZVN end-of-stream bytes.
`apple-65536-ramp.lzfse` encodes 65,536 bytes of the repeating i % 251 pattern.
The exact input, encoded output and decoded hashes are retained under
`artifacts/milestone-19/reference-product-reader` with the reference executable
SHA-256 `974909C0E0B56D0414AB559FB108B8120355D360C1891EED304F38BCECA0A159`.

These fixtures provide an independent encoder reference. They were not generated
by our Rust reader, and they are distinct from the genuine macOS ditto images.
The raw LZVN fixture is also read successfully by native macOS in a type-7
compressed HFS file.

The two `.zbm` fixtures were generated independently by macOS 15.7.4 (24G517)
using `/usr/lib/libcompression.dylib` and algorithm `COMPRESSION_LZBITMAP`
(`0x702`). `apple-1024-constant.zbm` encodes 1,024 bytes of 0x41;
`apple-65536-ramp.zbm` encodes 65,536 bytes of repeating `i % 251`.
Their source/output hashes, native roundtrip results and generator are preserved
under `artifacts/milestone-49/apple-corpus` and `mac-lzbitmap-corpus.py`.
These are generated test data, not copied Apple implementation code.
The decoder's separate Corellium MIT licence and reference provenance are in
`third-party/compression/lzbitmap-LICENSE.txt` and `sources.json`.
