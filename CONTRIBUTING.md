# Contributing

Start with a small issue or pull request describing the behavior, expected result
and a disposable-image reproduction. Keep drive identity, read-only defaults,
safe close, failed-write handling and startup permissions intact.

Use only generated disposable images for automated write tests. Never make
physical-device writes, administrator setup, formatting, repairs, deletion or
restart part of an unattended test. Tests must distinguish image results from
real-device acceptance. Do not commit generated outputs or private diagnostics.

Contributions to original HFS Bridge code are submitted under GPL-3.0-only.
Keep all third-party copyright/license notices when modifying vendored code.
