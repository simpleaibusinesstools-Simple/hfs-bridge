# Publication validation

The export retains the accepted native engine and GUI bytes. 313 native-source
files and 34 GUI files match the accepted frozen snapshots. The only source-tool
portability adjustment replaces a developer-specific sharp import path in the
optional icon renderer with the ordinary sharp package import. No drive engine
or GUI behavior was changed for publication.

Fresh exported-source checks: .NET GUI build passes with zero warnings/errors;
all 53 Rust library tests pass. The Windows download passes 50 drive-controller
and 7 image-controller checks, using disposable images. No physical-device
writes, installation or startup changes are part of this publication validation.

The repository and release text allowlists were scanned for credentials,
private keys, actual device serials, the private account SID, private IPs and
developer-specific paths. No matching private text remained. This is a scoped
review, not a claim that a scan can prove all software secure. Binary build
metadata may retain compiler/source path information from the accepted build.

User images/logs/SSH configuration/startup profiles and development cleanup
scripts are excluded. Upstream public test fixtures are retained as source.
The UI screenshot is a generated demo fixture, not a view of personal files.

Remaining interactive and hardware checks are listed in RELEASE-NOTES.md.
