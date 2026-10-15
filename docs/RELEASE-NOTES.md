# 0.1.0-alpha.1

First public early-access snapshot. This packages the milestone93 GUI and the
unchanged milestone91 accepted native engine, rather than rebuilding the writer.

## Included

Dark desktop design, HFS+/HFSX Explorer access, read-only default, explicit
writable access, tray operation, opt-in startup setup and atomic fast transfer.
Close & transfer now safely closes the mounted host, waits for open handles,
freshly checks the same device, then opens the picker. Copying still requires
an explicit Start transfer action. Cancellation starts no writer.

## Evidence and remaining checks

The exact GUI passes 50 drive workflow checks and 7 image workflow checks,
including held-file close, cancellation, changed-device refusal and picker flow.
Core browsing, copying both ways and earlier clean-close/Mac checks were accepted
on a personal HFS+ external drive. The fast-transfer engine passed real-drive
generated-file trials and large generated-image validation.

The latest GUI's interactive Close & transfer retry, actual next-sign-in startup,
controlled physical reconnect of the corrected build and a complete new Mac
filesystem check after the latest personal-device writes remain pending.
Offscreen GUI previews are not interactive or hardware acceptance.

## Limitations

Windows x64 only; .NET 10 Desktop Runtime and signed WinFsp 2.1 driver required.
The application binaries are unsigned. There is no unattended driver installer
or automatic updater. Startup is opt-in and uses an account-specific protected
copy and elevated sign-in task after explicit administrator approval.

Only supported HFS+/HFSX layouts are accepted. APFS, encrypted volumes,
formatting and filesystem repair are not provided. Some specialized Mac and
Windows filesystem operations remain unsupported. Use safe close before
disconnecting; this is early-access filesystem software, not a recovery product.
