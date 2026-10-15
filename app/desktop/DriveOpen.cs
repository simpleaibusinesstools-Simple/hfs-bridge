using System.Diagnostics;
using System.Globalization;
using System.Security.Principal;

namespace HfsBridge.Manager;

internal sealed partial class DriveWindow
{
    private readonly Button openDrive = new ThemeButton(), showFiles = new ThemeButton();
    private readonly CheckBox allowChanges = new();
    private readonly Label openDescription = new();
    private Control? advancedOptions;
    private DriveOpenRequest? requestedOpen;
    private DiskItem? openTarget;
    private bool openingReadOnly, openingForWrite, readOnlyHost, managedWriteHost;
    private string? mountedLetter;
    private readonly Button fastTransfer = new ThemeButton();
    private bool openingTransfer, transferActive;
    private DriveOpenRequest? transferAfterClose;
    private long transferCloseRetryDue;
    private Func<bool>? validationTransferConsent;
    private Action<DriveWritePlan>? validationTransferDialog;

    private void CancelOpen() { openingReadOnly = openingForWrite = openingTransfer = startupOpening = false; openTarget = null; requestedOpen = null; transferAfterClose = null; }

    private void OpenTransfer()
    {
        if (closing || transferActive || readTask != null || discoveryPending || reconnectAttempt ||
            inventory is not { ParagonActive: false } || disks.SelectedItem is not DiskItem { External: true, IsReadOnly: false } disk)
        { status.Text = "Select an available writable Mac drive for fast transfer"; return; }
        if (host != null && (!mountAcknowledged || hostIoFailed || unmountRequested || transferAfterClose != null)) return;
        bool needsPermission = host != null ? readOnlyHost : !allowChanges.Checked;
        if (needsPermission)
        {
            bool approved = validationTransferConsent?.Invoke() ?? MessageBox.Show(this,
                $"Fast transfer copies a Windows file onto {disk.FriendlyName}.\n\nAllow writing for this transfer? Any open HFS Bridge drive will close safely first.",
                "Allow fast transfer",MessageBoxButtons.YesNo,MessageBoxIcon.Question,MessageBoxDefaultButton.Button2) == DialogResult.Yes;
            if (!approved) return;
        }
        if (host != null)
        {
            CancelReconnect();
            transferAfterClose = new DriveOpenRequest(disk.Number,disk.SerialNumber,disk.Size,Writable:true,Transfer:true);
            transferCloseRetryDue = Environment.TickCount64 + 1000;
            RequestUnmount();
            if (!unmountRequested) transferAfterClose = null;
            UpdateControls();
            if (transferAfterClose != null) status.Text = "Closing safely for fast transfer · close files and Explorer windows using this drive…";
            return;
        }
        allowChanges.Checked = true;
        openingTransfer = true; OpenDrive();
    }
    private void PollTransferClose()
    {
        if (transferAfterClose == null || host is not { HasExited: false } || hostIoFailed) return;
        if (tray?.ExitPending == true) { transferAfterClose = null; return; }
        if (Environment.TickCount64 < transferCloseRetryDue) return;
        transferCloseRetryDue = Environment.TickCount64 + 1000;
        RequestUnmount(); // A normal close request; never terminate an owned writer.
    }

    private void ResumeTransferAfterClose(bool success)
    {
        var request = transferAfterClose; transferAfterClose = null;
        if (request == null) return;
        if (!success || closing || hostIoFailed || tray?.ExitPending == true || discoveryPending)
        { Append("Fast transfer canceled: the drive did not close safely or the session changed."); return; }
        // Discard the old partition/check and require a fresh, exact-identity inventory.
        requestedOpen = request; RefreshInventory();
        if (readTask != null) status.Text = "Drive closed safely · checking it again for fast transfer…";
        else CancelOpen();
    }

    private void OpenDrive()
    {
        try
        {
            if (closing || host != null || readTask != null || discoveryPending || inventory == null ||
                disks.SelectedItem is not DiskItem disk || !disk.External || inventory.ParagonActive)
                throw new IOException("Select an available external drive first.");
            CancelReconnect();
            using var identity = WindowsIdentity.GetCurrent();
            if (validationPartitionReader == null && !new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator))
            {
                var start = new ProcessStartInfo(Environment.ProcessPath!) { UseShellExecute = true, Verb = "runas", WorkingDirectory = AppContext.BaseDirectory };
                foreach (string arg in new[] { "--binary", binary, "--drives", allowChanges.Checked ? "--open-drive-writable" : "--open-drive",
                    disk.Number.ToString(CultureInfo.InvariantCulture), disk.SerialNumber, disk.Size.ToString(CultureInfo.InvariantCulture) })
                    start.ArgumentList.Add(arg);
                if (openingTransfer) start.ArgumentList[3] = "--transfer-drive";
                using var elevated = Process.Start(start);
                if (elevated == null) throw new IOException("Administrator approval was not completed.");
                Close(); return;
            }
            openTarget = disk; openingReadOnly = true; openingForWrite = allowChanges.Checked;
            if (snapshot == null) InspectSelected();
            else if (partitions.SelectedItem is DiskPartition { HfsCandidate: true }) CheckSelectedVolume();
            else throw new IOException("Choose an HFS partition under Advanced, then click Open drive.");
            if (readTask == null) throw new IOException("The read-only check could not start.");
        }
        catch (Exception error) { CancelOpen(); Append(error.Message); UpdateControls(); status.Text = error.Message; }
    }

    private void AdvanceOpen(ReadOperation operation)
    {
        try
        {
            if (operation == ReadOperation.Inventory && requestedOpen is DriveOpenRequest request)
            {
                requestedOpen = null;
                var matches = inventory!.Disks.Where(request.Matches).ToArray();
                if (matches.Length != 1) throw new IOException("The selected drive changed. Select it again before opening.");
                disks.SelectedItem = matches[0]; allowChanges.Checked = request.Writable; openingTransfer = request.Transfer; OpenDrive(); return;
            }
            if (operation == ReadOperation.Inventory)
            {
                if (AdvanceStartupInventory()) return;
                if (!openingReadOnly) { AdvanceReconnect(operation); return; }
            }
            if (!openingReadOnly) return;
            if (inventory == null || snapshot == null || disks.SelectedItem is not DiskItem disk || disk != openTarget)
                throw new IOException("The selected drive changed during its checks. Select it again.");
            if (operation == ReadOperation.Partitions)
            {
                var candidates = snapshot.Partitions.Where(part => part.HfsCandidate &&
                    (!startupOpening || startupProfile == null || startupProfile.Matches(part))).ToArray();
                if (candidates.Length != 1)
                {
                    if (advancedOptions != null) advancedOptions.Visible = true;
                    throw new IOException(candidates.Length == 0 ? "No HFS+ or HFSX partition was found on this drive." :
                        "This drive contains several Mac partitions. Choose one under Advanced, then click Open drive.");
                }
                partitions.SelectedItem = candidates[0]; CheckSelectedVolume();
                if (readTask == null) throw new IOException("The filesystem check could not start.");
            }
            else if (operation == ReadOperation.Volume)
            {
                if (VolumeRefusal() is string refusal) throw new IOException(refusal);
                if (partitions.SelectedItem is not DiskPartition part) throw new IOException("No partition selected.");
                RefreshLetters();
                if (letters.SelectedItem is not string letter) throw new IOException("No drive letter is available.");
                CheckStartupPartition(disk, part);
                letter = (string)letters.SelectedItem!;
                ProcessStartInfo start;
                if (openingForWrite)
                {
                    var plan = new DriveWritePlan(disk, part, letter);
                    _ = plan.Validate(new(inventory, disk, snapshot, volume!), true);
                    if (openingTransfer)
                    {
                        CancelOpen(); CancelReconnect(); transferActive = true; timer.Stop(); UpdateControls();
                        status.Text = "Fast transfer · drive reserved";
                        try
                        {
                            if (validationTransferDialog != null) validationTransferDialog(plan);
                            else { using var transfer = new DriveTransferWindow(binary, plan,chooseOnOpen:true); transfer.ShowDialog(this); }
                        }
                        finally { transferActive = false; timer.Start(); ClearSelection(); RefreshInventory(); }
                        return;
                    }
                    // Validation substitutes only a disposable-image native
                    // host; production always uses the owning supervisor.
                    start = validationHost == null ? DriveWriteSession.StartInfo(binary, plan)
                        : validationHost(["write-session", plan.Encode()]);
                }
                else
                {
                    string[] args = snapshot.ReadOnlyMountArguments(inventory, disk, part, letter);
                    start = validationHost == null ? NativeStart(args) : validationHost(args);
                }
                host = Start(start);
                readOnlyHost = !openingForWrite; managedWriteHost = openingForWrite;
                mountedLetter = letter; logFailed = hostIoFailed = false;
                mountAcknowledged = unmountRequested = flushAcknowledged = false;
                hostOut = host.StandardOutput.ReadLineAsync(); hostErr = host.StandardError.ReadLineAsync();
                openExplorerAfterMount = !startupOpening; startupOpening = false;
                CancelOpen(); UpdateControls(); status.Text = readOnlyHost ? "Opening drive · your files remain protected…" : "Opening drive for copying and changes…";
            }
        }
        catch (Exception error) { startupOpening = false; CancelOpen(); Append(error.Message); UpdateControls(); status.Text = error.Message; }
    }

    private void ShowMountedFiles()
    {
        if (host == null || !mountAcknowledged || mountedLetter == null) return;
        try
        {
            var start = new ProcessStartInfo(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "explorer.exe"))
            { UseShellExecute = true };
            start.ArgumentList.Add(mountedLetter + "\\");
            using var explorer = Process.Start(start);
        }
        catch (Exception error) { Append($"Open File Explorer → This PC → {mountedLetter}. {error.Message}"); }
    }
}
