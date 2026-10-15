using System.Diagnostics;
using System.Security.Principal;
using System.Text;

namespace HfsBridge.Manager;

internal sealed partial class DriveWindow : Form
{
    private readonly string binary;
    private readonly ComboBox disks = new ThemeComboBox(), partitions = new ThemeComboBox(), letters = new ThemeComboBox();
    private readonly Button refresh = new ThemeButton(), inspect = new ThemeButton(), checkVolume = new ThemeButton(), mount = new ThemeButton(), unmount = new ThemeButton();
    private readonly CheckBox consent = new(), reconnect = new();
    private readonly Label details = new(), status = new();
    private readonly TextBox log = new();
    private readonly System.Windows.Forms.Timer timer = new() { Interval = 100 };
    private readonly DesktopTray? tray;
    private readonly bool startupDiagnostics;
    private DriveInventory? inventory;
    private DiskInspection? snapshot;
    private DiskItem? inspectingDisk;
    private DiskPartition? inspectingPartition;
    private DiskVolumeInspection? volume;
    private string? volumeError;
    private Process? readTask, host;
    private Task<string>? readOut, readErr;
    private Task<string?>? hostOut, hostErr;
    private DateTime deadline;
    private enum ReadOperation { Inventory, Partitions, Volume }
    private ReadOperation readingOperation;
    private bool logFailed;
    private bool mountAcknowledged, unmountRequested, flushAcknowledged;
    // Only the validation workflow supplies a regular-image host constructor.
    // Production uses NativeStart with the validated direct-disk arguments.
    private Func<string[], ProcessStartInfo>? validationHost;
    private Func<string[], ProcessStartInfo>? validationVolumeReader;
    private Func<ProcessStartInfo>? validationInventoryReader;
    private Func<string[], ProcessStartInfo>? validationPartitionReader;

    internal DriveWindow(string executable, bool preview = false, DriveOpenRequest? openRequest = null,
        StartupProfile? automaticProfile = null, bool startInTray = false)
    {
        startupDiagnostics = automaticProfile != null;
        binary = Path.GetFullPath(executable);
        if (!File.Exists(binary)) throw new FileNotFoundException("The native HFS Bridge executable is missing.", binary);
        BuildLayout();
        if (!preview) tray = new DesktopTray(this, () => host != null || transferActive, ShowMountedFiles, RequestUnmount, () => status.Text);
        startupProfile = automaticProfile;
        requestedOpen = openRequest;
        openDrive.Click += (_, _) => OpenDrive();
        showFiles.Click += (_, _) => ShowMountedFiles();
        fastTransfer.Click += (_, _) => OpenTransfer();
        refresh.Click += (_, _) => RefreshInventory(); inspect.Click += (_, _) => InspectSelected();
        checkVolume.Click += (_, _) => CheckSelectedVolume();
        reconnect.CheckedChanged += (_, _) => { if (!reconnect.Checked) CancelReconnect(); UpdateControls(); };
        mount.Click += (_, _) => StartMount(); unmount.Click += (_, _) => RequestUnmount();
        disks.SelectedIndexChanged += (_, _) => ClearSelection(); partitions.SelectedIndexChanged += (_, _) => { ClearVolume(); UpdateControls(); }; consent.CheckedChanged += (_, _) => UpdateControls();
        timer.Tick += (_, _) => Poll(); if (!preview) Shown += (_, _) => RefreshInventory();
        RefreshLetters(); UpdateControls(); if (!preview) timer.Start();
        if (startInTray && !preview)
        {
            ShowInTaskbar = false; Opacity = 0;
            Shown += (_, _) => { tray?.Hide(); Opacity = 1; ShowInTaskbar = true; };
        }
    }
    private void Append(string value) { if (startupDiagnostics) StartupLog.Write(value.TrimEnd()); log.AppendText(value.TrimEnd() + Environment.NewLine); if (log.TextLength > 200000) log.Text = log.Text[^100000..]; }
    private void RefreshLetters()
    {
        letters.Items.Clear(); var used = new HashSet<string>(Directory.GetLogicalDrives().Select(p => p[..2]), StringComparer.OrdinalIgnoreCase);
        for (char c = 'Z'; c >= 'D'; c--) if (!used.Contains(c + ":")) letters.Items.Add(c + ":");
        if (letters.Items.Count > 0) letters.SelectedIndex = 0;
    }
    private void ClearSelection()
    {
        if (!openingReadOnly) allowChanges.Checked = false;
        snapshot = null; ClearVolume(); partitions.Items.Clear();
        details.Text = disks.SelectedItem is DiskItem d ? $"{d.FriendlyName}\n{d.LogicalSectorSize}/{d.PhysicalSectorSize}-byte sectors · {(d.IsOffline ? "Offline" : "Online")} · {(d.IsReadOnly ? "Write-protected" : "Writable flags")}" : "No USB drives are available.";
        UpdateControls();
    }
    private void ClearVolume() { volume = null; volumeError = null; consent.Checked = false; }
    private string? VolumeRefusal() => volumeError ?? (volume == null ? "Check the selected filesystem before mounting." : volume.Refusal);
    private void UpdateControls()
    {
        bool busy = host != null || readTask != null || discoveryPending || reconnectAttempt || transferActive;
        refresh.Enabled = disks.Enabled = !busy; inspect.Enabled = !busy && disks.SelectedItem is DiskItem;
        partitions.Enabled = letters.Enabled = !busy && snapshot != null;
        checkVolume.Enabled = !busy && snapshot != null && inventory != null && disks.SelectedItem is DiskItem && partitions.SelectedItem is DiskPartition { HfsCandidate: true };
        consent.Enabled = !busy && volume is { EngineAccess: true };
        // An armed choice can always be turned off, including during a check.
        reconnect.Enabled = reconnect.Checked || (!busy && volume is { EngineAccess: true });
        unmount.Enabled = host != null;
        openDrive.Enabled = !busy && inventory is { ParagonActive: false } && disks.SelectedItem is DiskItem { External: true } && letters.SelectedItem != null;
        allowChanges.Enabled = !busy && disks.SelectedItem is DiskItem { External: true, IsReadOnly: false };
        fastTransfer.Enabled = inventory is { ParagonActive: false } && disks.SelectedItem is DiskItem { External: true, IsReadOnly: false } &&
            (!busy || host != null && mountAcknowledged && !hostIoFailed && !unmountRequested && transferAfterClose == null);
        bool writesSelected = host != null ? !readOnlyHost : openingReadOnly ? openingForWrite : allowChanges.Checked;
        openDescription.Text = writesSelected ? "Copy files both ways. Close the drive before disconnecting." : "Browse and copy to Windows. Your originals stay protected.";
        showFiles.Enabled = host != null && mountAcknowledged && !hostIoFailed;
        string? refusal = snapshot != null && inventory != null && disks.SelectedItem is DiskItem d
            ? partitions.SelectedItem is DiskPartition ? VolumeRefusal() ?? snapshot.Refusal(inventory, d, partitions.SelectedItem as DiskPartition, consent.Checked) : "Select an HFS partition."
            : "Select a drive and inspect its partitions.";
        mount.Enabled = !busy && refusal == null && letters.SelectedItem != null;
        if (!busy) status.Text = volumeError ?? (disks.SelectedItem is not DiskItem ? "Connect a Mac drive to begin" : snapshot == null ? "Ready · click Open drive to browse and copy files" : refusal ?? "Ready to mount the selected partition.");
        RefreshWorkspaceState();
    }
    private static Process Start(ProcessStartInfo start)
    { var process = new Process { StartInfo = start }; try { if (!process.Start()) throw new IOException("The helper did not start."); return process; } catch { process.Dispose(); throw; } }
    private ProcessStartInfo NativeStart(params string[] args)
    {
        var start = new ProcessStartInfo(binary) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true, StandardOutputEncoding = Encoding.UTF8, StandardErrorEncoding = Encoding.UTF8, WorkingDirectory = Path.GetDirectoryName(binary)! };
        foreach (string arg in args) start.ArgumentList.Add(arg); return start;
    }
    private void BeginRead(ProcessStartInfo start, ReadOperation operation)
    {
        readGeneration = deviceGeneration;
        readTask = Start(start); readingOperation = operation; readOut = readTask.StandardOutput.ReadToEndAsync(); readErr = readTask.StandardError.ReadToEndAsync(); deadline = DateTime.UtcNow.AddSeconds(25);
        UpdateControls(); status.Text = operation == ReadOperation.Inventory ? "Reading connected drives…" : operation == ReadOperation.Volume ? "Checking filesystem headers and journal (read-only)…" : "Inspecting the selected drive…";
        if (startupDiagnostics) StartupLog.Write(status.Text);
    }
    private void RefreshInventory()
    {
        try { if (closing || host != null || readTask != null) return; discoveryPending = false; ClearSelection(); inventory = null; disks.Items.Clear(); RefreshLetters(); BeginRead(validationInventoryReader == null ? DriveInventory.StartInfo() : validationInventoryReader(), ReadOperation.Inventory); }
        catch (Exception error) { Append(error.Message); UpdateControls(); status.Text = "Drive inventory failed"; }
    }
    private void InspectSelected()
    {
        try
        {
            if (closing || discoveryPending || host != null || readTask != null || disks.SelectedItem is not DiskItem d || !d.External) return;
            if (reconnectTarget != null && d != reconnectTarget.Disk) CancelReconnect("Reconnect mounting cleared for the new drive selection.");
            using var identity = WindowsIdentity.GetCurrent();
            if (validationPartitionReader == null && !new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator))
            {
                var start = new ProcessStartInfo(Environment.ProcessPath!) { UseShellExecute = true, Verb = "runas", WorkingDirectory = AppContext.BaseDirectory };
                foreach (string arg in new[] { "--binary", binary, "--drives" }) start.ArgumentList.Add(arg);
                using var elevated = Process.Start(start); if (elevated == null) throw new IOException("Administrator window did not start.");
                Close(); return;
            }
            ClearSelection(); inspectingDisk = d;
            string[] args = ["disk-inspect", d.Number.ToString(System.Globalization.CultureInfo.InvariantCulture), "--json"];
            BeginRead(validationPartitionReader == null ? NativeStart(args) : validationPartitionReader(args), ReadOperation.Partitions);
        }
        catch (Exception error) { Append(error.Message); UpdateControls(); status.Text = "Inspection could not start"; }
    }
    private void CheckSelectedVolume()
    {
        try
        {
            if (closing || discoveryPending || host != null || readTask != null || snapshot == null || inventory == null || disks.SelectedItem is not DiskItem d || partitions.SelectedItem is not DiskPartition p) return;
            ClearVolume();
            var args = snapshot.VolumeArguments(inventory, d, p);
            inspectingDisk = d; inspectingPartition = p;
            BeginRead(validationVolumeReader == null ? NativeStart(args) : validationVolumeReader(args), ReadOperation.Volume);
        }
        catch (Exception error) { volumeError = "Filesystem check could not start. Inspect this drive again."; Append(error.Message); UpdateControls(); }
    }
    private void StartMount()
    {
        try
        {
            if (closing || discoveryPending || host != null || readTask != null || snapshot == null || inventory == null || disks.SelectedItem is not DiskItem d || partitions.SelectedItem is not DiskPartition p || letters.SelectedItem is not string letter) throw new IOException("Inspect and select a drive first.");
            if (VolumeRefusal() is string healthRefusal) throw new IOException(healthRefusal);
            var args = snapshot.MountArguments(inventory, d, p, consent.Checked, letter);
            readOnlyHost = false; mountedLetter = letter;
            host = Start(validationHost == null ? NativeStart(args) : validationHost(args)); logFailed = hostIoFailed = false; managedWriteHost = false;
            pendingReconnectTarget = reconnect.Checked ? new ReconnectTarget(d, p, letter) : null;
            mountAcknowledged = unmountRequested = flushAcknowledged = false;
            hostOut = host.StandardOutput.ReadLineAsync(); hostErr = host.StandardError.ReadLineAsync();
            UpdateControls(); status.Text = "Starting direct-drive mount…"; Append($"Selected {d}; partition {p.Number}. The backend rechecks identity before writing.");
        }
        catch (Exception error) { CancelReconnect(); Append(error.Message); status.Text = "Mount could not start"; }
    }
    private void RequestUnmount()
    { try { if (host is { HasExited: false }) { host.StandardInput.WriteLine(); host.StandardInput.Flush(); unmountRequested = true; status.Text = readOnlyHost ? "Closing drive · waiting for open files to close…" : "Waiting for open files to close and the drive to flush…"; } } catch (Exception error) { Append(error.Message); } }
    private void ReadHostLine(ref Task<string?>? task, StreamReader reader)
    {
        if (task == null || !task.IsCompleted) return;
        try { string? line = task.GetAwaiter().GetResult(); task = null; if (line == null) return; Append(line); ObserveHostFailure(line); if (!hostIoFailed && line.StartsWith("Mounted ", StringComparison.Ordinal)) { mountAcknowledged = true; if (!readOnlyHost && !managedWriteHost) ArmReconnect(); UpdateControls(); status.Text = readOnlyHost ? $"Mounted at {mountedLetter} · copy files to Windows · source protected" : "Mounted · copy files through File Explorer"; showFiles.Enabled = true; if ((readOnlyHost || managedWriteHost) && validationHost == null && openExplorerAfterMount) ShowMountedFiles(); } if (!hostIoFailed && line.StartsWith("Unmounted; ", StringComparison.Ordinal) && line.EndsWith(readOnlyHost ? "closed without changes." : "flushed successfully.", StringComparison.Ordinal)) flushAcknowledged = true; if (line.Contains("Open files remain", StringComparison.Ordinal)) status.Text = transferAfterClose != null ? "Close open files and Explorer windows · fast transfer will continue automatically" : "Close open files, then click Close safely again"; task = reader.ReadLineAsync(); }
        catch (Exception error) { logFailed = true; task = null; Append(error.Message); }
    }
    private void Poll()
    {
        tray?.Update();
        if (closing) return;
        if (readTask != null)
        {
            if (!readTask.HasExited && DateTime.UtcNow >= deadline) { StopReader(readTask); Append("Read-only inspection timed out."); }
            if (readTask.HasExited && readOut!.IsCompleted && readErr!.IsCompleted)
            {
                bool readSucceeded = false;
                var completedOperation = readingOperation;
                try
                {
                    if (readGeneration != deviceGeneration) throw new IOException("Drive connections changed during inspection; refreshing the drive list.");
                    string text = readOut.GetAwaiter().GetResult(), error = readErr.GetAwaiter().GetResult();
                    if (readTask.ExitCode != 0) throw new IOException(string.IsNullOrWhiteSpace(error) ? "Read-only helper failed." : error);
                    if (readingOperation == ReadOperation.Inventory)
                    {
                        inventory = DriveInventory.Parse(text);
                        foreach (var d in inventory.Disks.Where(d => d.External)) disks.Items.Add(d);
                        if (disks.Items.Count > 0) disks.SelectedIndex = 0;
                        if (inventory.ParagonActive)
                            Append(inventory.ParagonRemovalPending ? "Paragon removal is pending. Restart Windows before direct-drive testing." : "Paragon is active. Direct-drive mounting remains unavailable.");
                    }
                    else if (readingOperation == ReadOperation.Partitions)
                    {
                        snapshot = DiskInspection.Parse(text, inspectingDisk!);
                        if (snapshot.PhysicalSector == 0) details.Text = $"{inspectingDisk!.FriendlyName}\n{snapshot.LogicalSector}-byte logical sectors · physical size unreported";
                        foreach (var p in snapshot.Partitions.Where(p => p.HfsCandidate)) partitions.Items.Add(p);
                        if (partitions.Items.Count > 0) partitions.SelectedIndex = 0;
                        Append("Read-only partition inspection complete.");
                    }
                    else
                    {
                        if (snapshot == null || disks.SelectedItem is not DiskItem selectedDisk || selectedDisk != inspectingDisk ||
                            partitions.SelectedItem is not DiskPartition selectedPart || selectedPart != inspectingPartition || !snapshot.Partitions.Contains(selectedPart))
                            throw new IOException("Drive selection changed during the filesystem check. Inspect again.");
                        volume = DiskVolumeInspection.Parse(text, selectedPart); volumeError = null;
                        Append(volume.Refusal ?? "Basic HFS header/journal checks passed. This is not a complete filesystem consistency check.");
                    }
                    readSucceeded = true;
                }
                catch (Exception error)
                {
                    if (readingOperation == ReadOperation.Volume) { ClearVolume(); volumeError = "Filesystem check failed. Inspect or check this drive again."; }
                    else { snapshot = null; ClearVolume(); partitions.Items.Clear(); }
                    Append(error.Message);
                    CancelOpen();
                    if (reconnectAttempt) CancelReconnect("Reconnect check failed; mount manually after inspecting the drive.");
                }
                readTask.Dispose(); readTask = null; UpdateControls();
                if (readSucceeded)
                {
                    if (openingReadOnly || requestedOpen != null || completedOperation == ReadOperation.Inventory && startupProfile != null)
                        AdvanceOpen(completedOperation);
                    else AdvanceReconnect(completedOperation);
                }
            }
        }
        if (host == null) { PollDiscovery(); return; }
        ReadHostLine(ref hostOut, host.StandardOutput); ReadHostLine(ref hostErr, host.StandardError);
        PollTransferClose();
        PollFailedHostClose();
        if (host.HasExited && hostOut == null && hostErr == null)
        {
            bool success = host.ExitCode == 0 && !logFailed && mountAcknowledged && unmountRequested && flushAcknowledged; host.Dispose(); host = null; ClearSelection(); RefreshLetters();
            pendingReconnectTarget = null;
            if (!success) CancelReconnect("Host failed; automatic reconnect mounting is off. Check the filesystem before trying again.");
            showFiles.Enabled = false; mountedLetter = null; UpdateControls();
            status.Text = success ? readOnlyHost ? "Drive closed · source unchanged" : managedWriteHost ? "Drive closed · changes saved" : "Unmounted and flushed · inspect again before another mount" : hostIoFailed ? "Host failed · stale mount closed; check the drive before reopening" : "Host failed · keep logs and check the disk before retrying";
            ResumeTransferAfterClose(success);
        }
    }
    protected override void OnFormClosing(FormClosingEventArgs e)
    {
        if (transferActive) { e.Cancel = true; status.Text = "Wait for the transfer to finish and close the drive safely"; }
        else if (host != null)
        {
            e.Cancel = true;
            status.Text = e.CloseReason == CloseReason.UserClosing && tray?.CanHide == true
                ? "Drive stays open in the system tray" : "Closing drive safely · close files using this drive";
            tray?.RetainOnClose(e.CloseReason);
        }
        else if (readTask != null) { StopReader(readTask); readTask.Dispose(); readTask = null; }
        base.OnFormClosing(e);
        if (!e.Cancel) { closing = true; discoveryPending = false; CancelOpen(); CancelReconnect(); timer.Stop(); }
    }
    protected override void Dispose(bool disposing) { if (disposing) { tray?.Dispose(); timer.Dispose(); } base.Dispose(disposing); }
    private static void StopReader(Process reader)
    {
        // Only read-only inventory/inspection helpers enter this method.
        // An exit between HasExited and Kill is harmless; mounted hosts stay owned.
        try { if (!reader.HasExited) reader.Kill(); }
        catch (InvalidOperationException) when (reader.HasExited) { }
        catch (System.ComponentModel.Win32Exception) when (reader.HasExited) { }
    }
}


