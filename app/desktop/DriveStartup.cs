namespace HfsBridge.Manager;

internal sealed partial class DriveWindow
{
    private StartupProfile? startupProfile;
    private bool startupAttempted, startupOpening;
    private bool openExplorerAfterMount = true;
    private Func<DiskItem, DiskPartition, string>? validationStartupIdentityReader;

    private bool AdvanceStartupInventory()
    {
        if (startupProfile == null || inventory == null) return false;
        if (startupRecoveryRequired)
        {
            status.Text = "Automatic opening paused · check the drive after its I/O error";
            return false;
        }
        var matches = inventory.Disks.Where(startupProfile.Matches).ToArray();
        if (startupDiagnostics) StartupLog.Write($"Saved drive matches={matches.Length}; previous attempt={startupAttempted}.");
        if (matches.Length == 0) { startupAttempted = false; return false; }
        if (startupAttempted) return false;
        if (matches.Length != 1) throw new IOException("Several drives match the saved startup identity. Open the drive manually.");
        startupAttempted = true; startupOpening = true;
        disks.SelectedItem = matches[0]; allowChanges.Checked = startupProfile.Writable;
        OpenDrive(); return true;
    }

    private void CheckStartupPartition(DiskItem disk, DiskPartition part)
    {
        if (!startupOpening || startupProfile == null) return;
        if (!startupProfile.Matches(disk) || !startupProfile.Matches(part))
            throw new IOException("The saved drive or partition changed. Automatic mounting stopped.");
        string id = validationStartupIdentityReader == null ? StartupProfile.ReadVolumeId(disk, part) : validationStartupIdentityReader(disk, part);
        if (!id.Equals(startupProfile.VolumeId, StringComparison.OrdinalIgnoreCase))
            throw new IOException("The HFS volume identity changed. Open it manually before configuring startup again.");
        if (!letters.Items.Contains(startupProfile.Letter))
            throw new IOException("The saved drive letter is occupied. Automatic mounting stopped.");
        letters.SelectedItem = startupProfile.Letter;
    }

    private void OpenStartupSettings()
    {
        if (host != null || readTask != null || discoveryPending) { status.Text = "Close the drive before changing startup settings"; return; }
        using var settings = new StartupSettingsWindow(disks.SelectedItem as DiskItem, partitions.SelectedItem as DiskPartition,
            letters.SelectedItem as string ?? "Z:", allowChanges.Checked);
        settings.ShowDialog(this);
    }
}
