namespace HfsBridge.Manager;

internal sealed partial class DriveWindow
{
    private bool hostIoFailed, startupRecoveryRequired;
    private long failedHostCloseDue;

    private static bool IsTerminalSectorFailure(string line) =>
        (line.StartsWith("SECTOR_DIAGNOSTIC read:", StringComparison.Ordinal) ||
         line.StartsWith("SECTOR_DIAGNOSTIC read before write:", StringComparison.Ordinal) ||
         line.StartsWith("SECTOR_DIAGNOSTIC write:", StringComparison.Ordinal) ||
         line.StartsWith("SECTOR_DIAGNOSTIC sync:", StringComparison.Ordinal)) &&
        line.Contains("error=", StringComparison.Ordinal);

    private void ObserveHostFailure(string line)
    {
        if (hostIoFailed || !IsTerminalSectorFailure(line)) return;
        // SectorSlice has already failed closed. Ask the owning host to exit
        // normally; never kill it, retry its I/O, or reopen a replacement disk.
        hostIoFailed = logFailed = startupRecoveryRequired = true;
        transferAfterClose = null;
        CancelReconnect();
        showFiles.Enabled = false;
        UpdateControls();
        Append("Drive I/O failed. Closing the stale mount; automatic opening is paused until the drive is checked.");
        failedHostCloseDue = 0;
        PollFailedHostClose();
    }

    private void PollFailedHostClose()
    {
        if (!hostIoFailed || host is not { HasExited: false } || Environment.TickCount64 < failedHostCloseDue) return;
        failedHostCloseDue = Environment.TickCount64 + 1000;
        RequestUnmount();
        status.Text = "Drive connection or I/O failed · closing the stale mount…";
    }
}
