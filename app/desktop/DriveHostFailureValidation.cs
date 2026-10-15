using System.Diagnostics;
using System.Text;
using System.Security.Principal;

namespace HfsBridge.Manager;

internal sealed partial class DriveWindow
{
    private void ValidateHostFailure(string directory, DriveInventory fixture, DiskInspection inspection,
        Action<Func<bool>> wait, List<string> checks)
    {
        void Require(bool value, string message) { if (!value) throw new IOException(message); }
        var oldProfile = startupProfile;
        try
        {
            foreach (string operation in new[] { "read", "read before write", "write", "sync" })
                Require(IsTerminalSectorFailure($"SECTOR_DIAGNOSTIC {operation}: error=removed"), "Fatal sector failure was ignored.");
            foreach (string ordinary in new[] { "Device change: host owned=True", "Mounted image at R:",
                "Read-only inspection complete", "SECTOR_DIAGNOSTIC read: offset=512", "SECTOR_DIAGNOSTIC informational: error=none" })
                Require(!IsTerminalSectorFailure(ordinary), "Ordinary output triggered failed-host shutdown.");
            checks.Add("terminal sector read/write/sync errors are recognized; ordinary device notifications and informational lines cannot stop a host");
            using var identity = WindowsIdentity.GetCurrent();
            var disk = fixture.Disks[0]; var part = inspection.Partitions[0];
            foreach (bool writable in new[] { false, true })
            {
                string acknowledgment = Path.Combine(directory, writable ? "failed-writer-close.txt" : "failed-reader-close.txt");
                string script = "[Console]::Out.WriteLine('Mounted simulated stale host at R:\\');" +
                    "[Console]::Out.Flush();[Console]::Error.WriteLine('SECTOR_DIAGNOSTIC read: offset=16778240 bytes=512 error=Device removed (os error 433)');" +
                    "[Console]::Error.Flush();$null=[Console]::In.ReadLine();[Threading.Thread]::Sleep(250);[IO.File]::WriteAllText('" + acknowledgment.Replace("'", "''") + "','Orderly close received');exit 7";
                var start = DriveInventory.StartInfo(); start.ArgumentList.Clear(); start.RedirectStandardInput = true;
                foreach (string arg in new[] { "-NoProfile", "-NonInteractive", "-EncodedCommand", Convert.ToBase64String(Encoding.Unicode.GetBytes(script)) })
                    start.ArgumentList.Add(arg);
                CancelOpen(); CancelReconnect(); discoveryPending = false;
                host = Start(start); hostIoFailed = logFailed = startupRecoveryRequired = false;
                readOnlyHost = !writable; managedWriteHost = writable; mountedLetter = "R:";
                mountAcknowledged = unmountRequested = flushAcknowledged = false;
                openExplorerAfterMount = false;
                hostOut = host.StandardOutput.ReadLineAsync(); hostErr = host.StandardError.ReadLineAsync();
                wait(() => hostIoFailed);
                UpdateControls();
                Require(!showFiles.Enabled, "Control refresh re-enabled the failed mount.");
                wait(() => host == null);
                Require(hostIoFailed && logFailed && unmountRequested && !flushAcknowledged && startupRecoveryRequired,
                    "Failed host was left running or reported a clean flush.");
                Require(File.ReadAllText(acknowledgment) == "Orderly close received", "Controller did not request orderly host closure.");
                Require(!showFiles.Enabled && status.Text.StartsWith("Host failed", StringComparison.Ordinal), "Stale mount remained presented as usable.");
                inventory = fixture;
                startupProfile = new StartupProfile(1, identity.User!.Value, disk.SerialNumber.Trim(), disk.Size,
                    disk.LogicalSectorSize, disk.PhysicalSectorSize, part.Number, part.Offset, part.Length, "ABCDEF0000000001", "R:", writable);
                startupAttempted = false;
                Require(!AdvanceStartupInventory() && host == null && !startupAttempted,
                    "Startup reopened a failed drive without recovery checks.");
            }
            checks.Add("simulated reader and writer removal errors both request normal stdin closure without a manual click, retain failure reporting and pause automatic reopening");
        }
        finally
        {
            startupProfile = oldProfile; startupRecoveryRequired = hostIoFailed = logFailed = false;
            startupAttempted = startupOpening = false; openExplorerAfterMount = true;
            if (host != null) { RequestUnmount(); wait(() => host == null); }
        }
    }
}
