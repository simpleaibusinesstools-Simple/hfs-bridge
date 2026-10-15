using System.Diagnostics;
using System.Security.Principal;
using System.Text;
using System.Text.Json;

namespace HfsBridge.Manager;

internal sealed record DriveWritePlan(DiskItem Disk, DiskPartition Partition, string Letter)
{
    internal string Encode() => Convert.ToBase64String(JsonSerializer.SerializeToUtf8Bytes(this));
    internal static DriveWritePlan Decode(string value)
    {
        if (value.Length > 16384) throw new IOException("Invalid write-session request.");
        var plan = JsonSerializer.Deserialize<DriveWritePlan>(Convert.FromBase64String(value), DriveInventory.Json)
            ?? throw new IOException("Missing write-session request.");
        if (plan.Disk == null || plan.Partition == null || !plan.Disk.External ||
            string.IsNullOrWhiteSpace(plan.Disk.SerialNumber) || plan.Disk.SerialNumber.Length > 256 ||
            plan.Letter is not { Length: 2 } || plan.Letter[0] is < 'D' or > 'Z' || plan.Letter[1] != ':' ||
            plan.Partition.Token is not { Length: 64 } || !plan.Partition.Token.All(Uri.IsHexDigit))
            throw new IOException("Invalid write-session identity.");
        return plan;
    }

    internal DiskPartition Validate(WriteSnapshot current, bool allowOfflineTransition)
    {
        var disk = current.Disk; var inspection = current.Inspection;
        if (disk.Number != Disk.Number || disk.Size != Disk.Size || disk.SerialNumber != Disk.SerialNumber ||
            disk.LogicalSectorSize != Disk.LogicalSectorSize || disk.PhysicalSectorSize != Disk.PhysicalSectorSize ||
            disk.IsOffline != inspection.Offline || disk.IsReadOnly != inspection.ReadOnly)
            throw new IOException("Drive identity or state changed. Select it again.");
        var part = inspection.Partitions.SingleOrDefault(p => p.Number == Partition.Number);
        if (part == null || part.Offset != Partition.Offset || part.Length != Partition.Length || part.Token != Partition.Token)
            throw new IOException("The selected partition changed. Inspect the drive again.");
        if (!current.Volume.EngineAccess || current.Volume.Refusal is string)
            throw new IOException(current.Volume.Refusal ?? "The filesystem check did not pass.");
        // Only the planning check considers a future offline state. The native
        // host arguments below require a fresh, actually offline inspection.
        if (allowOfflineTransition && !inspection.VolumeLockSupported && !disk.IsOffline)
        {
            var future = disk with { IsOffline = true };
            _ = (inspection with { Offline = true }).MountArguments(
                current.Inventory with { Disks = [future] }, future, part, true, Letter);
        }
        else _ = inspection.MountArguments(current.Inventory, disk, part, true, Letter);
        return part;
    }
}

internal sealed record WriteSnapshot(DriveInventory Inventory, DiskItem Disk, DiskInspection Inspection, DiskVolumeInspection Volume);
internal interface IWriteSessionOperations
{
    WriteSnapshot Inspect(DriveWritePlan plan);
    void SetOffline(DriveWritePlan plan, bool offline);
    bool RunHost(string[] arguments);
    void Report(string message);
}

internal static class DriveWriteSession
{
    // This process owns the disk state and writer together. It is never a
    // cancellable read helper, and never force-stops a filesystem writer.
    internal static int Run(DriveWritePlan plan, IWriteSessionOperations operations)
    {
        bool restoreOnline = false, hostStarted = false, clean = false;
        Exception? failure = null;
        try
        {
            var before = operations.Inspect(plan);
            _ = plan.Validate(before, true);
            if (!before.Inspection.VolumeLockSupported && !before.Disk.IsOffline)
            {
                // A state-changing command may succeed before reporting an
                // error, so take responsibility before issuing it.
                restoreOnline = true;
                operations.SetOffline(plan, true);
            }
            var owned = operations.Inspect(plan);
            var part = plan.Validate(owned, false);
            var arguments = owned.Inspection.MountArguments(owned.Inventory, owned.Disk, part, true, plan.Letter);
            hostStarted = true;
            clean = operations.RunHost(arguments);
            if (!clean) throw new IOException("The drive did not close cleanly. Keep the logs and check it before another write.");
        }
        catch (Exception error) { failure = error; }
        finally
        {
            if (restoreOnline && (!hostStarted || clean))
            {
                try { operations.SetOffline(plan, false); restoreOnline = false; }
                catch (Exception error) { failure = new IOException("Could not restore the drive's online state. " + error.Message, failure); }
            }
            if (restoreOnline) operations.Report("Drive remains offline after an incomplete operation. Do not retry writing until it has been checked.");
        }
        if (failure != null) { operations.Report(failure.Message); return 1; }
        return 0;
    }

    internal static int RunPhysical(string binary, string encodedPlan)
    {
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            if (!new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator))
                throw new IOException("Administrator approval is required to open this drive for changes.");
            var plan = DriveWritePlan.Decode(encodedPlan);
            return Run(plan, new PhysicalWriteOperations(Path.GetFullPath(binary)));
        }
        catch (Exception error) { Forward(Console.Error, error.Message); return 1; }
    }

    internal static ProcessStartInfo StartInfo(string binary, DriveWritePlan plan)
    {
        var start = new ProcessStartInfo(Environment.ProcessPath!)
        { UseShellExecute = false, CreateNoWindow = true, RedirectStandardInput = true, RedirectStandardOutput = true,
            RedirectStandardError = true, StandardOutputEncoding = Encoding.UTF8, StandardErrorEncoding = Encoding.UTF8 };
        foreach (string value in new[] { "--binary", binary, "--write-session", plan.Encode() }) start.ArgumentList.Add(value);
        return start;
    }

    internal static void Forward(TextWriter destination, string message)
    {
        // A closed GUI pipe must never interrupt disk ownership or clean close.
        try { destination.WriteLine(message); destination.Flush(); }
        catch (IOException) { }
    }

    internal sealed class PhysicalWriteOperations(string binary) : IWriteSessionOperations
    {
        public void Report(string message) => Forward(Console.Error, message);
        private static ProcessStartInfo Powershell(string command)
        {
            var start = DriveInventory.StartInfo(); start.ArgumentList.Clear();
            foreach (string arg in new[] { "-NoProfile", "-NonInteractive", "-EncodedCommand",
                Convert.ToBase64String(Encoding.Unicode.GetBytes(command)) }) start.ArgumentList.Add(arg);
            return start;
        }
        private ProcessStartInfo Native(params string[] arguments)
        {
            var start = new ProcessStartInfo(binary) { UseShellExecute = false, CreateNoWindow = true,
                RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true,
                StandardOutputEncoding = Encoding.UTF8, StandardErrorEncoding = Encoding.UTF8,
                WorkingDirectory = Path.GetDirectoryName(binary)! };
            foreach (string arg in arguments) start.ArgumentList.Add(arg);
            return start;
        }
        private static string ReadReport(ProcessStartInfo start, bool readOnly)
        {
            using var process = Process.Start(start) ?? throw new IOException("The drive helper did not start.");
            var output = process.StandardOutput.ReadToEndAsync(); var error = process.StandardError.ReadToEndAsync();
            if (readOnly && !process.WaitForExit(30000))
            {
                if (!process.HasExited) process.Kill();
                process.WaitForExit();
                throw new IOException("Read-only drive inspection timed out.");
            }
            // A state-changing helper must finish; it cannot be abandoned or
            // treated as a reader that is safe to terminate on a timeout.
            process.WaitForExit();
            string text = output.GetAwaiter().GetResult(), errors = error.GetAwaiter().GetResult();
            if (process.ExitCode != 0) throw new IOException(string.IsNullOrWhiteSpace(errors) ? "Drive operation failed." : errors.Trim());
            return text;
        }
        public WriteSnapshot Inspect(DriveWritePlan plan)
        {
            var inventory = DriveInventory.Parse(ReadReport(DriveInventory.StartInfo(), true));
            var disk = inventory.Disks.SingleOrDefault(d => d.Number == plan.Disk.Number && d.External)
                ?? throw new IOException("The selected external drive is no longer available.");
            var inspection = DiskInspection.Parse(ReadReport(Native("disk-inspect", disk.Number.ToString(), "--json"), true), disk);
            var part = inspection.Partitions.SingleOrDefault(p => p.Number == plan.Partition.Number)
                ?? throw new IOException("The selected partition is no longer available.");
            var volume = DiskVolumeInspection.Parse(ReadReport(Native(inspection.VolumeArguments(inventory, disk, part)), true), part);
            return new(inventory, disk, inspection, volume);
        }
        public void SetOffline(DriveWritePlan plan, bool offline)
        {
            // The only interpolated request data is base64 JSON; serials and
            // names never become executable PowerShell source.
            string command = """
                $ErrorActionPreference='Stop'
                $p=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('PLAN'))|ConvertFrom-Json
                $matches=@(Get-Disk|Where-Object {$_.Number -eq $p.Disk.Number -and $_.Size -eq $p.Disk.Size -and $_.SerialNumber.Trim() -ceq $p.Disk.SerialNumber -and $_.BusType -eq 'USB' -and -not $_.IsBoot -and -not $_.IsSystem})
                if($matches.Count -ne 1){throw 'Selected drive identity changed before changing its state'}
                $d=$matches[0]
                if($d.LogicalSectorSize -ne 512 -or $d.PhysicalSectorSize -ne 512 -or $d.IsReadOnly){throw 'Unsupported or protected drive'}
                $desired=OFFLINE
                if($desired -and -not $d.IsOffline){
                  $mounted=@(Get-Partition -DiskNumber $d.Number -ErrorAction Stop|Where-Object {@($_.AccessPaths|Where-Object {$_ -match '^[A-Za-z]:\\'}).Count -gt 0})
                  if($mounted.Count -ne 0){throw 'This disk also has a mounted Windows volume. Close its files and use the advanced workflow.'}
                }
                if($d.IsOffline -ne $desired){$d|Set-Disk -IsOffline $desired -ErrorAction Stop}
                $now=Get-Disk -Number $d.Number
                if($now.SerialNumber.Trim() -cne $p.Disk.SerialNumber -or $now.Size -ne $p.Disk.Size -or $now.IsOffline -ne $desired){throw 'Drive state change could not be confirmed'}
                """;
            _ = ReadReport(Powershell(command.Replace("PLAN", plan.Encode(), StringComparison.Ordinal)
                .Replace("OFFLINE", offline ? "$true" : "$false", StringComparison.Ordinal)), false);
        }
        public bool RunHost(string[] arguments) => ForwardHost(Native(arguments), Console.In, Console.Out, Console.Error);
    }

    internal static bool ForwardHost(ProcessStartInfo start, TextReader requests, TextWriter output, TextWriter errorOutput)
    {
            using var host = Process.Start(start) ?? throw new IOException("The writable host did not start.");
            bool mounted = false, flushed = false;
            var inputGate = new object();
            void CloseRequest()
            {
                lock (inputGate)
                {
                    if (!host.HasExited) { host.StandardInput.WriteLine(); host.StandardInput.Flush(); }
                }
            }
            var errors = Task.Run(async () => { string? line; while ((line = await host.StandardError.ReadLineAsync()) != null) Forward(errorOutput, line); });
            _ = Task.Run(async () =>
            {
                try
                {
                    while (!host.HasExited)
                    {
                        string? line;
                        try { line = await requests.ReadLineAsync(); }
                        catch (IOException) { line = null; }
                        CloseRequest();
                        // If the GUI disappears, continue clean-close requests
                        // until open handles are released. Never kill the writer.
                        if (line == null) await Task.Delay(1000);
                    }
                }
                catch (IOException) { }
                catch (InvalidOperationException) { }
            });
            try
            {
                string? text;
                while ((text = host.StandardOutput.ReadLine()) != null)
                {
                    mounted |= text.StartsWith("Mounted ", StringComparison.Ordinal);
                    flushed |= text.StartsWith("Unmounted; ", StringComparison.Ordinal) && text.EndsWith("flushed successfully.", StringComparison.Ordinal);
                    Forward(output, text);
                }
            }
            finally
            {
                // Keep ownership even if reading the host protocol failed.
                // Request a normal close until it exits; never kill it.
                while (!host.HasExited)
                {
                    try { CloseRequest(); }
                    catch (IOException) { }
                    catch (InvalidOperationException) when (host.HasExited) { }
                    host.WaitForExit(1000);
                }
            }
            host.WaitForExit(); errors.GetAwaiter().GetResult();
            return host.ExitCode == 0 && mounted && flushed;
    }
}
