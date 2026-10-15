using System.Diagnostics;
using System.Security.Principal;
using System.Text;

namespace HfsBridge.Manager;

internal static class DriveTransferSession
{
    internal static int RunPhysical(string binary, string encoded, string source, string destination)
    {
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            if (!new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator))
                throw new IOException("Administrator approval is required for this transfer.");
            var plan = DriveWritePlan.Decode(encoded);
            var native = new ProcessStartInfo(Path.GetFullPath(binary)) { UseShellExecute = false, CreateNoWindow = true,
                RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true,
                StandardOutputEncoding = Encoding.UTF8, StandardErrorEncoding = Encoding.UTF8,
                WorkingDirectory = Path.GetDirectoryName(Path.GetFullPath(binary))! };
            foreach (string arg in new[] { "transfer-disk", plan.Disk.Number.ToString(System.Globalization.CultureInfo.InvariantCulture),
                "--partition", plan.Partition.Number.ToString(System.Globalization.CultureInfo.InvariantCulture), "--identity", plan.Partition.Token,
                source, destination }) native.ArgumentList.Add(arg);
            using var prepared = new PreparedTransfer(native);
            // Native READY holds the actual regular source handle and has
            // rejected source volumes on this disk before any offline change.
            prepared.Prepare();
            var operations = new TransferOperations(new DriveWriteSession.PhysicalWriteOperations(Path.GetFullPath(binary)), prepared);
            int result = DriveWriteSession.Run(plan, operations);
            if (result == 0) DriveWriteSession.Forward(Console.Out, "TRANSFER finished 0 0");
            return result;
        }
        catch (Exception error) { DriveWriteSession.Forward(Console.Error, error.Message); return 1; }
    }

    private sealed class TransferOperations(IWriteSessionOperations ownership, PreparedTransfer transfer) : IWriteSessionOperations
    {
        public WriteSnapshot Inspect(DriveWritePlan plan) => ownership.Inspect(plan);
        public void SetOffline(DriveWritePlan plan, bool offline) => ownership.SetOffline(plan, offline);
        public void Report(string message) => ownership.Report(message);
        public bool RunHost(string[] arguments) => transfer.Copy(arguments[0] switch {
            "mount-disk" => "disk", "mount-volume" => "volume", _ => throw new IOException("Unsupported transfer ownership route.") });
    }

    internal sealed class PreparedTransfer(ProcessStartInfo start) : IDisposable
    {
        private Process? process;
        private Task? errors;
        private bool startedWriting;
        private readonly TransferProtocol protocol = new();
        internal void Prepare()
        {
            process = Process.Start(start) ?? throw new IOException("The transfer engine did not start.");
            errors = Task.Run(async () => { string? line; while ((line = await process.StandardError.ReadLineAsync()) != null)
                DriveWriteSession.Forward(Console.Error, line); });
            var ready = process.StandardOutput.ReadLineAsync();
            if (!ready.Wait(TimeSpan.FromSeconds(30))) throw new IOException("Preparing the source file timed out.");
            var message = TransferProgress.Parse(ready.GetAwaiter().GetResult() ?? "");
            if (message?.Phase != "ready") throw new IOException("The source could not be prepared. Choose a regular local Windows file.");
            protocol.Accept(message);
            DriveWriteSession.Forward(Console.Out, message.Line);
        }
        internal bool Copy(string route)
        {
            if (process == null || startedWriting || route is not ("disk" or "volume")) throw new IOException("Transfer is not prepared.");
            // Take responsibility before sending GO. After this point neither
            // the GUI nor a disconnected pipe may terminate this writer.
            startedWriting = true;
            process.StandardInput.WriteLine("GO " + route); process.StandardInput.Flush();
            bool invalid = false;
            string? line;
            while ((line = process.StandardOutput.ReadLine()) != null)
            {
                var progress = TransferProgress.Parse(line);
                if (line.StartsWith("TRANSFER ", StringComparison.Ordinal) && progress == null) invalid = true;
                if (progress != null) { try { protocol.Accept(progress); } catch (IOException) { invalid = true; } }
                DriveWriteSession.Forward(Console.Out, line);
            }
            process.WaitForExit(); errors!.GetAwaiter().GetResult();
            return process.ExitCode == 0 && !invalid && protocol.Closed && protocol.Hash != null;
        }
        public void Dispose()
        {
            if (process == null) return;
            try { process.StandardInput.Close(); } catch (IOException) { }
            if (!startedWriting && !process.WaitForExit(5000)) process.Kill(); // source reader only, never sent GO
            // If GO was delivered before a pipe failure, continue draining so
            // progress output cannot block the writer's clean completion.
            Task<string>? remaining = startedWriting && !process.HasExited ? process.StandardOutput.ReadToEndAsync() : null;
            process.WaitForExit(); errors?.GetAwaiter().GetResult();
            remaining?.GetAwaiter().GetResult(); process.Dispose();
        }
    }
}

internal sealed class TransferProtocol
{
    private int order = -1;
    private ulong? total;
    private ulong bytes;
    internal string? Hash { get; private set; }
    internal bool Closed { get; private set; }
    internal bool Finished { get; private set; }
    internal void Accept(TransferProgress item)
    {
        int next = Array.IndexOf(new[] { "ready", "copy", "committing", "verify", "verified", "closed", "finished" }, item.Phase);
        if (next < order || next < 0 || next == 0 && order >= 0 ||
            next == 2 && (order != 1 || total != bytes) ||
            next == 3 && order is not (2 or 3) ||
            next == 4 && (order != 3 || bytes != total) ||
            next == 5 && (order != 4 || Hash == null) ||
            next == 6 && (order != 5 || !Closed))
            throw new IOException("Transfer progress arrived out of order.");
        if (next < 5)
        {
            if (total != null && total != item.Total || next == order && item.Bytes < bytes)
                throw new IOException("Transfer progress changed its size or moved backwards.");
            total = item.Total; bytes = item.Bytes;
        }
        order = next;
        if (next == 4) Hash = item.Hash;
        if (next == 5) Closed = true;
        if (next == 6) Finished = true;
    }
}

internal sealed record TransferProgress(string Phase, ulong Bytes, ulong Total, string? Hash, string Line)
{
    internal static TransferProgress? Parse(string line)
    {
        if (line.Length > 256) return null;
        var parts = line.Split(' ');
        if (parts.Length is not (4 or 5) || parts[0] != "TRANSFER" ||
            !new[] { "ready", "copy", "committing", "verify", "verified", "closed", "finished" }.Contains(parts[1]) ||
            !ulong.TryParse(parts[2], System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out ulong bytes) ||
            !ulong.TryParse(parts[3], System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out ulong total) || bytes > total)
            return null;
        string? hash = parts.Length == 5 ? parts[4] : null;
        if (parts[1] == "verified" ? hash is not { Length: 64 } || !hash.All(Uri.IsHexDigit) || bytes != total : hash != null) return null;
        if (parts[1] is "closed" or "finished" && (bytes != 0 || total != 0)) return null;
        return new(parts[1], bytes, total, hash, line);
    }
}
