using System.Security.Cryptography;

namespace HfsBridge.Manager;
internal sealed partial class DriveWindow
{
    private void ValidateFastTransfer(string directory, DriveInventory fixture, DiskInspection inspection, string image, List<string> checks)
    {
        void Require(bool value, string message) { if (!value) throw new IOException(message); }
        void Reject(Action action) { bool rejected = false; try { action(); } catch { rejected = true; } Require(rejected, "Unsafe transfer progress accepted."); }
        string digest = new('A', 64);
        foreach (string invalid in new[] { "TRANSFER copy -1 10", "TRANSFER copy 11 10", "TRANSFER copy 18446744073709551616 10",
            "TRANSFER verified 10 10 missing", "TRANSFER verified 5 10 " + digest, "TRANSFER closed 1 1", "TRANSFER finished 0 0 extra" })
            Require(TransferProgress.Parse(invalid) == null, "Invalid transfer protocol accepted.");
        var state = new TransferProtocol();
        foreach (string line in new[] { "TRANSFER ready 0 10", "TRANSFER copy 10 10", "TRANSFER committing 10 10",
            "TRANSFER verify 10 10", "TRANSFER verified 10 10 " + digest, "TRANSFER closed 0 0", "TRANSFER finished 0 0" })
            state.Accept(TransferProgress.Parse(line)!);
        Require(state.Closed && state.Finished && state.Hash == digest, "Valid transfer receipt failed.");
        Reject(() => new TransferProtocol().Accept(TransferProgress.Parse("TRANSFER closed 0 0")!));
        Reject(() => new TransferProtocol().Accept(TransferProgress.Parse("TRANSFER verified 10 10 " + digest)!));
        var early = new TransferProtocol(); early.Accept(TransferProgress.Parse("TRANSFER copy 5 10")!);
        Reject(() => early.Accept(TransferProgress.Parse("TRANSFER committing 10 10")!));
        Reject(() => early.Accept(TransferProgress.Parse("TRANSFER copy 4 10")!));
        Reject(() => early.Accept(TransferProgress.Parse("TRANSFER copy 5 11")!));
        checks.Add("fast-transfer progress rejects malformed values, overflow, missing hash, premature completion, regressing bytes and changed totals; completion requires verified copy and clean close");

        string source = Path.Combine(directory, "fast-transfer-source.bin"), output = Path.Combine(directory, "fast-transfer.img");
        byte[] payload = Enumerable.Range(0, 1048599).Select(i => (byte)(i * 31)).ToArray(); File.WriteAllBytes(source, payload);
        string expected = Convert.ToHexString(SHA256.HashData(payload));
        string imageHash; using (var input = File.OpenRead(image)) imageHash = Convert.ToHexString(SHA256.HashData(input));
        var plan = new DriveWritePlan(fixture.Disks[0], inspection.Partitions[0], "R:");
        int picks = 0;
        using var window = new DriveTransferWindow(binary, plan,chooseOnOpen:true) { StartPosition = FormStartPosition.Manual,
            Location = new Point(-32000, -32000), Opacity = 0, ShowInTaskbar = false,
            ValidationSourcePicker = () => { picks++; return source; },
            ValidationStart = (input, destination) => NativeStart("transfer-image", image, input, destination, "--output", output) };
        window.Show(); Application.DoEvents();
        Require(picks == 1 && window.Destination.Length > 0,"Opening fast transfer did not offer a file or preserve the chosen source.");
        checks.Add("opening the transfer dialog invokes file selection once before a verified copy; no copy starts automatically");
        var running = window.RunTransfer();
        window.Close();
        using var canceled = new DriveTransferWindow(binary,plan,chooseOnOpen:true) {
            StartPosition = FormStartPosition.Manual, Location = new Point(-32000,-32000), Opacity = 0, ShowInTaskbar = false,
            ValidationSourcePicker = () => null,
            ValidationStart = (_,_) => throw new IOException("Canceled picker must not start a transfer")
        };
        canceled.Show(); Application.DoEvents(); canceled.RunTransfer().GetAwaiter().GetResult();
        Require(canceled.Destination.Length == 0 && !canceled.Completed,"Canceling file selection started a copy.");
        canceled.Close(); checks.Add("canceling automatic file selection starts no writer and leaves the transfer uncommitted");
        Require(!window.IsDisposed && window.Visible, "A running transfer window closed.");
        DateTime deadline = DateTime.UtcNow.AddSeconds(30);
        while (!running.IsCompleted && DateTime.UtcNow < deadline) { Application.DoEvents(); Thread.Sleep(20); }
        Require(running.IsCompleted, "Image-only transfer controller timed out."); running.GetAwaiter().GetResult(); Application.DoEvents();
        Require(window.Completed && window.VerifiedHash == expected, "Image-only GUI transfer failed verification.");
        string returned = Path.Combine(directory, "fast-transfer-returned.bin");
        using (var reader = Start(NativeStart("extract", output, window.Destination, returned)))
        {
            var stdout = reader.StandardOutput.ReadToEndAsync(); var stderr = reader.StandardError.ReadToEndAsync();
            Require(reader.WaitForExit(30000) && reader.ExitCode == 0, "Image transfer extraction failed.");
            _ = stdout.GetAwaiter().GetResult(); _ = stderr.GetAwaiter().GetResult();
        }
        Require(File.ReadAllBytes(returned).SequenceEqual(payload), "GUI transfer saved bytes differ.");
        using (var input = File.OpenRead(image)) Require(Convert.ToHexString(SHA256.HashData(input)) == imageHash, "Transfer changed source image.");
        checks.Add("fast-transfer desktop workflow streams a new 1 MiB+23-byte image file, verifies its complete saved SHA256, refuses closing while active and retains the original image");
        window.Close();
    }
}
