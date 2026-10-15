using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;

namespace HfsBridge.Manager;

internal sealed partial class DriveWindow
{
    private void ValidateSimpleOpen(string directory, DriveInventory fixture, DiskInspection inspection,
        string source, Action<Func<bool>> wait, List<string> checks)
    {
        void Require(bool condition, string message) { if (!condition) throw new IOException(message); }
        string Hash(string path) { using var input = File.OpenRead(path); return Convert.ToHexString(SHA256.HashData(input)); }
        string original = Hash(source);
        var oldHost = validationHost; var oldVolume = validationVolumeReader;
        var oldPartitions = validationPartitionReader;
        var disk = fixture.Disks[0] with { IsOffline = false, IsReadOnly = true };
        var list = new DriveInventory([disk], [], false);
        var model = inspection with { Offline = false, ReadOnly = true, RemovableMedia = false, VolumeLockSupported = false };
        string protocol = Path.Combine(directory, "simple-open-partitions.json");
        void Select()
        {
            CancelOpen(); CancelReconnect(); discoveryPending = false;
            inventory = list; disks.Items.Clear(); disks.Items.Add(disk); disks.SelectedIndex = 0;
            ClearSelection(); RefreshLetters();
        }
        int opens = 0;
        try
        {
            File.WriteAllText(protocol, JsonSerializer.Serialize(model));
            validationPartitionReader = args => {
                Require(args.SequenceEqual(new[] { "disk-inspect", disk.Number.ToString(), "--json" }), "Wrong automatic partition arguments.");
                var start = DriveInventory.StartInfo(); start.ArgumentList.Clear();
                foreach (string arg in new[] { "-NoProfile", "-NonInteractive", "-Command", "Get-Content -Raw -LiteralPath '" + protocol.Replace("'", "''", StringComparison.Ordinal) + "'" }) start.ArgumentList.Add(arg);
                return start;
            };
            validationVolumeReader = args => {
                Require(args.SequenceEqual(model.VolumeArguments(list, disk, model.Partitions[0])), "Wrong automatic filesystem arguments.");
                return NativeStart("inspect", source, "--json");
            };
            validationHost = args => {
                Require(args.SequenceEqual(model.ReadOnlyMountArguments(list, disk, model.Partitions[0], args[2])), "Open selected a writable or wrong-device host.");
                opens++; return NativeStart("mount-readonly", source, args[2]);
            };
            Select(); Require(openDrive.Enabled && !mount.Enabled && !consent.Checked, "Simple open requires advanced write readiness.");
            OpenDrive(); wait(() => mountAcknowledged && host != null);
            string letter = mountedLetter ?? throw new IOException("Missing mounted letter.");
            string hello = Path.Combine(letter + "\\", "Transfer", "hello.txt");
            string copied = Path.Combine(directory, "simple-open-copy.txt");
            File.Copy(hello, copied);
            Require(File.ReadAllText(copied) == "HFS Bridge: persistent Windows-to-Mac filesystem development fixture.\n", "Read-only copy differs.");
            int refused = 0;
            foreach (Action write in new Action[] {
                () => File.WriteAllText(Path.Combine(letter + "\\", "new.txt"), "not allowed"),
                () => File.WriteAllText(hello, "not allowed"),
                () => File.Delete(hello),
                () => File.Move(hello, Path.Combine(letter + "\\", "renamed.txt")),
                () => Directory.CreateDirectory(Path.Combine(letter + "\\", "New folder")),
                () => File.SetAttributes(hello, FileAttributes.Hidden)
            }) { try { write(); } catch (IOException) { refused++; } catch (UnauthorizedAccessException) { refused++; } }
            Require(refused == 6 && File.ReadAllText(hello) == File.ReadAllText(copied), "Read-only volume allowed mutation.");
            RequestUnmount(); wait(() => host == null);
            Require(status.Text.StartsWith("Drive closed", StringComparison.Ordinal) && Hash(source) == original && !Directory.Exists(letter + "\\"), "Read-only close changed source or retained letter.");
            checks.Add("one-click automatic inspection/check/read-only mount and copy pass on online/write-protected synthetic selection; six Windows mutations refused, full image hash unchanged, clean close");

            Select(); model = model with { Partitions = [model.Partitions[0], model.Partitions[0] with { Number = 2 }] };
            File.WriteAllText(protocol, JsonSerializer.Serialize(model)); OpenDrive();
            wait(() => readTask == null && !openingReadOnly);
            Require(host == null && opens == 1 && status.Text.Contains("several Mac partitions", StringComparison.Ordinal), "Multiple partitions were silently selected.");
            checks.Add("multiple Mac partitions stop automatic opening and request an explicit choice");
            Select(); requestedOpen = new DriveOpenRequest(disk.Number, "changed", disk.Size);
            AdvanceOpen(ReadOperation.Inventory);
            Require(host == null && readTask == null && opens == 1 && requestedOpen == null, "Elevated launch accepted changed disk identity.");
            checks.Add("administrator handoff refuses a changed disk identity before starting any host");
        }
        finally
        {
            CancelOpen();
            if (host != null) { RequestUnmount(); wait(() => host == null); }
            validationHost = oldHost; validationVolumeReader = oldVolume; validationPartitionReader = oldPartitions;
        }
    }
}
