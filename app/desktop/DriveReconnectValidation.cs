using System.Diagnostics;
using System.Text.Json;

namespace HfsBridge.Manager;

internal sealed partial class DriveWindow
{
    private void ValidateReconnect(string directory, DriveInventory fixture, DiskInspection inspection,
        string source, Action<bool> selectFixture, Action<Func<bool>> wait, List<string> checks)
    {
        void Require(bool value, string message) { if (!value) throw new IOException(message); }
        var originalHost = validationHost; var originalVolume = validationVolumeReader; var originalInventory = validationInventoryReader;
        string kit = Path.Combine(directory, "reconnect"); Directory.CreateDirectory(kit);
        string inventoryPath = Path.Combine(kit, "inventory.json"), partitionsPath = Path.Combine(kit, "partitions.json");
        ProcessStartInfo JsonReader(string path)
        {
            var start = DriveInventory.StartInfo(); start.ArgumentList.Clear();
            foreach (string arg in new[] { "-NoLogo", "-NoProfile", "-NonInteractive", "-Command",
                "[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new($false); Get-Content -Raw -LiteralPath '" + path.Replace("'", "''", StringComparison.Ordinal) + "'" }) start.ArgumentList.Add(arg);
            return start;
        }
        int hosts = 0, partitionReads = 0, volumeReads = 0;
        string volumeSource = source;
        void WriteInventory(DriveInventory value) => File.WriteAllText(inventoryPath, JsonSerializer.Serialize(value));
        void RefreshAndWait(DriveInventory value)
        {
            WriteInventory(value); RefreshInventory(); wait(() => readTask == null);
        }
        void Settled() => wait(() => readTask == null && !discoveryPending);
        try
        {
            Require(!reconnect.Checked && reconnectTarget == null, "Reconnect mounting was enabled by default.");
            validationInventoryReader = () => JsonReader(inventoryPath);
            validationPartitionReader = args =>
            {
                Require(args.SequenceEqual(new[] { "disk-inspect", fixture.Disks[0].Number.ToString(), "--json" }), "Reconnect partition arguments differ.");
                partitionReads++; return JsonReader(partitionsPath);
            };
            validationVolumeReader = args =>
            {
                Require(args.SequenceEqual(inspection.VolumeArguments(fixture, fixture.Disks[0], inspection.Partitions[0])), "Reconnect filesystem arguments differ.");
                volumeReads++; return NativeStart("inspect", volumeSource, "--json");
            };
            validationHost = args =>
            {
                Require(args.SequenceEqual(inspection.MountArguments(fixture, fixture.Disks[0], inspection.Partitions[0], true, args[2])), "Reconnect mount arguments differ.");
                hosts++; return NativeStart("mount", source, args[2], "--output", Path.Combine(kit, $"mount-{hosts}.img"));
            };
            File.WriteAllText(partitionsPath, JsonSerializer.Serialize(inspection));
            selectFixture(true); reconnect.Checked = true; StartMount();
            wait(() => mountAcknowledged);
            var target = reconnectTarget ?? throw new IOException("Acknowledged opt-in manual mount did not arm reconnect.");
            string letter = target.Letter;
            Require(hosts == 1 && reconnect.Checked, "Initial opt-in mount differs.");
            RequestUnmount(); wait(() => host == null);
            Require(reconnectTarget == target && !reconnectSawAbsent, "Clean unmount lost the explicit session preference.");
            RefreshAndWait(fixture);
            NotifyDeviceChangeForValidation(); discoveryDue = Environment.TickCount64 - 1; Settled();
            Require(hosts == 1 && host == null && !reconnectSawAbsent, "Refresh or unrelated device change remounted a deliberately unmounted drive.");
            checks.Add("reconnect mounting defaults off, arms only after an acknowledged opt-in mount and does not undo a deliberate Unmount");

            RefreshAndWait(new DriveInventory([], [], false));
            Require(reconnectSawAbsent, "The absent target was not observed.");
            int volumeBefore = volumeReads;
            WriteInventory(fixture); RefreshInventory(); wait(() => host != null && mountAcknowledged);
            Require(hosts == 2 && partitionReads == 1 && volumeReads == volumeBefore + 1 && !reconnectAttempt && reconnectTarget != null,
                "Reconnect skipped a fresh partition or filesystem check.");
            byte[] payload = [0, 11, 27, 91, 255, 73];
            string output = Path.Combine(letter + "\\", "reconnect-copy.bin"); File.WriteAllBytes(output, payload);
            Require(File.ReadAllBytes(output).SequenceEqual(payload), "Automatically mounted image failed copy roundtrip.");
            RequestUnmount(); wait(() => host == null);
            Require(status.Text.StartsWith("Unmounted and flushed", StringComparison.Ordinal), "Reconnect mount did not unmount cleanly.");
            checks.Add("observed disconnect and exact-identity return run fresh partition and filesystem checks before a real disposable-image remount, copy and clean unmount");

            // Reuse only the target armed by the actual manual image mount.
            // Negative transitions must never construct another host.
            void Rearm()
            {
                reconnect.Checked = true; reconnectTarget = target; reconnectAttempt = reconnectSawAbsent = false;
                volumeSource = source; File.WriteAllText(partitionsPath, JsonSerializer.Serialize(inspection));
                RefreshAndWait(new DriveInventory([], [], false)); Require(reconnectSawAbsent, "Rearm absence missing.");
            }
            void Refused() => Require(host == null && hosts == 2 && !reconnect.Checked && reconnectTarget == null && !consent.Checked && !mount.Enabled,
                "Unsafe reconnect started a host or retained confirmation.");
            foreach (var inventoryCase in new[] {
                new DriveInventory([fixture.Disks[0] with { Number = fixture.Disks[0].Number + 1 }], [], false),
                new DriveInventory([fixture.Disks[0], fixture.Disks[0] with { Number = fixture.Disks[0].Number + 1 }], [], false),
                new DriveInventory([fixture.Disks[0] with { IsReadOnly = true }], [], false),
                new DriveInventory(fixture.Disks, [new DriverItem("Hfsplus", "Running")], false) })
            { Rearm(); RefreshAndWait(inventoryCase); Refused(); }
            Rearm();
            File.WriteAllText(partitionsPath, JsonSerializer.Serialize(inspection with { Partitions = [inspection.Partitions[0] with { Token = new string('F', 64) }] }));
            RefreshAndWait(fixture); Refused();
            checks.Add("changed disk number, duplicate serial, write protection, Paragon presence and changed partition token all refuse reconnect mounting");

            Rearm(); var partitionReader = validationPartitionReader;
            validationPartitionReader = _ => NativeStart("unsupported-validation-command");
            RefreshAndWait(fixture); Refused(); validationPartitionReader = partitionReader;
            Rearm(); var filesystemReader = validationVolumeReader;
            validationVolumeReader = _ => NativeStart("unsupported-validation-command");
            RefreshAndWait(fixture); Refused(); validationVolumeReader = filesystemReader;
            // C: is an actually occupied volume. Only the in-memory remembered
            // letter changes here; it never becomes a host argument or I/O path.
            Rearm(); Require(Directory.GetLogicalDrives().Any(p => p.StartsWith("C:", StringComparison.OrdinalIgnoreCase)), "Expected occupied system letter absent.");
            reconnectTarget = target with { Letter = "C:" };
            RefreshAndWait(fixture); Refused();
            checks.Add("failed partition or filesystem readers and an occupied remembered letter refuse host creation and clear automatic confirmation");

            Rearm(); volumeSource = Path.Combine(directory, "unclean.img");
            RefreshAndWait(fixture); Refused();
            Require(log.Text.Contains("checking on a Mac", StringComparison.Ordinal), "Dirty reconnect did not explain native checking.");
            checks.Add("a fresh unclean-filesystem result disables reconnect mounting without writing to that image");

            Rearm(); WriteInventory(fixture); RefreshInventory(); wait(() => reconnectAttempt && readingOperation == ReadOperation.Partitions);
            reconnect.Checked = false; Settled(); Refused();
            Rearm(); WriteInventory(fixture); RefreshInventory(); wait(() => reconnectAttempt && readingOperation == ReadOperation.Volume);
            reconnect.Checked = false; Settled(); Refused();
            Rearm(); WriteInventory(fixture); RefreshInventory(); wait(() => reconnectAttempt && readingOperation == ReadOperation.Partitions);
            NotifyDeviceChangeForValidation(); discoveryDue = Environment.TickCount64 - 1; Settled(); Refused();
            checks.Add("turning reconnect off or changing the device tree during its read-only checks cancels the attempt before host creation");

            Rearm(); var mountFactory = validationHost;
            validationHost = _ => NativeStart("unsupported-validation-command");
            RefreshAndWait(fixture); wait(() => host == null);
            Refused(); Require(status.Text.StartsWith("Host failed", StringComparison.Ordinal), "Failed reconnect host claimed a clean mount.");
            validationHost = mountFactory;
            checks.Add("a failed reconnect host disables the preference and clears confirmation without claiming successful mounting");
        }
        finally
        {
            if (host != null) { RequestUnmount(); wait(() => host == null); }
            CancelReconnect(); validationPartitionReader = null;
            validationHost = originalHost; validationVolumeReader = originalVolume; validationInventoryReader = originalInventory;
        }
    }
}
