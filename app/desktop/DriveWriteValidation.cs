using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;

namespace HfsBridge.Manager;

internal sealed partial class DriveWindow
{
    private sealed class SessionRequests : TextReader
    {
        private readonly System.Threading.Channels.Channel<string> channel = System.Threading.Channels.Channel.CreateUnbounded<string>();
        internal void CloseDrive() => channel.Writer.TryWrite("");
        internal void End() => channel.Writer.TryComplete();
        public override async Task<string?> ReadLineAsync()
        {
            try { return await channel.Reader.ReadAsync(); }
            catch (System.Threading.Channels.ChannelClosedException) { return null; }
        }
    }
    private sealed class SessionMessages : StringWriter
    {
        internal volatile bool Mounted, Busy;
        public override void WriteLine(string? text)
        {
            lock (this) base.WriteLine(text);
            Mounted |= text?.StartsWith("Mounted ", StringComparison.Ordinal) == true;
            Busy |= text?.Contains("Open files remain", StringComparison.Ordinal) == true;
        }
    }
    private sealed class ClosedGuiWriter : TextWriter
    {
        public override System.Text.Encoding Encoding => System.Text.Encoding.UTF8;
        public override void WriteLine(string? value) => throw new IOException("Simulated closed GUI pipe.");
    }

    private void ValidateWriteTransport(string directory, string source, List<string> checks)
    {
        void Require(bool value, string message) { if (!value) throw new IOException(message); }
        void WaitFor(Func<bool> condition)
        {
            var end = DateTime.UtcNow.AddSeconds(20);
            while (!condition()) { if (DateTime.UtcNow >= end) throw new TimeoutException("Write-session transport test timed out."); Thread.Sleep(50); }
        }
        RefreshLetters(); string letter = (string)letters.SelectedItem!;
        var messages = new SessionMessages(); var requests = new SessionRequests();
        string output = Path.Combine(directory, "write-supervisor.img");
        var running = Task.Run(() => DriveWriteSession.ForwardHost(NativeStart("mount", source, letter, "--output", output), requests, messages, messages));
        FileStream? held = null;
        try
        {
            WaitFor(() => messages.Mounted);
            held = new FileStream(Path.Combine(letter + "\\", "supervisor.txt"), FileMode.CreateNew, FileAccess.ReadWrite, FileShare.Read);
            held.Write(System.Text.Encoding.UTF8.GetBytes("Supervisor copy check\n")); held.Flush(true);
            requests.CloseDrive(); WaitFor(() => messages.Busy);
            Require(!running.IsCompleted, "Supervisor released a busy writable host.");
            held.Dispose(); held = null; requests.CloseDrive();
            WaitFor(() => running.IsCompleted);
            Require(running.GetAwaiter().GetResult() && !Directory.Exists(letter + "\\"), "Supervisor did not flush/close and release the letter.");
        }
        finally
        {
            held?.Dispose(); requests.End();
            WaitFor(() => running.IsCompleted);
            File.WriteAllText(Path.Combine(directory, "write-supervisor.log"), messages.ToString());
        }
        var closed = new ClosedGuiWriter();
        var orphan = Task.Run(() => DriveWriteSession.ForwardHost(NativeStart("mount", source, letter, "--output", Path.Combine(directory, "write-supervisor-gui-closed.img")),
            new StringReader(""), closed, closed));
        WaitFor(() => orphan.IsCompleted);
        Require(orphan.GetAwaiter().GetResult() && !Directory.Exists(letter + "\\"), "Closed GUI pipes interrupted clean-close ownership.");
        checks.Add("actual supervisor transport on disposable images: held file refuses early close, released file flushes and frees drive letter; lost GUI input/output pipes trigger clean close without killing the writer");
    }

    private sealed class SimulatedWriteOperations(WriteSnapshot initial) : IWriteSessionOperations
    {
        internal WriteSnapshot Snapshot = initial;
        internal readonly List<string> Events = [];
        internal bool FailOffline, FailHost, FailRestore, ChangeIdentity, ChangePartition;
        internal int Reads;
        public WriteSnapshot Inspect(DriveWritePlan plan)
        {
            Events.Add("inspect"); Reads++;
            if (Reads > 1 && ChangeIdentity) return Snapshot with { Disk = Snapshot.Disk with { SerialNumber = "changed" } };
            if (Reads > 1 && ChangePartition) return Snapshot with { Inspection = Snapshot.Inspection with {
                Partitions = [Snapshot.Inspection.Partitions[0] with { Token = new string('F', 64) }] } };
            return Snapshot;
        }
        public void SetOffline(DriveWritePlan plan, bool offline)
        {
            Events.Add(offline ? "offline" : "online");
            if (!offline && FailRestore) throw new IOException("Simulated restore failure.");
            var disk = Snapshot.Disk with { IsOffline = offline };
            Snapshot = Snapshot with { Disk = disk, Inventory = Snapshot.Inventory with { Disks = [disk] },
                Inspection = Snapshot.Inspection with { Offline = offline } };
            if (offline && FailOffline) throw new IOException("Simulated error after the disk changed state.");
        }
        public bool RunHost(string[] arguments)
        {
            Events.Add(arguments[0]);
            if (arguments[0] == "mount-disk" && !Snapshot.Disk.IsOffline) throw new IOException("Unsafe online raw writer.");
            return !FailHost;
        }
        public void Report(string message) => Events.Add("report:" + message);
    }

    private void ValidateSimpleWrite(string directory, DriveInventory fixture, DiskInspection inspection,
        DiskVolumeInspection checkedVolume, string source, Action<Func<bool>> wait, List<string> checks)
    {
        void Require(bool value, string message) { if (!value) throw new IOException(message); }
        string Hash(string path) { using var file = File.OpenRead(path); return Convert.ToHexString(SHA256.HashData(file)); }
        var disk = fixture.Disks[0] with { IsOffline = false, IsReadOnly = false };
        var list = new DriveInventory([disk], [], false);
        var model = inspection with { Offline = false, ReadOnly = false, VolumeLockSupported = false, RemovableMedia = false };
        var part = model.Partitions[0];
        var snapshot = new WriteSnapshot(list, disk, model, checkedVolume);
        var plan = new DriveWritePlan(disk, part, "R:");
        Require(DriveWritePlan.Decode(plan.Encode()) == plan, "Write request did not roundtrip.");
        var normal = new SimulatedWriteOperations(snapshot);
        Require(DriveWriteSession.Run(plan, normal) == 0 && normal.Events.SequenceEqual(new[] {
            "inspect", "offline", "inspect", "mount-disk", "online" }), "Temporary ownership did not restore after clean close.");
        foreach (var failure in new[] { "offline", "identity", "partition", "host", "restore" })
        {
            var fake = new SimulatedWriteOperations(snapshot) { FailOffline = failure == "offline", ChangeIdentity = failure == "identity",
                ChangePartition = failure == "partition", FailHost = failure == "host", FailRestore = failure == "restore" };
            Require(DriveWriteSession.Run(plan, fake) != 0, "Ownership failure was reported as success.");
            Require(fake.Events.Contains("online") == (failure != "host"), "Failed writer restored online or pre-host failure abandoned owned state.");
            Require(fake.Events.Contains("mount-disk") == (failure is "host" or "restore"), "Writer started after failed preparation.");
        }
        foreach (var bad in new[] {
            snapshot with { Inventory = list with { Drivers = [new DriverItem("Hfsplus", "Running")] } },
            snapshot with { Disk = disk with { IsSystem = true } },
            snapshot with { Disk = disk with { IsReadOnly = true }, Inspection = model with { ReadOnly = true } },
            snapshot with { Volume = checkedVolume with { EngineAccess = false, Journal = "pending" } } })
        {
            var fake = new SimulatedWriteOperations(bad);
            Require(DriveWriteSession.Run(plan, fake) != 0 && !fake.Events.Contains("offline") && !fake.Events.Contains("mount-disk"),
                "Unsafe preflight caused a state change or writer start.");
        }
        var alreadyOffline = disk with { IsOffline = true };
        var offline = new SimulatedWriteOperations(snapshot with { Disk = alreadyOffline, Inventory = list with { Disks = [alreadyOffline] }, Inspection = model with { Offline = true } });
        Require(DriveWriteSession.Run(plan, offline) == 0 && !offline.Events.Contains("online") && !offline.Events.Contains("offline"),
            "Pre-existing offline state was changed.");
        var removable = new SimulatedWriteOperations(snapshot with { Inspection = model with { RemovableMedia = true, VolumeLockSupported = true } });
        Require(DriveWriteSession.Run(plan, removable) == 0 && removable.Events.Contains("mount-volume") && !removable.Events.Contains("offline"),
            "Removable volume unnecessarily changed disk state.");
        checks.Add("write-session ownership: fresh identity/partition checks, temporary offline/clean restore, already-offline preservation, removable locking, and five injected failures; unsafe preflight causes no state changes (simulated disk operations)");

        var oldHost = validationHost; var oldVolume = validationVolumeReader; var oldPartitions = validationPartitionReader;
        string original = Hash(source), protocol = Path.Combine(directory, "simple-write-partitions.json");
        string output = Path.Combine(directory, "simple-write.img");
        try
        {
            CancelOpen(); CancelReconnect(); discoveryPending = false;
            inventory = list; disks.Items.Clear(); disks.Items.Add(disk); disks.SelectedIndex = 0;
            ClearSelection(); RefreshLetters();
            File.WriteAllText(protocol, JsonSerializer.Serialize(model));
            validationPartitionReader = args => {
                Require(args.SequenceEqual(new[] { "disk-inspect", disk.Number.ToString(), "--json" }), "Wrong write inspection arguments.");
                var start = DriveInventory.StartInfo(); start.ArgumentList.Clear();
                foreach (string arg in new[] { "-NoProfile", "-NonInteractive", "-Command", "Get-Content -Raw -LiteralPath '" + protocol.Replace("'", "''", StringComparison.Ordinal) + "'" }) start.ArgumentList.Add(arg);
                return start;
            };
            validationVolumeReader = args => {
                Require(args.SequenceEqual(model.VolumeArguments(list, disk, part)), "Wrong write volume check.");
                return NativeStart("inspect", source, "--json");
            };
            validationHost = args => {
                Require(args.Length == 2 && args[0] == "write-session", "Simple write bypassed ownership supervisor.");
                var request = DriveWritePlan.Decode(args[1]);
                Require(request.Disk == disk && request.Partition == part, "Write request selected the wrong disk.");
                return NativeStart("mount", source, request.Letter, "--output", output);
            };
            allowChanges.Checked = true; OpenDrive(); wait(() => host != null && mountAcknowledged);
            Require(managedWriteHost && !readOnlyHost && allowChanges.Checked && !allowChanges.Enabled &&
                openDescription.Text.StartsWith("Copy files both ways", StringComparison.Ordinal), "Write mode was lost, mislabeled or changeable while mounted.");
            string folder = Path.Combine(mountedLetter! + "\\", "Windows copy check");
            Directory.CreateDirectory(folder);
            string payload = Path.Combine(directory, "simple-write-payload.bin");
            File.WriteAllBytes(payload, Enumerable.Range(0, 131101).Select(i => (byte)((i * 37 + 11) % 251)).ToArray());
            string target = Path.Combine(folder, "payload.bin"); File.Copy(payload, target);
            using (var stream = new FileStream(target, FileMode.Open, FileAccess.ReadWrite, FileShare.Read)) stream.Flush(true);
            string returned = Path.Combine(directory, "simple-write-returned.bin"); File.Copy(target, returned);
            Require(Hash(payload) == Hash(returned), "Simple-write copy-back hash differs.");
            RequestUnmount(); wait(() => host == null);
            Require(status.Text == "Drive closed · changes saved" && Hash(source) == original, "Simple write did not close cleanly or changed the source.");
            checks.Add("simple writable desktop action: automatic partition/check/session request, native image copy in and back with exact hash, disabled controls while mounted, clean close and unchanged source (physical state operations simulated separately)");
            ValidateWriteTransport(directory, source, checks);
        }
        finally
        {
            CancelOpen(); if (host != null) { RequestUnmount(); wait(() => host == null); }
            validationHost = oldHost; validationVolumeReader = oldVolume; validationPartitionReader = oldPartitions;
            allowChanges.Checked = false;
        }
    }
}
