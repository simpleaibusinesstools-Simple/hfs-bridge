using System.Diagnostics;
using System.Security.Principal;
using System.Text.Json;
using System.Xml.Linq;

namespace HfsBridge.Manager;

internal sealed partial class DriveWindow
{
    private void ValidateStartup(string directory, DriveInventory fixture, DiskInspection inspection,
        string source, Action<Func<bool>> wait, List<string> checks)
    {
        void Require(bool condition, string message) { if (!condition) throw new IOException(message); }
        void Reject(Action action) { try { action(); } catch (Exception error) when (error is IOException or JsonException) { return; } throw new IOException("Unsafe startup case was accepted."); }
        var oldHost = validationHost; var oldVolume = validationVolumeReader; var oldPartitions = validationPartitionReader;
        using var identity = WindowsIdentity.GetCurrent(); string sid = identity.User!.Value;
        var disk = fixture.Disks[0] with { Number = 12, IsOffline = false, IsReadOnly = true };
        var list = new DriveInventory([disk], [], false);
        var model = inspection with { Number = disk.Number, Offline = false, ReadOnly = true };
        var part = model.Partitions[0];
        RefreshLetters(); string letter = letters.Items.Cast<string>().FirstOrDefault() ?? throw new IOException("No free test drive letter.");
        var profile = new StartupProfile(1, sid, disk.SerialNumber.Trim(), disk.Size, 512, 512,
            part.Number, part.Offset, part.Length, "ABCDEF0000000001", letter, false);
        string protocol = Path.Combine(directory, "startup-partitions.json");
        int opens = 0;
        void Select(DriveInventory? available = null)
        {
            CancelOpen(); CancelReconnect(); discoveryPending = false;
            inventory = available ?? list; disks.Items.Clear();
            foreach (var item in inventory.Disks) disks.Items.Add(item);
            if (disks.Items.Count != 0) disks.SelectedIndex = 0;
            ClearSelection(); RefreshLetters();
        }
        try
        {
            if (File.Exists(Path.Combine(AppContext.BaseDirectory, "manifest.json")))
                StartupInstall.ValidatePackage(AppContext.BaseDirectory);
            var missingTask = System.Runtime.InteropServices.Marshal.GetExceptionForHR(unchecked((int)0x80070002));
            var deniedTask = System.Runtime.InteropServices.Marshal.GetExceptionForHR(unchecked((int)0x80070005));
            Require(missingTask is FileNotFoundException && StartupInstall.IsMissingTask(missingTask) &&
                StartupInstall.IsMissingTask(new System.Runtime.InteropServices.COMException("Missing task", unchecked((int)0x80070002))) &&
                deniedTask != null && !StartupInstall.IsMissingTask(deniedTask), "Task lookup did not distinguish first installation from access denial.");
            checks.Add("first-install task lookup accepts Windows' mapped FileNotFoundException or exact COM missing-task code, while access denial remains refused");
            profile.Validate();
            Require(profile.Matches(disk with { Number = 7 }), "Startup identity incorrectly depends on a Windows disk number.");
            Require(!profile.Matches(disk with { IsSystem = true }) && !profile.Matches(disk with { BusType = "SATA" }) &&
                !profile.Matches(disk with { SerialNumber = "changed" }) && !profile.Matches(part with { Offset = part.Offset + 512 }), "Startup identity gates failed.");
            Reject(() => (profile with { VolumeId = "0000000000000000" }).Validate());
            Reject(() => (profile with { Length = ulong.MaxValue }).Validate());
            Reject(() => (profile with { Letter = "C:" }).Validate());
            var selection = new StartupSelection(sid, profile.Serial, profile.Size, profile.Partition, letter, false);
            Require(StartupSelection.Decode(selection.Encode()) == selection, "Startup selection roundtrip differs.");
            string encodedProfile = JsonSerializer.Serialize(profile);
            Require(StartupProfile.ReadJson<StartupProfile>(encodedProfile) == profile, "Saved startup profile roundtrip differs.");
            Reject(() => StartupProfile.ReadJson<StartupProfile>(encodedProfile[..^1] + ",\"Writable\":true}"));
            Reject(() => StartupProfile.ReadJson<StartupProfile>(encodedProfile.Replace("\"Writable\":false", "\"Other\":false", StringComparison.Ordinal)));
            XNamespace ns = "http://schemas.microsoft.com/windows/2004/02/mit/task";
            string task = StartupInstall.TaskXml(Path.Combine(StartupProfile.InstallDirectory(sid), "HfsBridge.Manager.exe"), sid);
            var xml = XDocument.Parse(task);
            Require(xml.Descendants(ns + "Arguments").Single().Value == "--startup" &&
                xml.Descendants(ns + "LogonType").Single().Value == "InteractiveToken" &&
                xml.Descendants(ns + "AllowHardTerminate").Single().Value == "false" &&
                xml.Descendants(ns + "ExecutionTimeLimit").Single().Value == "PT0S" &&
                xml.Descendants(ns + "UserId").All(item => item.Value == sid), "Unsafe startup task settings.");
            Reject(() => StartupInstall.TaskXml(Path.Combine(directory, "unprotected.exe"), sid));
            StartupInstall.ValidateExistingTaskXml(task, sid);
            var normalizedTask = XDocument.Parse(task);
            foreach (var user in normalizedTask.Descendants(ns + "UserId")) user.Value = identity.Name;
            StartupInstall.ValidateExistingTaskXml(normalizedTask.ToString(), sid);
            normalizedTask.Descendants(ns + "UserId").First().Value = "S-1-5-18";
            Reject(() => StartupInstall.ValidateExistingTaskXml(normalizedTask.ToString(), sid));
            Reject(() => StartupInstall.ValidateExistingTaskXml(task.Replace("--startup", "--images", StringComparison.Ordinal), sid));
            Reject(() => StartupInstall.ValidateExistingTaskXml(task.Replace("</Actions>", "<Exec><Command>unexpected.exe</Command></Exec></Actions>", StringComparison.Ordinal), sid));
            File.WriteAllText(Path.Combine(directory, "startup-task-review.xml"), task);
            checks.Add("startup profile binds USB identity, partition bounds and persistent HFS volume ID; changed disk number permitted; protected user-specific task uses no stored password or forced termination");

            File.WriteAllText(protocol, JsonSerializer.Serialize(model));
            validationPartitionReader = _ =>
            {
                var reader = DriveInventory.StartInfo(); reader.ArgumentList.Clear();
                foreach (string arg in new[] { "-NoProfile", "-NonInteractive", "-Command", "Get-Content -Raw -LiteralPath '" + protocol.Replace("'", "''", StringComparison.Ordinal) + "'" }) reader.ArgumentList.Add(arg);
                return reader;
            };
            validationVolumeReader = _ => NativeStart("inspect", source, "--json");
            validationStartupIdentityReader = (_, _) => profile.VolumeId;
            validationHost = args => { opens++; Require(args[0] == "mount-disk-readonly" && args[2] == letter, "Startup chose a writable or wrong-letter host."); return NativeStart("mount-readonly", source, letter); };
            Select(); startupProfile = profile; startupAttempted = false;
            string inventoryProtocol = Path.Combine(directory, "startup-inventory.json");
            File.WriteAllText(inventoryProtocol, JsonSerializer.Serialize(list));
            var inventoryReader = DriveInventory.StartInfo(); inventoryReader.ArgumentList.Clear();
            foreach (string arg in new[] { "-NoProfile", "-NonInteractive", "-Command", "Get-Content -Raw -LiteralPath '" + inventoryProtocol.Replace("'", "''", StringComparison.Ordinal) + "'" }) inventoryReader.ArgumentList.Add(arg);
            inventory = null; disks.Items.Clear();
            BeginRead(inventoryReader, ReadOperation.Inventory);
            // Exercise production polling/dispatch, not a direct call into
            // AdvanceOpen that could bypass a missing startup callback.
            wait(() => mountAcknowledged && host != null);
            Require(opens == 1 && !openExplorerAfterMount, "Startup host opened Explorer or failed to mount.");
            string hello = Path.Combine(letter + "\\", "Transfer", "hello.txt");
            Require(File.ReadAllText(hello).StartsWith("HFS Bridge:", StringComparison.Ordinal), "Startup-mounted image cannot be read.");
            var currentHost = host;
            tray?.Hide();
            Require(host == currentHost && File.ReadAllText(hello).StartsWith("HFS Bridge:", StringComparison.Ordinal), "Tray hide interrupted the mounted drive.");
            RequestUnmount(); wait(() => host == null);
            Select(); AdvanceOpen(ReadOperation.Inventory);
            Require(opens == 1 && readTask == null, "Startup undid a deliberate Close drive.");
            checks.Add("startup lifecycle mounts a new read-only disposable image, reads exact fixture data, suppresses Explorer, keeps host alive in tray and respects deliberate close");

            Select(new DriveInventory([], [], false)); AdvanceOpen(ReadOperation.Inventory);
            Require(!startupAttempted, "An observed absence did not reset startup eligibility.");
            Select(); validationStartupIdentityReader = (_, _) => "ABCDEF0000000002";
            AdvanceOpen(ReadOperation.Inventory); wait(() => readTask == null && !openingReadOnly);
            Require(host == null && opens == 1 && status.Text.Contains("identity changed", StringComparison.Ordinal), "Changed HFS volume was mounted automatically.");
            Select(); startupAttempted = false; startupProfile = profile with { Letter = "C:" };
            Reject(() => startupProfile.Validate());
            startupProfile = profile; Select(new DriveInventory([disk, disk with { Number = 7 }], [], false)); startupAttempted = false;
            AdvanceOpen(ReadOperation.Inventory);
            Require(host == null && opens == 1 && status.Text.Contains("Several drives", StringComparison.Ordinal), "Ambiguous startup drive was mounted.");
            checks.Add("automatic startup refuses changed volume identity and duplicate device matches; no physical raw reads or writes, registration, startup changes or elevation");

            Select(); startupProfile = profile; startupOpening = true; validationStartupIdentityReader = (_, _) => profile.VolumeId;
            letters.Items.Remove(letter);
            Reject(() => CheckStartupPartition(disk, part));
            Select(); startupProfile = profile; startupAttempted = false;
            string dirty = Path.Combine(directory, "startup-unclean-protocol.json");
            var dirtyVolume = JsonSerializer.Deserialize<DiskVolumeInspection>(File.ReadAllText(Path.Combine(directory, "native-volume-protocol.json")), DriveInventory.Json)!;
            File.WriteAllText(dirty, JsonSerializer.Serialize(dirtyVolume with { Attributes = dirtyVolume.Attributes & ~256u, EngineAccess = false }));
            validationVolumeReader = _ =>
            {
                var reader = DriveInventory.StartInfo(); reader.ArgumentList.Clear();
                foreach (string arg in new[] { "-NoProfile", "-NonInteractive", "-Command", "Get-Content -Raw -LiteralPath '" + dirty.Replace("'", "''", StringComparison.Ordinal) + "'" }) reader.ArgumentList.Add(arg);
                return reader;
            };
            AdvanceOpen(ReadOperation.Inventory); wait(() => readTask == null && !openingReadOnly);
            Require(host == null && opens == 1 && status.Text.Contains("needs checking", StringComparison.Ordinal), "Startup opened an unclean filesystem.");
            checks.Add("automatic startup refuses an occupied saved letter and an unclean filesystem before starting any host");

            disk = disk with { IsReadOnly = false }; list = list with { Disks = [disk] }; model = model with { ReadOnly = false };
            File.WriteAllText(protocol, JsonSerializer.Serialize(model));
            startupProfile = profile with { Writable = true }; startupAttempted = false;
            string writableImage = Path.Combine(directory, "startup-writable.img");
            validationVolumeReader = _ => NativeStart("inspect", source, "--json");
            validationHost = args =>
            {
                opens++; Require(args.Length == 2 && args[0] == "write-session", "Writable startup bypassed the owning supervisor.");
                var plan = DriveWritePlan.Decode(args[1]);
                Require(plan.Disk == disk && plan.Partition == part && plan.Letter == letter, "Automatic write identity changed.");
                return NativeStart("mount", source, letter, "--output", writableImage);
            };
            Select(); AdvanceOpen(ReadOperation.Inventory); wait(() => mountAcknowledged && host != null);
            Require(managedWriteHost && !readOnlyHost && !openExplorerAfterMount, "Writable startup selected the wrong mount mode.");
            string automaticFile = Path.Combine(letter + "\\", "Transfer", "startup-written.txt");
            File.WriteAllText(automaticFile, "Automatic startup disposable-image copy check.");
            using (var file = new FileStream(automaticFile, FileMode.Open, FileAccess.ReadWrite, FileShare.None)) file.Flush(true);
            using (var owner = new FileStream(automaticFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
            {
                var shuttingDown = new FormClosingEventArgs(CloseReason.WindowsShutDown, false); OnFormClosing(shuttingDown);
                wait(() => status.Text.Contains("Close open files", StringComparison.Ordinal));
                Require(shuttingDown.Cancel && tray?.ExitPending == true && host is { HasExited: false }, "Shutdown simulation abandoned the owned image.");
                Require(File.ReadAllText(automaticFile) == "Automatic startup disposable-image copy check.", "Mounted automatic-write data differs.");
            }
            // Cancel the deferred window exit for this in-process test, then
            // close through the same controller. No OS shutdown is requested.
            tray?.CancelExit(); RequestUnmount(); wait(() => host == null);
            using (var reader = Start(NativeStart("extract", writableImage, "/Transfer/startup-written.txt", Path.Combine(directory, "startup-written.txt"))))
            {
                var stdout = reader.StandardOutput.ReadToEndAsync(); var stderr = reader.StandardError.ReadToEndAsync();
                Require(reader.WaitForExit(10000) && reader.ExitCode == 0, "Saved automatic-write image extraction failed.");
                Append(stdout.GetAwaiter().GetResult() + stderr.GetAwaiter().GetResult());
            }
            Require(File.ReadAllText(Path.Combine(directory, "startup-written.txt")) == "Automatic startup disposable-image copy check." && flushAcknowledged,
                "Automatic startup did not save data and close cleanly.");
            checks.Add("opt-in writable startup selects owning-supervisor arguments; actual new image writes, held-file simulated shutdown retention, clean close and fresh saved-image extraction pass");

            using var window = new Form(); _ = window.Handle; bool owned = true; int closeRequests = 0, exits = 0;
            window.FormClosing += (_, _) => exits++;
            using var testTray = new DesktopTray(window, () => owned, () => { }, () => closeRequests++, () => "Testing");
            testTray.RequestExit(); testTray.Update();
            Require(testTray.ExitPending && closeRequests == 1 && exits == 0, "Tray exit closed an owned host early.");
            owned = false; testTray.Update();
            Require(!testTray.ExitPending && exits == 1, "Tray exit did not finish after ownership ended.");
            checks.Add("tray exit requests orderly close and waits for host ownership to end; notification and menu resources dispose");
        }
        finally
        {
            startupProfile = null; startupOpening = startupAttempted = false; validationStartupIdentityReader = null;
            CancelOpen(); if (host != null) { RequestUnmount(); wait(() => host == null); }
            validationHost = oldHost; validationVolumeReader = oldVolume; validationPartitionReader = oldPartitions;
            openExplorerAfterMount = true;
        }
    }
}
