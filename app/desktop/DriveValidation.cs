using System.Diagnostics;
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace HfsBridge.Manager;

internal sealed partial class DriveWindow
{
    internal int ValidateWorkflow(string directory, string protocolFixture, string? physicalInspection = null)
    {
        if (Directory.Exists(directory) || File.Exists(directory)) throw new IOException("Use a new evidence directory.");
        Directory.CreateDirectory(directory);
        var checks = new List<string>(); string? failure = null; FileStream? held = null;
        void Require(bool value, string message) { if (!value) throw new IOException(message); }
        void Wait(Func<bool> condition)
        {
            DateTime end = DateTime.UtcNow.AddSeconds(25);
            do { Poll(); if (condition()) return; Thread.Sleep(50); } while (DateTime.UtcNow < end);
            throw new TimeoutException(status.Text);
        }
        string Hash(string file) { using var input = File.OpenRead(file); return Convert.ToHexString(SHA256.HashData(input)); }
        try
        {
            var disk = new DiskItem(3, "Validation USB", "USB", 8192, "AB12", 512, 512, false, false, true, false);
            var clean = new DriveInventory([disk], [], false);
            string protocol = File.ReadAllText(protocolFixture);
            var inspected = DiskInspection.Parse(protocol, disk);
            var part = inspected.Partitions.Single();
            Require(part.Name == "Mac Ω\"\\\n", "Rust/C# Unicode or escape mismatch.");
            Require(inspected.MountArguments(clean, disk, part, true, "Z:").SequenceEqual(new[] { "mount-disk", "3", "Z:", "--partition", "1", "--identity", part.Token }), "Wrong host arguments.");
            checks.Add("Rust JSON parses with exact Unicode/control data and token; direct-drive host arguments match");
            void Refuses(DiskInspection value, DriveInventory list, DiskItem item, DiskPartition? choice, bool confirmation)
            { Require(value.Refusal(list, item, choice, confirmation) != null, "Ineligible drive selection accepted."); }
            Refuses(inspected, clean, disk, part, false); Refuses(inspected, clean, disk, null, true);
            Refuses(inspected, clean, disk, part with { Writable = false }, true);
            Refuses(inspected, new DriveInventory([disk], [new DriverItem("Hfsplus", "Running")], false), disk, part, true);
            var pending = new DriveInventory([disk], [], true);
            Require(pending.ParagonActive && inspected.Refusal(pending, disk, part, true)!.StartsWith("Restart Windows", StringComparison.Ordinal), "Pending driver removal bypassed restart gate.");
            foreach (var changed in new[] { disk with { Number = 4 }, disk with { IsSystem = true }, disk with { IsBoot = true }, disk with { BusType = "NVMe" }, disk with { SerialNumber = "changed" }, disk with { Size = 16384 }, disk with { IsReadOnly = true }, disk with { IsOffline = false }, disk with { PhysicalSectorSize = 4096 } })
                Refuses(inspected, new DriveInventory([changed], [], false), changed, part, true);
            foreach (var changed in new[] { inspected with { Offline = false }, inspected with { ReadOnly = true }, inspected with { PhysicalWriteSupported = false }, inspected with { PhysicalSector = 4096 } })
                Refuses(changed, clean, disk, part, true);
            void Reject(Action action) { bool refused = false; try { action(); } catch { refused = true; } Require(refused, "Malformed inspection accepted."); }
            Reject(() => DriveInventory.Parse("{\"Disks\":[],\"Drivers\":null,\"ParagonRemovalPending\":false}"));
            Reject(() => DriveInventory.Parse("{\"Disks\":[],\"Drivers\":[]}"));
            string incomplete = JsonSerializer.Serialize(disk).Replace("\"IsSystem\":false,", "", StringComparison.Ordinal);
            Reject(() => DriveInventory.Parse("{\"Disks\":[" + incomplete + "],\"Drivers\":[],\"ParagonRemovalPending\":false}"));
            foreach (string corruption in new[] { "schema", "number", "bounds", "token", "missing", "duplicate" })
            {
                var corrupt = JsonNode.Parse(protocol)!;
                switch (corruption)
                {
                    case "schema": corrupt["schema"] = 2; break;
                    case "number": corrupt["number"] = 4; break;
                    case "bounds": corrupt["partitions"]![0]!["length"] = ulong.MaxValue; break;
                    case "token": corrupt["partitions"]![0]!["token"] = "yes"; break;
                    case "missing": corrupt.AsObject().Remove("readOnly"); break;
                    default: corrupt["partitions"]!.AsArray().Add(corrupt["partitions"]![0]!.DeepClone()); break;
                }
                Reject(() => DiskInspection.Parse(corrupt.ToJsonString(), disk));
            }
            checks.Add("identity/system/boot/non-USB/Paragon/restart/offline/sector/permission gates and incomplete, corrupt or duplicate metadata refuse mounting");
            var protectedOnline = disk with { IsOffline = false, IsReadOnly = true };
            Require((inspected with { Offline = false, ReadOnly = true }).VolumeArguments(new DriveInventory([protectedOnline], [], false), protectedOnline, part)
                .SequenceEqual(new[] { "disk-volume", "3", "--partition", "1", "--identity", part.Token }), "Online/protected volume read was refused or has unsafe arguments.");
            Reject(() => inspected.VolumeArguments(clean, disk with { SerialNumber = "changed" }, part));
            Reject(() => inspected.VolumeArguments(clean, disk, part with { Token = new string('A', 64) }));
            checks.Add("filesystem status uses explicit partition/token and permits read-only online/protected selection without relaxing mount gates");
            var unknownAlignment = JsonNode.Parse(protocol)!;
            unknownAlignment["physicalSector"] = 0;
            unknownAlignment["physicalWriteSupported"] = false;
            var unknown = DiskInspection.Parse(unknownAlignment.ToJsonString(), disk);
            Require(unknown.VolumeArguments(clean, disk, unknown.Partitions[0])[0] == "disk-volume", "Missing alignment query blocked safe inspection.");
            Refuses(unknown, clean, disk, unknown.Partitions[0], true);
            unknownAlignment["physicalWriteSupported"] = true;
            Reject(() => DiskInspection.Parse(unknownAlignment.ToJsonString(), disk));
            checks.Add("unsupported physical alignment permits read-only checks, reports unknown and refuses write mounting");
            unknownAlignment["physicalWriteSupported"] = false;
            unknownAlignment["removableMedia"] = true;
            unknownAlignment["volumeLockSupported"] = true;
            unknownAlignment["offline"] = false;
            var removableDisk = disk with { IsOffline = false };
            var removableInventory = new DriveInventory([removableDisk], [], false);
            var removable = DiskInspection.Parse(unknownAlignment.ToJsonString(), removableDisk);
            Require(removable.MountArguments(removableInventory, removableDisk, removable.Partitions[0], true, "Z:")[0] == "mount-volume", "Removable USB did not select held-volume locking.");
            Refuses(removable, removableInventory, removableDisk, removable.Partitions[0], false);
            Refuses(removable with { ReadOnly = true }, removableInventory, removableDisk, removable.Partitions[0], true);
            unknownAlignment["removableMedia"] = false;
            Reject(() => DiskInspection.Parse(unknownAlignment.ToJsonString(), removableDisk));
            checks.Add("eligible online removable USB selects volume locking; consent, write protection and truthful capabilities remain required");

            RefreshInventory(); Wait(() => readTask == null);
            Require(inventory != null, "Live read-only inventory failed.");
            Require(disks.Items.Cast<DiskItem>().All(d => d.External), "Internal disk entered external list.");
            File.WriteAllText(Path.Combine(directory, "live-inventory.json"), JsonSerializer.Serialize(inventory, new JsonSerializerOptions { WriteIndented = true }));
            checks.Add("live Windows disk/driver inventory works; internal/system drives excluded");
            if (physicalInspection != null)
            {
                string captured = File.ReadAllText(physicalInspection);
                using var identity = JsonDocument.Parse(captured);
                uint number = identity.RootElement.GetProperty("number").GetUInt32();
                var liveDisk = inventory!.Disks.Single(d => d.Number == number && d.External);
                var actual = DiskInspection.Parse(captured, liveDisk);
                Require(actual.Partitions.Any(p => p.HfsCandidate), "Real-drive inspection lacks an HFS candidate.");
                Require(inventory.ParagonActive && actual.Refusal(inventory, liveDisk, actual.Partitions.First(p => p.HfsCandidate), true)!.Contains("Paragon", StringComparison.Ordinal), "Real drive bypassed active Paragon gate.");
                File.Copy(physicalInspection, Path.Combine(directory, "physical-inspection.json"));
                checks.Add("read-only Toshiba inspection matches live Windows identity and parses in desktop; active Paragon refuses direct mounting");
            }
            string source = Path.Combine(directory, "source.img"), output = Path.Combine(directory, "writable.img");
            using (var fixture = Start(NativeStart("fixture", source, "--journaled")))
            {
                var stdout = fixture.StandardOutput.ReadToEndAsync(); var stderr = fixture.StandardError.ReadToEndAsync();
                Require(fixture.WaitForExit(10000) && fixture.ExitCode == 0, "Disposable image fixture failed.");
                Append(stdout.GetAwaiter().GetResult() + stderr.GetAwaiter().GetResult());
            }
            string original = Hash(source);
            // The synthetic selection's capacity matches this new regular image.
            // Only validation maps disk-volume to the image-only inspect command.
            part = part with { Length = (ulong)new FileInfo(source).Length };
            disk = disk with { Size = part.Length + 8192 };
            clean = new DriveInventory([disk], [], false);
            inspected = inspected with { Length = disk.Size, Partitions = [part] };
            string volumeSource = source;
            ProcessStartInfo ImageVolumeReader(string[] args)
            {
                Require(args.SequenceEqual(inspected.VolumeArguments(clean, disk, part)), "Wrong filesystem-status helper arguments.");
                return NativeStart("inspect", volumeSource, "--json");
            }
            validationVolumeReader = ImageVolumeReader;
            void SelectFixture(bool checkFilesystem = true)
            {
                inventory = clean; disks.Items.Clear(); disks.Items.Add(disk); disks.SelectedIndex = 0;
                snapshot = inspected; partitions.Items.Add(part); partitions.SelectedIndex = 0;
                consent.Checked = false; UpdateControls(); Require(!mount.Enabled, "Mount enabled before confirmation.");
                consent.Checked = true; UpdateControls(); Require(!mount.Enabled && !consent.Enabled, "Mount enabled before filesystem status was checked.");
                consent.Checked = false;
                if (checkFilesystem)
                {
                    CheckSelectedVolume(); Require(!checkVolume.Enabled && !partitions.Enabled && !mount.Enabled, "Inputs stayed editable during filesystem status read.");
                    Wait(() => readTask == null);
                    Require(volume is { EngineAccess: true } && consent.Enabled && !mount.Enabled, "Native image filesystem status did not pass or bypassed confirmation.");
                    consent.Checked = true; UpdateControls(); Require(mount.Enabled, "Valid checked selection did not enable Mount.");
                }
            }
            SelectFixture(); string volumeProtocol = readOut!.GetAwaiter().GetResult();
            ValidatePresentationModes(checks);
            File.WriteAllText(Path.Combine(directory, "native-volume-protocol.json"), volumeProtocol);
            foreach (string corruption in new[] { "schema", "signature", "bounds", "free", "journal", "journalFlag", "unsafe", "contradiction", "alternate", "missing", "operation" })
            {
                var corrupt = JsonNode.Parse(volumeProtocol)!;
                switch (corruption)
                {
                    case "schema": corrupt["schema"] = 2; break;
                    case "signature": corrupt["signature"] = 0; break;
                    case "bounds": corrupt["totalBlocks"] = uint.MaxValue; break;
                    case "free": corrupt["freeBlocks"] = uint.MaxValue; break;
                    case "journal": corrupt["journal"] = "repaired"; break;
                    case "journalFlag": corrupt["journal"] = "absent"; break;
                    case "unsafe": corrupt["physicalWrites"] = true; break;
                    case "contradiction": corrupt["attributes"] = volume!.Attributes & ~256u; break;
                    case "alternate": corrupt["alternateMatches"] = true; corrupt["alternateCompatible"] = false; break;
                    case "missing": corrupt.AsObject().Remove("engineAccess"); break;
                    default: corrupt["operation"] = "repair"; break;
                }
                Reject(() => DiskVolumeInspection.Parse(corrupt.ToJsonString(), part));
            }
            Reject(() => DiskVolumeInspection.Parse(volumeProtocol.TrimEnd()[..^1] + ",\"SCHEMA\":1}", part));
            checks.Add("actual Rust volume JSON parses; duplicate/missing/contradictory/unsafe/wrong-operation/geometry reports refuse mount readiness");
            SelectFixture(); disks.Items.Add(disk with { Number = 4, SerialNumber = "other" }); disks.SelectedIndex = 1;
            Require(snapshot == null && volume == null && !consent.Checked && !mount.Enabled && partitions.Items.Count == 0, "Changed drive kept stale selection.");
            SelectFixture(); CheckSelectedVolume(); partitions.Items.Add(part with { Number = 2 }); partitions.SelectedIndex = 1;
            Wait(() => readTask == null);
            Require(volume == null && !consent.Checked && !mount.Enabled, "Changed partition accepted stale filesystem status.");
            SelectFixture(); validationVolumeReader = _ => NativeStart("unsupported-validation-command"); CheckSelectedVolume(); Wait(() => readTask == null);
            Require(volume == null && !consent.Checked && !mount.Enabled && !consent.Enabled && status.Text.StartsWith("Filesystem check failed", StringComparison.Ordinal), "Failed reader reused passing filesystem status.");
            validationVolumeReader = ImageVolumeReader;
            string dirty = Path.Combine(directory, "unclean.img"); File.Copy(source, dirty);
            using (var image = File.Open(dirty, FileMode.Open, FileAccess.ReadWrite, FileShare.None))
            {
                byte[] attributes = new byte[4];
                foreach (long position in new[] { 1028L, image.Length - 1020 })
                {
                    image.Position = position; image.ReadExactly(attributes);
                    BinaryPrimitives.WriteUInt32BigEndian(attributes, BinaryPrimitives.ReadUInt32BigEndian(attributes) & ~256u);
                    image.Position = position; image.Write(attributes);
                }
                image.Flush(true);
            }
            string dirtyBefore = Hash(dirty); volumeSource = dirty; SelectFixture(false); CheckSelectedVolume(); Wait(() => readTask == null);
            Require(volume is { EngineAccess: false } && !mount.Enabled && !consent.Enabled && status.Text.Contains("checking on a Mac", StringComparison.Ordinal), "Unclean volume did not explain native-check refusal.");
            int forbiddenMounts = 0; validationHost = _ => { forbiddenMounts++; throw new IOException("Unclean-volume host must not start."); };
            consent.Checked = true; UpdateControls(); StartMount();
            Require(!mount.Enabled && host == null && forbiddenMounts == 0 && Hash(dirty) == dirtyBefore, "Unclean status permitted a host or changed the image.");
            validationHost = null; volumeSource = source;
            checks.Add("drive/partition changes and failed readers invalidate prior status; an actual unclean image refuses the host even with forced confirmation and stays byte-identical");
            SelectFixture(); checks.Add("drive changes discard inspection/token/confirmation; explicit confirmation controls Mount");
            var discoveryReads = ValidateDiscovery(directory, clean, inspected, SelectFixture, Wait, checks);
            string letter = (string?)letters.SelectedItem ?? throw new IOException("No free drive letter.");
            // This controller test hosts a NEW regular image. Raw storage has
            // separate owned-VHD acceptance; no physical-drive writes occur.
            validationHost = args => NativeStart("mount", source, args[2], "--output", output);
            StartMount(); Wait(() => mountAcknowledged && Directory.Exists(letter + "\\"));
            Require(!refresh.Enabled && !disks.Enabled && !partitions.Enabled && !checkVolume.Enabled && !consent.Enabled && unmount.Enabled, "Mounted inputs remained editable.");
            int readsBeforeMountEvent = discoveryReads(), ownedHost = host!.Id;
            for (int i = 0; i < 12; i++) NotifyDeviceChangeForValidation();
            discoveryDue = Environment.TickCount64 - 1; Poll();
            Require(host is { HasExited: false } && host.Id == ownedHost && readTask == null && discoveryReads() == readsBeforeMountEvent && unmount.Enabled && mountAcknowledged,
                "Discovery interfered with a mounted host or started a competing reader.");
            string file = Path.Combine(letter + "\\", "drive-window.bin"), copied = Path.Combine(directory, "copied-out.bin");
            byte[] payload = Enumerable.Range(0, 80019).Select(i => (byte)(i % 251)).ToArray();
            File.WriteAllBytes(file, payload); File.Copy(file, copied);
            Require(File.ReadAllBytes(copied).SequenceEqual(payload), "Copy roundtrip failed.");
            held = File.Open(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite); RequestUnmount();
            Wait(() => status.Text.Contains("Close open files", StringComparison.Ordinal));
            var closing = new FormClosingEventArgs(CloseReason.UserClosing, false); OnFormClosing(closing);
            Require(closing.Cancel && host is { HasExited: false } && Directory.Exists(letter + "\\"), "Busy close released host.");
            held.Dispose(); held = null; RequestUnmount(); Wait(() => host == null);
            Require(status.Text.StartsWith("Unmounted and flushed", StringComparison.Ordinal) && snapshot == null && !mount.Enabled && !unmount.Enabled && !Directory.Exists(letter + "\\"), "Unmount did not clear stale selection.");
            Require(Hash(source) == original, "Source image changed.");
            checks.Add("real disposable-image host/copy roundtrip, locked inputs, busy unmount/close retention, flush confirmation and selection invalidation");
            Wait(() => !discoveryPending && readTask == null);
            Require(discoveryReads() == readsBeforeMountEvent + 1 && snapshot == null && volume == null && !consent.Checked && !mount.Enabled,
                "Deferred mounted-host discovery failed to run once after clean unmount or reused readiness.");
            checks.Add("device notifications during a real image mount preserve host ownership and busy-close retention; one read-only refresh follows clean unmount");
            SelectFixture(); validationHost = _ => NativeStart("unsupported-validation-command"); StartMount(); Wait(() => host == null);
            Require(status.Text.StartsWith("Host failed", StringComparison.Ordinal) && !mount.Enabled, "Failed child reported success.");
            checks.Add("failed child cannot report successful mount/unmount or reuse selection");

            SelectFixture();
            string crashed = Path.Combine(directory, "crashed.img"), reopened = Path.Combine(directory, "reopened.img");
            letter = (string?)letters.SelectedItem ?? throw new IOException("No free crash-test drive letter.");
            validationHost = args => NativeStart("mount", source, args[2], "--output", crashed);
            StartMount(); Wait(() => mountAcknowledged && Directory.Exists(letter + "\\"));
            file = Path.Combine(letter + "\\", "crash-window.bin");
            held = new FileStream(file, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.ReadWrite | FileShare.Delete, 4096, FileOptions.WriteThrough);
            held.Write(payload); held.Flush(true);
            using (var observer = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
            {
                byte[] acknowledged = new byte[payload.Length]; observer.ReadExactly(acknowledged);
                Require(acknowledged.SequenceEqual(payload) && observer.ReadByte() == -1, "Acknowledged crash-test payload differs.");
            }
            // Deliberate process death is confined to this directly owned child
            // and the NEW regular-image backend, after an acknowledged flush.
            // No physical-drive host or arbitrary PID enters this test.
            Require(host != null && !host.HasExited && host.StartInfo.ArgumentList.SequenceEqual(new[] { "mount", source, letter, "--output", crashed }), "Crash test does not own an image-only host.");
            int crashPid = host!.Id;
            host.Kill(); Require(host.WaitForExit(10000), "Owned crash-test host did not exit.");
            int crashExit = host.ExitCode;
            Wait(() => host == null);
            Require(status.Text.StartsWith("Host failed", StringComparison.Ordinal) && !flushAcknowledged && !unmountRequested && snapshot == null && volume == null && !consent.Checked && !mount.Enabled && !unmount.Enabled && refresh.Enabled, "Host death reported a clean flush or retained mount readiness.");
            bool assignedWhileHeld = Directory.GetLogicalDrives().Any(d => d.StartsWith(letter, StringComparison.OrdinalIgnoreCase));
            bool listedWhileHeld = letters.Items.Contains(letter);
            held.Dispose(); held = null;
            Wait(() => !Directory.GetLogicalDrives().Any(d => d.StartsWith(letter, StringComparison.OrdinalIgnoreCase)));
            RefreshInventory(); Wait(() => readTask == null);
            Require(letters.Items.Contains(letter), "Released crash drive letter is missing after Refresh drives.");
            using (var reader = Start(NativeStart("inspect", crashed, "--json")))
            {
                var stdout = reader.StandardOutput.ReadToEndAsync(); var stderr = reader.StandardError.ReadToEndAsync();
                Require(reader.WaitForExit(10000) && reader.ExitCode == 0, "Crash-image inspection failed.");
                string crashProtocol = stdout.GetAwaiter().GetResult(); Append(stderr.GetAwaiter().GetResult());
                File.WriteAllText(Path.Combine(directory, "crashed-volume-protocol.json"), crashProtocol);
                Require(DiskVolumeInspection.Parse(crashProtocol, part).EngineAccess, "Acknowledged crash output did not pass existing engine preflight.");
            }
            string recovered = Path.Combine(directory, "after-crash.bin");
            using (var reader = Start(NativeStart("extract", crashed, "/crash-window.bin", recovered)))
            {
                var stdout = reader.StandardOutput.ReadToEndAsync(); var stderr = reader.StandardError.ReadToEndAsync();
                Require(reader.WaitForExit(10000) && reader.ExitCode == 0, "Read-only crash payload extraction failed.");
                Append(stdout.GetAwaiter().GetResult() + stderr.GetAwaiter().GetResult());
            }
            Require(File.ReadAllBytes(recovered).SequenceEqual(payload) && Hash(source) == original, "Acknowledged crash payload or source image changed.");
            string crashHash = Hash(crashed);
            SelectFixture();
            validationHost = args => NativeStart("mount", crashed, args[2], "--output", reopened);
            StartMount(); Wait(() => mountAcknowledged && Directory.Exists(letter + "\\"));
            Require(File.ReadAllBytes(Path.Combine(letter + "\\", "crash-window.bin")).SequenceEqual(payload), "Reopened crash payload differs.");
            RequestUnmount(); Wait(() => host == null);
            Require(status.Text.StartsWith("Unmounted and flushed", StringComparison.Ordinal) && Hash(crashed) == crashHash && Hash(source) == original, "Reopened crash copy failed clean unmount or changed an input.");
            File.WriteAllText(Path.Combine(directory, "crash-result.json"), JsonSerializer.Serialize(new
            {
                Pass = true, OwnedHostPID = crashPid, TerminatedHostExit = crashExit,
                DeliberateProcessTermination = true, LiveWindowsHandleDuringTermination = true, AcknowledgedFlush = true,
                FalseCleanUnmountRefused = true, SelectionInvalidated = true,
                DriveLetterAssignedWhileHandleHeld = assignedWhileHeld, DriveLetterListedWhileHandleHeld = listedWhileHeld,
                DriveLetterReleasedAndReusable = true, PayloadSHA256 = Hash(recovered), CrashImageSHA256 = crashHash,
                ReopenedImageSHA256 = Hash(reopened), SourceUnchanged = true, PhysicalDiskWrites = false,
                Limitation = "Process death after acknowledged flush; no hardware power loss or interruption of an in-progress transaction"
            }, new JsonSerializerOptions { WriteIndented = true }));
            checks.Add("real image-host death with a live Windows handle refuses clean-unmount reporting, clears readiness, releases its letter and preserves acknowledged payload through read-only extraction and clean remount");
            ValidateReconnect(directory, clean, inspected, source, SelectFixture, Wait, checks);
            ValidateSimpleOpen(directory, clean, inspected, source, Wait, checks);
            ValidateSimpleWrite(directory, clean, inspected, DiskVolumeInspection.Parse(volumeProtocol, part), source, Wait, checks);
            ValidateStartup(directory, clean, inspected, source, Wait, checks);
            ValidateFastTransfer(directory, clean, inspected, source, checks);
            ValidateTransferClose(directory, clean, inspected, source, Wait, checks);
            ValidateHostFailure(directory, clean, inspected, Wait, checks);
            int readsBeforeClose = discoveryReads(); NotifyDeviceChangeForValidation();
            var finalClosing = new FormClosingEventArgs(CloseReason.UserClosing, false); OnFormClosing(finalClosing);
            discoveryDue = Environment.TickCount64 - 1; Poll();
            Require(!finalClosing.Cancel && !discoveryPending && readTask == null && discoveryReads() == readsBeforeClose,
                "Closing a window launched a delayed discovery helper.");
            checks.Add("closing an unmounted window cancels pending discovery without starting another helper");
        }
        catch (Exception error) { failure = error.ToString(); }
        finally
        {
            held?.Dispose();
            if (host != null) { RequestUnmount(); try { Wait(() => host == null); } catch (Exception error) { failure += " " + error.Message; } }
            validationHost = null;
            validationVolumeReader = null;
            validationInventoryReader = null;
            File.WriteAllText(Path.Combine(directory, "controller.log"), log.Text);
            File.WriteAllText(Path.Combine(directory, "result.json"), JsonSerializer.Serialize(new { Pass = failure == null, Failure = failure, Checks = checks, NativeBinarySHA256 = Hash(binary), PhysicalDiskWrites = false, HostLifetimeBacking = "New disposable image", RawBackendAcceptance = "milestone-30 owned VHD Windows/Mac", VisualAcceptance = "PENDING" }, new JsonSerializerOptions { WriteIndented = true }));
        }
        return failure == null ? 0 : 1;
    }
}
