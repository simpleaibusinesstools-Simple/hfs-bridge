using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;

namespace HfsBridge.Manager;

internal sealed partial class DriveWindow
{
    private void ValidateTransferClose(string directory, DriveInventory fixture, DiskInspection inspection,
        string image, Action<Func<bool>> wait, List<string> checks)
    {
        void Require(bool condition, string message) { if (!condition) throw new IOException(message); }
        string Hash(string path) { using var input = File.OpenRead(path); return Convert.ToHexString(SHA256.HashData(input)); }
        var oldHost = validationHost; var oldInventory = validationInventoryReader;
        var oldPartitions = validationPartitionReader; var oldVolume = validationVolumeReader;
        string original = Hash(image), listFile = Path.Combine(directory,"transfer-close-inventory.json"),
            partsFile = Path.Combine(directory,"transfer-close-partitions.json");
        var disk = fixture.Disks[0] with { IsOffline = false, IsReadOnly = false };
        var list = new DriveInventory([disk],[],false);
        var model = inspection with { Offline = false, ReadOnly = false };
        int dialogs = 0, inventoryReads = 0, partitionReads = 0, volumeReads = 0;
        FileStream? held = null;
        ProcessStartInfo JsonReader(string path)
        {
            var start = DriveInventory.StartInfo(); start.ArgumentList.Clear();
            foreach (string arg in new[] { "-NoProfile","-NonInteractive","-Command",
                "Get-Content -Raw -LiteralPath '"+path.Replace("'","''",StringComparison.Ordinal)+"'" }) start.ArgumentList.Add(arg);
            return start;
        }
        void Select()
        {
            CancelOpen(); CancelReconnect(); discoveryPending = false; hostIoFailed = logFailed = false;
            inventory = list; disks.Items.Clear(); disks.Items.Add(disk); disks.SelectedIndex = 0; RefreshLetters();
            File.WriteAllText(listFile,JsonSerializer.Serialize(list));
            File.WriteAllText(partsFile,JsonSerializer.Serialize(model));
            validationTransferConsent = () => true;
        }
        void OpenReadOnly()
        { Select(); OpenDrive(); wait(() => host != null && mountAcknowledged); Require(fastTransfer.Enabled,"Mounted drive still disables the transfer action."); }
        try
        {
            validationInventoryReader = () => { inventoryReads++; return JsonReader(listFile); };
            validationPartitionReader = _ => { partitionReads++; return JsonReader(partsFile); };
            validationVolumeReader = _ => { volumeReads++; return NativeStart("inspect",image,"--json"); };
            validationHost = args => {
                Require(args[0] == "mount-disk-readonly","Transfer close test attempted a writable mount.");
                return NativeStart("mount-readonly",image,args[2]);
            };
            validationTransferDialog = plan => {
                Require(host == null && transferActive && plan.Disk == disk && plan.Partition == model.Partitions[0],
                    "Transfer dialog opened before host release or for a changed target.");
                dialogs++;
            };
            OpenReadOnly();
            int owned = host!.Id; validationTransferConsent = () => false; OpenTransfer();
            Require(host?.Id == owned && !unmountRequested && transferAfterClose == null && !allowChanges.Checked,
                "Declining transfer writing changed or closed the mounted read-only session.");
            checks.Add("mounted fast-transfer action is usable; declining write permission preserves the owned read-only host and source");

            string letter = mountedLetter!;
            held = File.Open(Path.Combine(letter+"\\","Transfer","hello.txt"),FileMode.Open,FileAccess.Read,FileShare.ReadWrite);
            int previousInventory = inventoryReads, previousParts = partitionReads, previousVolume = volumeReads;
            validationTransferConsent = () => true; OpenTransfer();
            wait(() => status.Text.Contains("Close open files",StringComparison.Ordinal));
            Require(host?.Id == owned && transferAfterClose != null && dialogs == 0 && !fastTransfer.Enabled && inventoryReads == previousInventory,
                "Held-file close started a competing transfer/reader or lost the queued action.");
            held.Dispose(); held = null;
            wait(() => dialogs == 1 && host == null && readTask == null);
            Require(inventoryReads > previousInventory && partitionReads > previousParts && volumeReads > previousVolume &&
                !Directory.Exists(letter+"\\") && Hash(image) == original,"Safe close skipped fresh checks or changed the read-only source.");
            checks.Add("held open file defers fast transfer without killing the host; clean release runs fresh inventory/partition/filesystem checks before the transfer dialog");

            OpenReadOnly(); int beforeChanged = dialogs;
            held = File.Open(Path.Combine(mountedLetter!+"\\","Transfer","hello.txt"),FileMode.Open,FileAccess.Read,FileShare.ReadWrite);
            OpenTransfer(); wait(() => status.Text.Contains("Close open files",StringComparison.Ordinal));
            File.WriteAllText(listFile,JsonSerializer.Serialize(new DriveInventory([disk with { SerialNumber = "CHANGED" }],[],false)));
            held.Dispose(); held = null;
            wait(() => host == null && readTask == null && !openingReadOnly);
            Require(dialogs == beforeChanged && requestedOpen == null && transferAfterClose == null,"Changed identity reached a transfer.");
            checks.Add("a changed drive identity after clean close cancels transfer before any writer or dialog starts");

            OpenReadOnly(); int beforeDisconnect = dialogs;
            held = File.Open(Path.Combine(mountedLetter!+"\\","Transfer","hello.txt"),FileMode.Open,FileAccess.Read,FileShare.ReadWrite);
            OpenTransfer(); wait(() => status.Text.Contains("Close open files",StringComparison.Ordinal));
            NotifyDeviceChangeForValidation(); Require(transferAfterClose == null,"Device change kept transfer approval.");
            held.Dispose(); held = null; RequestUnmount();
            wait(() => host == null && readTask == null && !discoveryPending);
            Require(dialogs == beforeDisconnect,"Device change auto-resumed a transfer.");
            checks.Add("device-change notifications cancel queued transfer without interrupting owned handles or reusing approval");

            OpenReadOnly(); int beforeFailure = dialogs;
            held = File.Open(Path.Combine(mountedLetter!+"\\","Transfer","hello.txt"),FileMode.Open,FileAccess.Read,FileShare.ReadWrite);
            OpenTransfer(); wait(() => status.Text.Contains("Close open files",StringComparison.Ordinal));
            ObserveHostFailure("SECTOR_DIAGNOSTIC read: error=simulated transfer-close failure");
            Require(transferAfterClose == null,"Terminal host failure kept transfer approval.");
            held.Dispose(); held = null; RequestUnmount(); wait(() => host == null);
            Require(dialogs == beforeFailure && status.Text.StartsWith("Host failed",StringComparison.Ordinal) && Hash(image) == original,
                "Failed close auto-started transfer or changed the source.");
            checks.Add("terminal host failure cancels queued transfer, retains failed-close reporting and refuses automatic writing");
        }
        finally
        {
            held?.Dispose(); transferAfterClose = null; CancelOpen();
            if (host != null) { RequestUnmount(); wait(() => host == null); }
            validationTransferConsent = null; validationTransferDialog = null;
            validationHost = oldHost; validationInventoryReader = oldInventory;
            validationPartitionReader = oldPartitions; validationVolumeReader = oldVolume;
            hostIoFailed = logFailed = startupRecoveryRequired = false; discoveryPending = false;
        }
    }
}
