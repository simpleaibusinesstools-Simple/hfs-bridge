using System.Diagnostics;
using System.Text.Json;

namespace HfsBridge.Manager;

internal sealed partial class DriveWindow
{
    private void NotifyDeviceChangeForValidation(int change = DeviceNodesChanged)
    {
        var message = Message.Create(Handle, DeviceChangeMessage, change, 0);
        WndProc(ref message);
    }

    private Func<int> ValidateDiscovery(string directory, DriveInventory fixture, DiskInspection inspection,
        Action<bool> selectFixture, Action<Func<bool>> wait, List<string> checks)
    {
        void Require(bool value, string message) { if (!value) throw new IOException(message); }
        string connected = Path.Combine(directory, "discovery-connected.json"), empty = Path.Combine(directory, "discovery-empty.json");
        string protocol = Path.Combine(directory, "discovery-partitions.json");
        File.WriteAllText(connected, JsonSerializer.Serialize(fixture));
        File.WriteAllText(empty, JsonSerializer.Serialize(new DriveInventory([], [], false)));
        File.WriteAllText(protocol, JsonSerializer.Serialize(inspection));
        ProcessStartInfo FixtureReader(string path)
        {
            // A new regular JSON fixture only; no disk-management commands.
            var start = DriveInventory.StartInfo(); start.ArgumentList.Clear();
            foreach (string arg in new[] { "-NoLogo", "-NoProfile", "-NonInteractive", "-Command",
                "[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new($false); Get-Content -Raw -LiteralPath '" + path.Replace("'", "''", StringComparison.Ordinal) + "'" }) start.ArgumentList.Add(arg);
            return start;
        }
        string next = connected; int reads = 0;
        validationInventoryReader = () => { reads++; return FixtureReader(next); };
        void Settle()
        {
            discoveryDue = Environment.TickCount64 - 1;
            wait(() => !discoveryPending && readTask == null);
        }
        void RefusesReadiness() => Require(snapshot == null && volume == null && !consent.Checked && !mount.Enabled && !checkVolume.Enabled,
            "Device change retained filesystem readiness or confirmation.");

        selectFixture(true); NotifyDeviceChangeForValidation(0x1234);
        Require(mount.Enabled && !discoveryPending && reads == 0, "Unrelated device message changed drive readiness.");
        for (int i = 0; i < 16; i++) NotifyDeviceChangeForValidation();
        Poll(); RefusesReadiness();
        Require(reads == 0 && readTask == null && discoveryPending && disks.Items.Count == 0 && !inspect.Enabled,
            "Notification burst bypassed debounce or retained stale drives.");
        Settle();
        Require(reads == 1 && disks.Items.Count == 1 && disks.SelectedItem is DiskItem && !mount.Enabled && !consent.Checked,
            "Debounced reconnect failed or silently restored write consent.");
        for (int i = 0; i < 20; i++) Poll();
        Require(reads == 1, "Discovery keeps launching inventories without a new event.");
        checks.Add("Windows device-change dispatch coalesces bursts, ignores unrelated events, refreshes once and requires a fresh check and consent");

        // The earlier helper may finish after a disconnect. Its success must
        // not put that disappeared disk back into the list, even temporarily.
        RefreshInventory(); Require(readTask != null, "Inventory reader was not started.");
        next = empty; NotifyDeviceChangeForValidation(); discoveryDue = Environment.TickCount64 + 25000;
        wait(() => readTask == null);
        Require(inventory == null && disks.Items.Count == 0 && discoveryPending, "Stale inventory was applied after disconnect.");
        Settle(); Require(inventory != null && disks.Items.Count == 0 && !inspect.Enabled, "Disconnected device remained selectable.");
        next = connected;
        NotifyDeviceChangeForValidation(); Settle();
        Require(disks.Items.Count == 1 && !mount.Enabled && !consent.Checked, "Reconnected identical drive reused readiness.");
        checks.Add("disconnect discards a completed older inventory; reconnecting the same identity requires inspection again");

        selectFixture(true); CheckSelectedVolume(); NotifyDeviceChangeForValidation();
        discoveryDue = Environment.TickCount64 + 25000; wait(() => readTask == null); RefusesReadiness();
        Require(discoveryPending && inventory == null, "Stale passing filesystem check survived connection change.");
        Settle();
        selectFixture(false); inspectingDisk = fixture.Disks.Single();
        BeginRead(FixtureReader(protocol), ReadOperation.Partitions); NotifyDeviceChangeForValidation();
        discoveryDue = Environment.TickCount64 + 25000; wait(() => readTask == null); RefusesReadiness();
        Require(partitions.Items.Count == 0, "Stale partition token survived connection change.");
        Settle();
        checks.Add("connection changes during successful filesystem and partition helpers discard both old results before any mount can start");

        validationInventoryReader = () => { reads++; return NativeStart("unsupported-validation-command"); };
        NotifyDeviceChangeForValidation(); Settle(); RefusesReadiness();
        Require(inventory == null && readTask == null && refresh.Enabled, "Failed automatic inventory retained trust or blocked manual retry.");
        validationInventoryReader = () => { reads++; return FixtureReader(next); };
        RefreshInventory(); wait(() => readTask == null);
        Require(disks.Items.Count == 1 && !mount.Enabled, "Manual recovery after inventory failure failed.");
        checks.Add("failed automatic discovery leaves mounting unavailable; manual refresh recovers without restoring old approval");
        selectFixture(true);
        return () => reads;
    }
}
