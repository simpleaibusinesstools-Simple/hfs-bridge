using System.Security.Principal;

namespace HfsBridge.Manager;

internal sealed partial class DriveWindow
{
    private sealed record ReconnectTarget(DiskItem Disk, DiskPartition Partition, string Letter);
    private ReconnectTarget? reconnectTarget, pendingReconnectTarget;
    private bool reconnectSawAbsent, reconnectAttempt;
    private long reconnectGeneration;

    private void CancelReconnect(string? reason = null)
    {
        reconnectTarget = pendingReconnectTarget = null;
        reconnectSawAbsent = reconnectAttempt = false;
        consent.Checked = false;
        reconnect.Checked = false;
        if (reason != null) { Append(reason); status.Text = reason; }
    }

    private void ArmReconnect()
    {
        if (!reconnect.Checked || pendingReconnectTarget == null) return;
        reconnectTarget = pendingReconnectTarget; pendingReconnectTarget = null;
        reconnectSawAbsent = reconnectAttempt = false;
        Append($"Reconnect mounting enabled for {reconnectTarget.Disk.FriendlyName}, partition {reconnectTarget.Partition.Number}, at {reconnectTarget.Letter}. Keep this window open; unmount before disconnecting.");
    }

    private void AdvanceReconnect(ReadOperation completed)
    {
        if (!reconnect.Checked || closing || host != null || discoveryPending || readTask != null || reconnectTarget == null) return;
        try
        {
            var target = reconnectTarget;
            if (completed == ReadOperation.Inventory)
            {
                if (inventory == null) return;
                var matches = inventory.Disks.Where(d => d.External && d.SerialNumber.Trim() == target.Disk.SerialNumber.Trim()).ToArray();
                if (matches.Length == 0) { reconnectSawAbsent = true; return; }
                // A refresh or device message while the drive remains attached
                // must never undo the user's deliberate Unmount action.
                if (!reconnectSawAbsent) return;
                if (matches.Length != 1 || matches[0] != target.Disk || inventory.ParagonActive)
                    throw new IOException("Drive identity or eligibility changed. Inspect and mount it manually.");
                if (validationPartitionReader == null)
                {
                    using var identity = WindowsIdentity.GetCurrent();
                    if (!new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator))
                        throw new IOException("Reconnect mounting needs an existing administrator window. Inspect the drive manually.");
                }
                reconnectAttempt = true; reconnectSawAbsent = false; reconnectGeneration = deviceGeneration;
                disks.SelectedItem = matches[0]; ClearSelection(); inspectingDisk = matches[0];
                string[] args = ["disk-inspect", matches[0].Number.ToString(System.Globalization.CultureInfo.InvariantCulture), "--json"];
                BeginRead(validationPartitionReader == null ? NativeStart(args) : validationPartitionReader(args), ReadOperation.Partitions);
            }
            else if (reconnectAttempt)
            {
                if (reconnectGeneration != deviceGeneration || inventory == null || snapshot == null || disks.SelectedItem is not DiskItem disk || disk != target.Disk)
                    throw new IOException("Reconnect selection changed. Inspect and mount manually.");
                if (completed == ReadOperation.Partitions)
                {
                    var part = snapshot.Partitions.SingleOrDefault(p => p == target.Partition);
                    if (part == null || snapshot.Refusal(inventory, disk, part, true) is string)
                        throw new IOException("The saved partition identity or write eligibility changed. Inspect and mount manually.");
                    partitions.SelectedItem = part;
                    CheckSelectedVolume();
                    if (readTask == null) throw new IOException("Reconnect filesystem check did not start.");
                }
                else if (completed == ReadOperation.Volume)
                {
                    if (VolumeRefusal() is string refusal) throw new IOException(refusal);
                    RefreshLetters();
                    if (!letters.Items.Contains(target.Letter)) throw new IOException("The remembered drive letter is in use. Choose a free letter and mount manually.");
                    letters.SelectedItem = target.Letter;
                    // Only the session target armed by an acknowledged manual
                    // mount can supply this confirmation, after fresh checks.
                    consent.Checked = true; reconnectAttempt = false;
                    Append("Reconnect identity and filesystem checks passed; mounting the confirmed drive.");
                    StartMount();
                }
            }
        }
        catch (Exception error) { CancelReconnect(error.Message); UpdateControls(); status.Text = error.Message; }
    }
}
