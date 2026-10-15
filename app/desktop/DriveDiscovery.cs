namespace HfsBridge.Manager;

internal sealed partial class DriveWindow
{
    // Windows broadcasts this notification when the device tree changes.
    // It supplies no trustworthy disk identity: discard prior readiness and
    // query our existing read-only inventory after the notification burst.
    private const int DeviceChangeMessage = 0x0219, DeviceNodesChanged = 0x0007;
    private long deviceGeneration, readGeneration, discoveryDue;
    private bool discoveryPending, closing;

    protected override void WndProc(ref Message message)
    {
        if (message.Msg == DeviceChangeMessage && message.WParam == DeviceNodesChanged)
            DeviceConnectionsChanged();
        base.WndProc(ref message);
    }

    private void DeviceConnectionsChanged()
    {
        if (closing || IsDisposed || Disposing) return;
        deviceGeneration++;
        if (startupDiagnostics) StartupLog.Write($"Device change: host owned={host != null}; opening={openingReadOnly}.");
        discoveryPending = true;
        discoveryDue = Environment.TickCount64 + 500;
        if (transferAfterClose != null) { transferAfterClose = null; Append("Fast transfer canceled because drive connections changed."); }
        // A mounted host owns its disk handles until it exits normally. A
        // notification must never interrupt that ownership or start a reader.
        if (host != null || transferActive) return;
        CancelOpen();
        if (reconnectAttempt) CancelReconnect("Drive connections changed during reconnect checks; mount manually after inspection.");
        ClearSelection(); inventory = null; disks.Items.Clear();
        UpdateControls();
        status.Text = "Drive connections changed · refreshing the list…";
    }

    private void PollDiscovery()
    {
        if (!closing && !transferActive && discoveryPending && host == null && readTask == null && Environment.TickCount64 >= discoveryDue)
            RefreshInventory();
    }
}
