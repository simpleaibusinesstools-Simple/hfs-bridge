namespace HfsBridge.Manager;

// The tray owns presentation only. The existing controllers keep disk ownership
// and are solely responsible for flushing and closing a mounted host.
internal sealed class DesktopTray : IDisposable
{
    private readonly Form window;
    private readonly Func<bool> active;
    private readonly Action closeDrive;
    private readonly Func<string> status;
    private readonly NotifyIcon icon;
    private readonly ContextMenuStrip menu = new();
    private readonly ToolStripMenuItem files, close;
    private bool disposed;
    private long nextCloseRetry;
    internal bool ExitPending { get; private set; }
    internal void CancelExit() => ExitPending = false;
    internal bool CanHide => !disposed && window.Owner == null;

    internal bool RetainOnClose(CloseReason reason)
    {
        if (!active()) return false;
        if (reason == CloseReason.UserClosing && CanHide) Hide();
        else RequestExit();
        return true;
    }

    internal DesktopTray(Form window, Func<bool> active, Action showFiles, Action closeDrive, Func<string> status)
    {
        this.window = window; this.active = active; this.closeDrive = closeDrive; this.status = status;
        var restore = new ToolStripMenuItem("Open HFS Bridge", null, (_, _) => Restore());
        files = new ToolStripMenuItem("Open drive in Explorer", null, (_, _) => showFiles());
        close = new ToolStripMenuItem("Close drive safely", null, (_, _) => closeDrive());
        var quit = new ToolStripMenuItem("Exit HFS Bridge", null, (_, _) => RequestExit());
        menu.Items.AddRange([restore, files, close, new ToolStripSeparator(), quit]);
        menu.Opening += (_, _) => { files.Enabled = close.Enabled = active(); };
        icon = new NotifyIcon { Icon = window.Icon ?? SystemIcons.Application, Text = "HFS Bridge", ContextMenuStrip = menu };
        icon.DoubleClick += (_, _) => Restore();
        window.Shown += (_, _) => icon.Visible = window.Owner == null;
        window.Resize += (_, _) => { if (window.Owner == null && window.WindowState == FormWindowState.Minimized) Hide(); };
    }

    internal void Hide()
    {
        if (!CanHide) return;
        icon.Visible = true; Update(); window.Hide();
    }

    internal void Restore()
    {
        if (disposed) return;
        CancelExit();
        window.Show(); window.WindowState = FormWindowState.Normal; window.Activate();
    }

    internal void RequestExit()
    {
        if (disposed) return;
        if (!active()) { window.Close(); return; }
        ExitPending = true; nextCloseRetry = Environment.TickCount64 + 1000; closeDrive();
        icon.ShowBalloonTip(5000, "Closing the drive safely", "Close files using the drive. HFS Bridge will exit after the drive has closed.", ToolTipIcon.Info);
    }

    internal void Update()
    {
        if (disposed) return;
        string text = "HFS Bridge · " + status(); icon.Text = text[..Math.Min(63, text.Length)];
        if (ExitPending && active() && Environment.TickCount64 >= nextCloseRetry)
        {
            nextCloseRetry = Environment.TickCount64 + 1000; closeDrive();
        }
        if (ExitPending && !active()) { ExitPending = false; window.Close(); }
    }

    public void Dispose()
    {
        if (disposed) return;
        disposed = true; icon.Visible = false; icon.Dispose(); menu.Dispose();
    }
}
