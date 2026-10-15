using System.Diagnostics;
using System.Security.Principal;

namespace HfsBridge.Manager;

internal sealed class StartupSettingsWindow : Form
{
    internal StartupSettingsWindow(DiskItem? disk, DiskPartition? partition, string letter, bool writable)
    {
        Text = "HFS Bridge · Startup settings"; StartPosition = FormStartPosition.CenterParent;
        var content = DesktopTheme.DialogFrame(this);
        DesktopTheme.Row(content, DesktopTheme.Text("Your drive, ready at sign-in", 17, true));
        DesktopTheme.Row(content, DesktopTheme.Text(disk == null ? "Select a USB drive in HFS Bridge before enabling startup." : disk.FriendlyName, 10, true));
        DesktopTheme.Row(content, DesktopTheme.Text("HFS Bridge will start in the system tray and check the saved drive\nbefore opening it. Close drive safely from the tray when finished.", 9, muted: true));
        var changes = new CheckBox { Text = "Allow changes when this drive opens automatically", Checked = false,
            AutoSize = true, Margin = new Padding(0, 12, 0, 8), ForeColor = DesktopTheme.TextColor };
        DesktopTheme.Row(content, changes);
        DesktopTheme.Row(content, DesktopTheme.Text("One-time administrator setup installs a protected app copy and a\nsign-in task for your account. It does not store your password.\nSetup checks the drive read-only; it does not open it for writing.", 9, muted: true));
        var buttons = new FlowLayoutPanel { AutoSize = true, Dock = DockStyle.Top, Margin = new Padding(0, 16, 0, 0) };
        var enable = new ThemeButton { Width = 160, Enabled = disk is { External: true } };
        var disable = new ThemeButton { Width = 160 };
        DesktopTheme.Button(enable, "Enable startup", true); DesktopTheme.Button(disable, "Disable startup");
        buttons.Controls.Add(enable); buttons.Controls.Add(disable); DesktopTheme.Row(content, buttons);
        enable.Click += (_, _) =>
        {
            if (disk == null) return;
            using var identity = WindowsIdentity.GetCurrent();
            string sid = identity.User?.Value ?? throw new IOException("Missing Windows account identity.");
            Launch("--startup-setup", new StartupSelection(sid, disk.SerialNumber.Trim(), disk.Size, partition?.Number, letter, changes.Checked).Encode());
        };
        disable.Click += (_, _) => Launch("--startup-disable");
    }
    private void Launch(params string[] args)
    {
        try
        {
            var start = new ProcessStartInfo(Environment.ProcessPath!) { UseShellExecute = true, Verb = "runas", WorkingDirectory = AppContext.BaseDirectory };
            foreach (string arg in args) start.ArgumentList.Add(arg);
            using var process = Process.Start(start);
            if (process == null) throw new IOException("Administrator approval was not completed.");
            Close();
        }
        catch (Exception error) { MessageBox.Show(this, error.Message, "Startup settings", MessageBoxButtons.OK, MessageBoxIcon.Information); }
    }
}

