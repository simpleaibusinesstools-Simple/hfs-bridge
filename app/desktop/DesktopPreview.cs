using System.Drawing.Imaging;
using System.Text.Json;

namespace HfsBridge.Manager;

// Off-screen rendering of our own controls. A transparent, off-desktop window
// realizes the WinForms controls, without hosts or physical-device discovery.
internal static class DesktopPreview
{
    internal static int Render(string binary, string directory)
    {
        if (Directory.Exists(directory) || File.Exists(directory)) throw new IOException("Use a new preview directory.");
        Directory.CreateDirectory(directory);
        var reports = new List<object>();
        foreach (string screen in new[] { "disk-images", "external-drives", "startup-settings", "fast-transfer", "empty", "mounted", "busy", "error", "writable", "hover" })
        foreach (string size in screen is "mounted" or "busy" or "error" or "writable" or "hover" ? new[] { "default" } : new[] { "default", "compact", "large-text" })
        {
            using Form form = screen is "external-drives" or "empty" or "mounted" or "busy" or "error" or "writable" or "hover" ? new DriveWindow(binary, preview: true) :
                screen == "fast-transfer" ? new DriveTransferWindow(binary,
                    new DriveWritePlan(new DiskItem(3, "Example Mac drive", "USB", 32_000_000_000, "EXAMPLE", 512, 512, false, false, false, false),
                        new DiskPartition(2, "Mac files", 16777216, 31_000_000_000, true, true, new string('A', 64)), "Z:")) :
                screen == "startup-settings" ? new StartupSettingsWindow(new DiskItem(3, "Example USB drive", "USB", 32_000_000_000,
                    "EXAMPLE", 512, 512, false, false, false, false), null, "Z:", false) : new ManagerWindow(binary, preview: true);
            if (form is DriveWindow drive) drive.PreviewWorkspace(screen == "external-drives" ? "ready" : screen);
            if (screen == "external-drives") { form.MaximumSize = Size.Empty; form.ClientSize = new Size(1488,1056); }
            form.StartPosition = FormStartPosition.Manual; form.Location = new Point(-32000, -32000);
            form.ShowInTaskbar = false; form.Opacity = 0;
            if (size == "compact") form.Size = form.MinimumSize;
            if (size == "large-text")
            {
                var fonts = Enumerate(form).Select(c => (Control: c, Font: c.Font)).ToArray();
                form.Scale(new SizeF(1.5f, 1.5f));
                foreach (var item in fonts) item.Control.Font = new Font(item.Font.FontFamily, item.Font.Size * 1.5f, item.Font.Style);
            }
            form.Show();
            if (screen == "external-drives" && size == "default") form.ClientSize = new Size(1488,1056);
            if (size == "compact") form.Size = form.MinimumSize;
            Layout(form);
            string name = screen + "-" + size;
            using var bitmap = new Bitmap(form.Width, form.Height);
            form.DrawToBitmap(bitmap, new Rectangle(Point.Empty, bitmap.Size));
            bitmap.Save(Path.Combine(directory, name + ".png"), ImageFormat.Png);
            var controls = Enumerate(form).Where(c => c is Button or TextBox or ComboBox or CheckBox or Label)
                .Select(c => new { Type = c.GetType().Name, c.Text, c.AccessibleName, c.Enabled, c.TabIndex,
                    X = c.Left, Y = c.Top, c.Width, c.Height, ParentWidth = c.Parent?.ClientSize.Width,
                    ParentHeight = c.Parent?.ClientSize.Height }).ToArray();
            reports.Add(new { Name = name, form.Width, form.Height, form.DeviceDpi, Controls = controls });
            if (size is "compact" or "large-text")
            {
                foreach (var scroll in Enumerate(form).OfType<Panel>().Where(panel => panel.AutoScroll && panel.VerticalScroll.Visible))
                    scroll.AutoScrollPosition = new Point(0,int.MaxValue);
                Layout(form);
                using var lower = new Bitmap(form.Width,form.Height); form.DrawToBitmap(lower,new Rectangle(Point.Empty,lower.Size));
                lower.Save(Path.Combine(directory,name+"-bottom.png"),ImageFormat.Png);
            }
            form.Close();
        }
        File.WriteAllText(Path.Combine(directory, "layout.json"), JsonSerializer.Serialize(new {
            OffscreenOnly = true, HostsStarted = false, PhysicalDrivesAccessed = false, Screens = reports
        }, new JsonSerializerOptions { WriteIndented = true }));
        return 0;
    }
    private static IEnumerable<Control> Enumerate(Control parent)
    {
        foreach (Control child in parent.Controls) { yield return child; foreach (Control item in Enumerate(child)) yield return item; }
    }
    private static void Layout(Control parent)
    {
        foreach (Control child in parent.Controls) { child.CreateControl(); Layout(child); }
        parent.PerformLayout();
    }
}
