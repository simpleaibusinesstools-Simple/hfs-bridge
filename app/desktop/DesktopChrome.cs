using System.Runtime.InteropServices;

namespace HfsBridge.Manager;

// User-operated native chrome. Closing still goes through each form's safe lifecycle.
internal sealed class DesktopChrome : NativeWindow
{
    private readonly Form form;
    private DesktopChrome(Form window)
    {
        form = window;
        form.HandleCreated += (_, _) => AssignHandle(form.Handle);
        form.HandleDestroyed += (_, _) => ReleaseHandle();
    }
    internal static void Install(Form form, ReferencePanel header, Control brand, bool custom)
    {
        if (!custom) return;
        var chrome = new DesktopChrome(form);
        form.Disposed += (_, _) => GC.KeepAlive(chrome);
        void Drag(object? sender, MouseEventArgs args)
        { if (args.Button == MouseButtons.Left) { ReleaseCapture(); SendMessage(form.Handle,0xA1,2,0); } }
        header.MouseDown += Drag; brand.MouseDown += Drag;
        header.DoubleClick += (_, _) => Toggle(form); brand.DoubleClick += (_, _) => Toggle(form);
        var minimize = new ThemeButton(); var maximize = new ThemeButton(); var close = new ThemeButton();
        foreach (var button in new[] { minimize,maximize,close }) { DesktopTheme.Button(button,""); button.FlatAppearance.BorderSize = 0; }
        DesktopTheme.Icon(minimize,"subtract"); DesktopTheme.Icon(maximize,"square"); DesktopTheme.Icon(close,"dismiss");
        minimize.AccessibleName = "Minimize window"; maximize.AccessibleName = "Maximize or restore window"; close.AccessibleName = "Close window safely";
        minimize.Click += (_, _) => form.WindowState = FormWindowState.Minimized;
        maximize.Click += (_, _) => Toggle(form); close.Click += (_, _) => form.Close();
        close.FlatAppearance.MouseOverBackColor = Color.FromArgb(155,55,65);
        float width = header.DesignWidth;
        header.Place(minimize,width-254,14,78,54); header.Place(maximize,width-172,14,78,54); header.Place(close,width-88,14,78,54);
    }
    private static void Toggle(Form form)
    { form.MaximumSize = Screen.FromControl(form).WorkingArea.Size; form.WindowState = form.WindowState == FormWindowState.Maximized ? FormWindowState.Normal : FormWindowState.Maximized; }
    protected override void WndProc(ref Message message)
    {
        base.WndProc(ref message);
        if (message.Msg != 0x84 || message.Result != 1 || form.WindowState == FormWindowState.Maximized) return;
        long coordinates = message.LParam.ToInt64(); var point = form.PointToClient(new Point((short)coordinates,(short)(coordinates>>16)));
        int edge = Math.Max(6,form.DeviceDpi/16); bool left = point.X<edge, right = point.X>=form.Width-edge, top = point.Y<edge, bottom = point.Y>=form.Height-edge;
        message.Result = top ? left ? 13 : right ? 14 : 12 : bottom ? left ? 16 : right ? 17 : 15 : left ? 10 : right ? 11 : message.Result;
    }
    [DllImport("user32.dll")] private static extern bool ReleaseCapture();
    [DllImport("user32.dll")] private static extern nint SendMessage(nint window, uint message, nint wParam, nint lParam);
}

