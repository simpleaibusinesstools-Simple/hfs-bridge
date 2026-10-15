using System.Drawing.Drawing2D;

namespace HfsBridge.Manager;

// Presentation only. Mounting, permissions and device ownership stay in the controllers.
internal static class DesktopTheme
{
    internal static Color Ink => HighContrast ? SystemColors.WindowText : Color.FromArgb(239, 247, 255);
    internal static Color Muted => HighContrast ? SystemColors.WindowText : Color.FromArgb(175, 202, 224);
    internal static Color Accent => HighContrast ? SystemColors.Highlight : Color.FromArgb(67, 233, 207);
    internal static Color Canvas => HighContrast ? SystemColors.Window : Color.FromArgb(12, 31, 44);
    internal static Color Line => HighContrast ? SystemColors.WindowText : Color.FromArgb(49, 83, 104);
    internal static bool HighContrast => SystemInformation.HighContrast;
    internal static Color Surface => HighContrast ? SystemColors.Window : Color.FromArgb(18, 43, 60);
    internal static Color TextColor => HighContrast ? SystemColors.WindowText : Ink;

    internal static Label Text(string value, float size = 10, bool bold = false, bool muted = false)
        => new() { Text = value, AutoSize = true, Dock = DockStyle.Top, BackColor = Color.Transparent,
            Font = new Font("Segoe UI", size, bold ? FontStyle.Bold : FontStyle.Regular),
            ForeColor = HighContrast ? SystemColors.WindowText : muted ? Muted : Ink,
            Margin = new Padding(0, 0, 0, 6), UseMnemonic = false };

    internal static TableLayoutPanel Stack(int gap = 10)
    {
        var stack = new TableLayoutPanel { AutoSize = true, AutoSizeMode = AutoSizeMode.GrowAndShrink, Dock = DockStyle.Top,
            ColumnCount = 1, Margin = new Padding(0, 0, 0, gap), BackColor = Color.Transparent };
        stack.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100)); return stack;
    }
    internal static void Row(TableLayoutPanel parent, Control child)
    {
        int row = parent.RowCount++; parent.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        child.Dock = DockStyle.Top; parent.Controls.Add(child, 0, row); child.TabIndex = row;
    }
    internal static TableLayoutPanel Pair(Control left, Control right, int rightWidth)
    {
        var row = new TableLayoutPanel { ColumnCount = 2, RowCount = 1, AutoSize = true,
            Dock = DockStyle.Top, Margin = new Padding(0, 0, 0, 16), BackColor = Color.Transparent };
        row.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100)); row.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, rightWidth));
        left.Dock = right.Dock = DockStyle.Top; left.Margin = new Padding(0, 0, 14, 0); right.Margin = Padding.Empty;
        row.Controls.Add(left, 0, 0); row.Controls.Add(right, 1, 0); right.TabIndex = 1; return row;
    }
    internal static TableLayoutPanel SettingsRow(Control letter, Control settings)
    {
        var row = Pair(letter, settings, 1); row.ColumnStyles[0] = new ColumnStyle(SizeType.Absolute, 140);
        row.ColumnStyles[1] = new ColumnStyle(SizeType.Percent, 100); return row;
    }
    internal static void Button(Button button, string label, bool primary = false)
    {
        button.Text = label.TrimStart('&'); button.UseMnemonic = false; button.Height = 48; button.MinimumSize = new Size(0, 38);
        button.FlatStyle = HighContrast ? FlatStyle.Standard : FlatStyle.Flat;
        button.FlatAppearance.BorderSize = primary ? 0 : 1; button.FlatAppearance.BorderColor = Line;
        button.FlatAppearance.MouseOverBackColor = primary ? Color.FromArgb(102, 248, 223) : Color.FromArgb(28, 61, 80);
        button.FlatAppearance.MouseDownBackColor = primary ? Color.FromArgb(45, 201, 181) : Color.FromArgb(33, 74, 94);
        button.BackColor = HighContrast ? SystemColors.Control : primary ? Accent : Surface;
        button.ForeColor = HighContrast ? SystemColors.ControlText : primary ? Color.FromArgb(4, 29, 37) : Ink;
        button.Font = new Font("Segoe UI", 11, FontStyle.Bold); button.Cursor = Cursors.Hand;
        button.UseVisualStyleBackColor = HighContrast; button.Margin = new Padding(0, 0, 12, 0);
        button.AccessibleName = label.Replace("&", "");
        if (!HighContrast)
        {
            void State() { button.BackColor = button.Enabled ? primary ? Accent : Surface : Color.FromArgb(29, 52, 68);
                button.ForeColor = button.Enabled ? primary ? Color.FromArgb(4, 29, 37) : Ink : Color.FromArgb(128, 157, 177); }
            button.EnabledChanged += (_, _) => State(); State();
        }
    }
    internal static Control Field(Control input, string name, string? placeholder = null)
    {
        input.AccessibleName = name; input.Font = new Font("Segoe UI", 11);
        input.ForeColor = TextColor; input.BackColor = Surface;
        var frame = new BorderedPanel { Height = 48, Dock = DockStyle.Top, Margin = Padding.Empty,
            Padding = new Padding(12, 10, 10, 6), BackColor = Surface };
        if (input is TextBox text) { text.BorderStyle = BorderStyle.None; text.PlaceholderText = placeholder ?? ""; }
        if (input is ComboBox combo) { combo.FlatStyle = FlatStyle.Flat; combo.DropDownStyle = ComboBoxStyle.DropDownList; }
        input.Dock = DockStyle.Fill; frame.Controls.Add(input);
        input.Enter += (_, _) => { frame.FocusBorder = true; frame.Invalidate(); };
        input.Leave += (_, _) => { frame.FocusBorder = false; frame.Invalidate(); }; return frame;
    }
    internal static TableLayoutPanel Labeled(string label, Control field)
    { var stack = Stack(12); Row(stack, Text(label, 10, true)); Row(stack, field); return stack; }
    internal static TableLayoutPanel Card(TableLayoutPanel content)
    {
        var card = new BorderedPanel { AutoSize = true, AutoSizeMode = AutoSizeMode.GrowAndShrink,
            Dock = DockStyle.Top, Padding = new Padding(24), Margin = new Padding(0, 0, 0, 18), BackColor = Surface };
        content.Margin = Padding.Empty; card.Controls.Add(content);
        var wrapper = Stack(0); Row(wrapper, card); return wrapper;
    }
    internal static TableLayoutPanel Frame(Form form, bool external, Button navigation)
    {
        form.SuspendLayout(); form.AutoScaleDimensions = new SizeF(96, 96); form.AutoScaleMode = AutoScaleMode.Dpi;
        form.Font = new Font("Segoe UI", 11); form.ForeColor = TextColor; form.BackColor = Canvas;
        form.ClientSize = new Size(1240, 880); form.MinimumSize = new Size(1000, 710);
        if (!HighContrast) form.FormBorderStyle = FormBorderStyle.None;
        var root = new ArtPanel { Dock = DockStyle.Fill, BackgroundImage = HighContrast ? null : Art("workspace-background"),
            BackgroundImageLayout = ImageLayout.Stretch };
        root.Disposed += (_, _) => root.BackgroundImage?.Dispose();
        var header = new ReferencePanel(1488, 82) { Dock = DockStyle.Top, BackColor = Color.Transparent };
        var brand = new BridgeBrand(); header.Place(brand, 36, 20, 218, 44);
        var current = new ThemeButton(); Button(current, external ? "Drives" : "Disk images"); current.TabStop = false;
        Button(navigation, external ? "Disk images" : "Drives");
        Icon(current, external ? "hard_drive" : "database", "mint"); Icon(navigation, external ? "database" : "hard_drive");
        foreach (var tab in new[] { current, navigation }) { tab.TextImageRelation = TextImageRelation.ImageBeforeText; tab.ImageAlign = ContentAlignment.MiddleLeft; tab.Padding = new Padding(16,0,8,0); tab.FlatAppearance.BorderSize = 0; }
        current.ForeColor = Accent; current.BackColor = Surface;
        header.Place(external ? current : navigation, 284, 15, 156, 65, 16);
        header.Place(external ? navigation : current, 461, 15, 204, 65, 16);
        var underline = new Panel { BackColor = Accent }; header.Place(underline, external ? 288 : 465, 77, external ? 147 : 190, 3);
        var startup = new ThemeButton(); Button(startup, "Startup"); Icon(startup, "settings"); startup.FlatAppearance.BorderSize = 0;
        startup.TextImageRelation = TextImageRelation.ImageBeforeText; header.Place(startup, 971, 18, 146, 52, 14);
        startup.Click += (_, _) => { if (form is DriveWindow window) window.ShowStartupFromHeader(); else using (var settings = new StartupSettingsWindow(null, null, "Z:", false)) settings.ShowDialog(form); };
        var tray = new ThemeButton(); Button(tray, ""); Icon(tray, "hard_drive"); tray.FlatAppearance.BorderSize = 0;
        tray.AccessibleName = "Minimize to system tray"; header.Place(tray, 1143, 18, 66, 52);
        form.Shown += (_, _) => tray.Enabled = form.Owner == null;
        tray.Click += (_, _) => { if (form.Owner == null) form.WindowState = FormWindowState.Minimized; };
        DesktopChrome.Install(form, header, brand, !HighContrast);
        var divider = new Panel { Dock = DockStyle.Bottom, Height = 1, BackColor = Line }; header.Controls.Add(divider);
        var footer = new TableLayoutPanel { Dock = DockStyle.Bottom, AutoSize = true, AutoSizeMode = AutoSizeMode.GrowAndShrink, Height = 82, ColumnCount = 2,
            BackColor = Color.Transparent, Padding = new Padding(44, 8, 32, 8), Margin = Padding.Empty };
        footer.ColumnStyles.Add(new ColumnStyle(SizeType.Percent,100)); footer.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        footer.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        var credit = new LinkLabel { Text = "Powered by WinFsp", AutoSize = true, Anchor = AnchorStyles.Left, Font = new Font("Segoe UI", 11),
            LinkColor = HighContrast ? SystemColors.HotTrack : Muted, ActiveLinkColor = Accent, LinkBehavior = LinkBehavior.HoverUnderline, BackColor = Color.Transparent };
        credit.LinkClicked += (_, _) => System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo("https://github.com/winfsp/winfsp") { UseShellExecute = true });
        footer.Controls.Add(credit,0,0); footer.Controls.Add(Publisher(form),1,0);
        var scroll = new ArtPanel { Dock = DockStyle.Fill, AutoScroll = true, BackColor = Color.Transparent,
            Padding = new Padding(52, 30, 52, 8) };
        var main = Stack(0); scroll.Controls.Add(main);
        root.Controls.Add(scroll); root.Controls.Add(footer); root.Controls.Add(header); form.Controls.Add(root);
        void SizeWorkspace()
        {
            float scale = form.ClientSize.Width/1488f;
            scroll.Padding = new Padding((int)(52*scale),(int)(30*scale),(int)(52*scale),8);
            footer.MinimumSize = new Size(0,(int)(82*scale));
        }
        form.ClientSizeChanged += (_,_) => SizeWorkspace(); form.Shown += (_,_) => SizeWorkspace();
        form.Shown += (_,_) => FitToWorkArea(form);
        form.ResumeLayout(true); return main;
    }
    private static TableLayoutPanel Publisher(Form form)
    {
        var footer = new TableLayoutPanel { AutoSize = true, AutoSizeMode = AutoSizeMode.GrowAndShrink,
            ColumnCount = 2, RowCount = 1, Anchor = AnchorStyles.Right, Margin = Padding.Empty, BackColor = Color.Transparent };
        footer.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize)); footer.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        using var resource = typeof(DesktopTheme).Assembly.GetManifestResourceStream("HfsBridge.Manager.SimpleAiLogo") ?? throw new IOException("Missing publisher logo.");
        using var original = Image.FromStream(resource); var logo = new Bitmap(original);
        var picture = new PictureBox { Image = logo, SizeMode = PictureBoxSizeMode.Zoom, Size = new Size(68,48),
            Margin = new Padding(0,0,12,0), Anchor = AnchorStyles.Left, AccessibleName = "SimpleAI Tools logo", TabStop = false, BackColor = Color.Transparent };
        picture.Disposed += (_,_) => logo.Dispose(); footer.Controls.Add(picture,0,0);
        var words = Stack(0); words.Dock = DockStyle.None; words.Anchor = AnchorStyles.Left; words.Margin = Padding.Empty;
        var name = Text("SimpleAI Tools",10,true); name.Margin = new Padding(0,0,0,2);
        var copyright = Text($"© {DateTime.Now.Year}",9,muted:true); copyright.Margin = Padding.Empty;
        copyright.AccessibleName = "SimpleAI Tools copyright"; Row(words,name); Row(words,copyright); footer.Controls.Add(words,1,0);
        var clock = new System.Windows.Forms.Timer { Interval = 60_000 }; clock.Tick += (_,_) => copyright.Text = $"© {DateTime.Now.Year}";
        form.Shown += (_,_) => { copyright.Text = $"© {DateTime.Now.Year}"; clock.Start(); }; form.Disposed += (_,_) => clock.Dispose(); return footer;
    }
    internal static void Status(TableLayoutPanel main, Label status)
    {
        status.AutoSize = true; status.ForeColor = TextColor; status.Font = new Font("Segoe UI",11,FontStyle.Bold);
        status.Margin = Padding.Empty; status.AccessibleName = "Drive status";
        var card = Stack(0); Row(card,status); Row(main,Card(card));
        status.TextChanged += (_,_) => status.ForeColor = Failure(status.Text) && !HighContrast ? Color.FromArgb(255,186,151) : TextColor;
    }
    internal static bool Failure(string value) => new[] { "failed", "could not", "error", "before trying", "check the drive" }.Any(x => value.Contains(x,StringComparison.OrdinalIgnoreCase));
    internal static Control ActivityPanel(TextBox log)
    {
        log.Multiline = true; log.ReadOnly = true; log.ScrollBars = ScrollBars.Vertical; log.BorderStyle = BorderStyle.None;
        log.BackColor = Surface; log.ForeColor = TextColor; log.Font = new Font("Segoe UI",10); log.AccessibleName = "Activity log";
        var frame = new BorderedPanel { Padding = new Padding(16), Height = 130, Dock = DockStyle.Top, BackColor = Surface };
        log.Dock = DockStyle.Fill; frame.Controls.Add(log); return frame;
    }
    internal static void Activity(TableLayoutPanel main, TextBox log)
    { Row(main,Text("ACTIVITY",9,true,true)); Row(main,ActivityPanel(log)); }
    internal static Image Art(string name)
    {
        using var stream = typeof(DesktopTheme).Assembly.GetManifestResourceStream("HfsBridge.Manager.Art."+name+".png") ?? throw new IOException("Missing visual asset: "+name);
        using var original = Image.FromStream(stream); return new Bitmap(original);
    }
    internal static TableLayoutPanel DialogFrame(Form form)
    {
        form.AutoScaleDimensions = new SizeF(96,96); form.AutoScaleMode = AutoScaleMode.Dpi;
        form.ForeColor = TextColor; form.BackColor = Canvas; form.Font = new Font("Segoe UI",11);
        form.ClientSize = new Size(860,660); form.MinimumSize = new Size(780,620);
        if (!HighContrast) form.FormBorderStyle = FormBorderStyle.None;
        var root = new ArtPanel { Dock = DockStyle.Fill, BackgroundImage = HighContrast ? null : Art("workspace-background"), BackgroundImageLayout = ImageLayout.Stretch };
        root.Disposed += (_,_) => root.BackgroundImage?.Dispose();
        var header = new ReferencePanel(860,70) { Dock = DockStyle.Top };
        var brand = new BridgeBrand(); header.Place(brand,28,16,218,44); DesktopChrome.Install(form,header,brand,!HighContrast);
        var scroll = new ArtPanel { Dock = DockStyle.Fill, AutoScroll = true, Padding = new Padding(28,18,28,12), BackColor = Color.Transparent };
        var body = Stack(0); scroll.Controls.Add(body);
        var footer = new Panel { Dock = DockStyle.Bottom, Height = 64, Padding = new Padding(28,8,28,8), BackColor = Color.Transparent };
        var publisher = Publisher(form); publisher.Dock = DockStyle.Right; footer.Controls.Add(publisher);
        root.Controls.Add(scroll); root.Controls.Add(footer); root.Controls.Add(header); form.Controls.Add(root); form.Shown += (_,_) => FitToWorkArea(form); return body;
    }
    private static void FitToWorkArea(Form form)
    {
        if (form.Location.X < -10000) return; // Offscreen renderer only.
        Rectangle area = Screen.FromControl(form).WorkingArea;
        int width = Math.Max(1,area.Width-16), height = Math.Max(1,area.Height-16);
        form.MinimumSize = new Size(Math.Min(form.MinimumSize.Width,width),Math.Min(form.MinimumSize.Height,height));
        form.Size = new Size(Math.Min(form.Width,width),Math.Min(form.Height,height));
        form.Location = new Point(Math.Clamp(form.Left,area.Left,area.Right-form.Width),Math.Clamp(form.Top,area.Top,area.Bottom-form.Height));
    }
    internal static void Icon(Button button, string name, string variant = "light")
    {
        Image original = Art("icon-"+name+"-"+variant); var image = new Bitmap(original,new Size(26,26)); original.Dispose();
        button.Image = image; button.Disposed += (_,_) => image.Dispose();
        button.TextImageRelation = TextImageRelation.ImageBeforeText;
    }
    internal static PictureBox Picture(string name)
    {
        var picture = new PictureBox { Image = Art(name), SizeMode = PictureBoxSizeMode.Zoom, BackColor = Color.Transparent, TabStop = false };
        picture.Disposed += (_,_) => picture.Image?.Dispose(); return picture;
    }
    internal sealed class BorderedPanel : Panel
    {
        internal bool FocusBorder;
        internal BorderedPanel() => DoubleBuffered = true;
        protected override void OnPaint(PaintEventArgs e)
        { base.OnPaint(e); using var pen = new Pen(HighContrast ? SystemColors.WindowText : FocusBorder ? Accent : Line,FocusBorder ? 2 : 1);
            using var border = ThemeButton.Rounded(new Rectangle(0,0,Math.Max(1,Width-1),Math.Max(1,Height-1)),6);
            e.Graphics.SmoothingMode = SmoothingMode.AntiAlias; e.Graphics.DrawPath(pen,border); }
    }
    internal sealed class ArtPanel : Panel { internal ArtPanel() => DoubleBuffered = true; }
    private sealed class BridgeBrand : Control
    {
        internal BridgeBrand() { SetStyle(ControlStyles.SupportsTransparentBackColor,true); DoubleBuffered = true; BackColor = Color.Transparent; AccessibleName = "HFS Bridge"; }
        protected override void OnPaint(PaintEventArgs e)
        {
            base.OnPaint(e); e.Graphics.SmoothingMode = SmoothingMode.AntiAlias;
            float s = Height / 44f; e.Graphics.ScaleTransform(s,s);
            // Preserve the existing approved HFS Bridge mark exactly.
            using var fill = new SolidBrush(HighContrast ? SystemColors.Highlight : Color.FromArgb(87,209,182));
            e.Graphics.FillRectangle(fill,0,3,12,20); e.Graphics.FillRectangle(fill,17,14,12,20);
            using var stroke = new Pen(fill,3); e.Graphics.DrawLine(stroke,9,14,20,23);
            using var font = new Font("Segoe UI",21*96/DeviceDpi,FontStyle.Bold);
            e.Graphics.DrawString("HFS Bridge",font,HighContrast ? SystemBrushes.ControlText : Brushes.White,47,1);
        }
    }
}

// Reference-sized coordinates are only presentation; the scale tracks window/DPI size.
internal sealed class ReferencePanel : Panel
{
    private readonly float referenceWidth, referenceHeight;
    private readonly List<(Control Control, RectangleF Bounds, float? Font)> items = [];
    private bool layingOut;
    internal float DesignWidth => referenceWidth;
    internal ReferencePanel(float width, float height) { referenceWidth = width; referenceHeight = height; DoubleBuffered = true; BackColor = Color.Transparent; Margin = Padding.Empty; }
    internal void Place(Control control, float x, float y, float width, float height, float? font = null)
    { control.Dock = DockStyle.None; control.Margin = Padding.Empty; items.Add((control,new RectangleF(x,y,width,height),font)); Controls.Add(control); PerformLayout(); }
    protected override void OnLayout(LayoutEventArgs e)
    {
        base.OnLayout(e); if (layingOut || Width < 10) return; layingOut = true;
        try
        {
            float s = Width / referenceWidth; Height = (int)Math.Ceiling(referenceHeight*s);
            foreach (var item in items)
            {
                var b = item.Bounds; item.Control.SetBounds((int)(b.X*s),(int)(b.Y*s),(int)(b.Width*s),(int)(b.Height*s));
                if (item.Font is float points)
                {
                    float size = Math.Max(9,points*s)*96/DeviceDpi; if (Math.Abs(item.Control.Font.Size-size)>.2f)
                    { var old = item.Control.Font; item.Control.Font = new Font("Segoe UI",size,old.Style); }
                }
            }
        }
        finally { layingOut = false; }
    }
}

