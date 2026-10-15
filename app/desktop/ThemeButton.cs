using System.Drawing.Drawing2D;

namespace HfsBridge.Manager;

// A real WinForms Button: keyboard, accessibility and Click semantics are unchanged.
internal sealed class ThemeButton : Button
{
    private bool hover, pressed;
    internal bool PreserveDisabledColors;
    internal Image? SelectedIcon;
    internal bool UseSelectedIcon;
    internal void ClickForValidation() => OnClick(EventArgs.Empty);
    internal void HoverForValidation() => OnMouseEnter(EventArgs.Empty);
    internal ThemeButton() { DoubleBuffered = true; UseMnemonic = false; }
    protected override void OnMouseEnter(EventArgs e) { hover = true; Invalidate(); base.OnMouseEnter(e); }
    protected override void OnMouseLeave(EventArgs e) { hover = pressed = false; Invalidate(); base.OnMouseLeave(e); }
    protected override void OnMouseDown(MouseEventArgs e) { pressed = true; Invalidate(); base.OnMouseDown(e); }
    protected override void OnMouseUp(MouseEventArgs e) { pressed = false; Invalidate(); base.OnMouseUp(e); }
    protected override void OnPaint(PaintEventArgs e)
    {
        if (DesktopTheme.HighContrast) { base.OnPaint(e); return; }
        e.Graphics.SmoothingMode = SmoothingMode.AntiAlias;
        var rect = new Rectangle(0,0,Width-1,Height-1);
        using var shape = Rounded(rect,Math.Min(8,Height/8));
        Color fill = Enabled && pressed ? FlatAppearance.MouseDownBackColor : Enabled && hover ? FlatAppearance.MouseOverBackColor : BackColor;
        if (Enabled && BackColor == DesktopTheme.Accent && (hover || pressed))
            fill = pressed ? Color.FromArgb(45,201,181) : Color.FromArgb(102,248,223);
        using var brush = new SolidBrush(fill); e.Graphics.FillPath(brush,shape);
        if (FlatAppearance.BorderSize > 0) { using var pen = new Pen(FlatAppearance.BorderColor); e.Graphics.DrawPath(pen,shape); }
        var textSize = TextRenderer.MeasureText(Text,Font,Size.Empty,TextFormatFlags.NoPadding|TextFormatFlags.SingleLine|TextFormatFlags.NoPrefix);
        Image? artwork = UseSelectedIcon ? SelectedIcon ?? Image : Image;
        int icon = artwork == null ? 0 : Math.Clamp((int)(Height*.38),18,38), gap = icon == 0 || Text.Length == 0 ? 0 : Math.Max(8,Height/7);
        int width = Math.Min(textSize.Width,Math.Max(0,Width-icon-gap-20)), x = (Width-width-icon-gap)/2;
        if (artwork != null) { e.Graphics.DrawImage(artwork,new Rectangle(x,(Height-icon)/2,icon,icon)); x += icon+gap; }
        Color ink = Enabled || PreserveDisabledColors ? ForeColor : Color.FromArgb(133,162,181);
        TextRenderer.DrawText(e.Graphics,Text,Font,new Rectangle(x,0,width,Height),ink,
            TextFormatFlags.NoPadding|TextFormatFlags.NoPrefix|TextFormatFlags.SingleLine|TextFormatFlags.VerticalCenter|TextFormatFlags.EndEllipsis);
        if (Focused && ShowFocusCues) { using var focus = new Pen(DesktopTheme.Ink,2); e.Graphics.DrawRectangle(focus,4,4,Width-9,Height-9); }
    }
    protected override void Dispose(bool disposing) { if (disposing) SelectedIcon?.Dispose(); base.Dispose(disposing); }
    internal static GraphicsPath Rounded(Rectangle rect, int radius)
    {
        var path = new GraphicsPath(); int d = radius*2;
        path.AddArc(rect.X,rect.Y,d,d,180,90); path.AddArc(rect.Right-d,rect.Y,d,d,270,90);
        path.AddArc(rect.Right-d,rect.Bottom-d,d,d,0,90); path.AddArc(rect.X,rect.Bottom-d,d,d,90,90); path.CloseFigure(); return path;
    }
}
