namespace HfsBridge.Manager;

// Retains the native combo popup, selection, keyboard and accessibility behavior.
internal sealed class ThemeComboBox : ComboBox
{
    private Image? arrow;
    internal ThemeComboBox()
    {
        if (!DesktopTheme.HighContrast) SetStyle(ControlStyles.UserPaint|ControlStyles.OptimizedDoubleBuffer,true);
        DrawMode = DrawMode.OwnerDrawFixed; DropDownStyle = ComboBoxStyle.DropDownList;
    }
    protected override void OnPaint(PaintEventArgs e)
    {
        if (DesktopTheme.HighContrast) { base.OnPaint(e); return; }
        e.Graphics.Clear(BackColor);
        string value = SelectedItem is DiskItem disk ? disk.FriendlyName : SelectedItem?.ToString() ?? "";
        TextRenderer.DrawText(e.Graphics,value,Font,new Rectangle(6,0,Math.Max(0,Width-38),Height),
            Enabled ? ForeColor : DesktopTheme.Muted,TextFormatFlags.NoPrefix|TextFormatFlags.VerticalCenter|TextFormatFlags.SingleLine|TextFormatFlags.EndEllipsis);
        arrow ??= DesktopTheme.Art("icon-chevron_down-light");
        int side = Math.Min(22,Height-8); e.Graphics.DrawImage(arrow,new Rectangle(Width-side-8,(Height-side)/2,side,side));
        if (Focused && ShowFocusCues) ControlPaint.DrawFocusRectangle(e.Graphics,new Rectangle(2,2,Width-5,Height-5),ForeColor,BackColor);
    }
    protected override void OnDrawItem(DrawItemEventArgs e)
    {
        if (e.Index >= 0)
        {
            bool selected = (e.State&DrawItemState.Selected)!=0;
            using var brush = new SolidBrush(selected ? DesktopTheme.HighContrast ? SystemColors.Highlight : Color.FromArgb(32,66,82) : DesktopTheme.Surface);
            e.Graphics.FillRectangle(brush,e.Bounds);
            string value = Items[e.Index] is DiskItem disk ? disk.FriendlyName : Items[e.Index]?.ToString() ?? "";
            TextRenderer.DrawText(e.Graphics,value,Font,e.Bounds,selected && DesktopTheme.HighContrast ? SystemColors.HighlightText : DesktopTheme.TextColor,TextFormatFlags.NoPrefix|TextFormatFlags.VerticalCenter|TextFormatFlags.EndEllipsis);
        }
        base.OnDrawItem(e);
    }
    protected override void OnSelectedIndexChanged(EventArgs e) { Invalidate(); base.OnSelectedIndexChanged(e); }
    protected override void OnEnabledChanged(EventArgs e) { Invalidate(); base.OnEnabledChanged(e); }
    protected override void Dispose(bool disposing) { if (disposing) arrow?.Dispose(); base.Dispose(disposing); }
}
