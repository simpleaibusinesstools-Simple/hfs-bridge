namespace HfsBridge.Manager;

internal sealed class StatusLight : Control
{
    internal StatusLight() { SetStyle(ControlStyles.SupportsTransparentBackColor,true); BackColor = Color.Transparent; DoubleBuffered = true; }
    protected override void OnPaint(PaintEventArgs e)
    { base.OnPaint(e); e.Graphics.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;
        using var brush = new SolidBrush(ForeColor); e.Graphics.FillEllipse(brush,1,1,Width-2,Height-2); }
}
