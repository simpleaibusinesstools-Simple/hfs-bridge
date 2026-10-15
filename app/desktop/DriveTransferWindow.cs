using System.Diagnostics;
using System.Globalization;
using System.Text;

namespace HfsBridge.Manager;

internal sealed class DriveTransferWindow : Form
{
    private readonly string binary;
    private readonly DriveWritePlan plan;
    private readonly TextBox source = new() { ReadOnly = true };
    private readonly Label target = new(), detail = new();
    private readonly Button choose = new ThemeButton(), copy = new ThemeButton(), close = new ThemeButton();
    private readonly ProgressBar progress = new() { Minimum = 0, Maximum = 100, Height = 18, AccessibleName = "Transfer progress" };
    private bool busy, failed;
    private string destination = "";
    internal string? VerifiedHash { get; private set; }
    internal bool Completed { get; private set; }
    internal string Destination => destination;
    internal Func<string, string, ProcessStartInfo>? ValidationStart;
    internal Func<string?>? ValidationSourcePicker;

    internal DriveTransferWindow(string executable, DriveWritePlan selection, bool chooseOnOpen = false)
    {
        binary = executable; plan = selection;
        Text = "HFS Bridge · Fast transfer"; StartPosition = FormStartPosition.CenterParent;
        var body = DesktopTheme.DialogFrame(this);
        DesktopTheme.Row(body, DesktopTheme.Text("Copy a large file", 20, true));
        DesktopTheme.Row(body, DesktopTheme.Text($"Windows → {plan.Disk.FriendlyName}\nYour original stays on Windows. Each copy is verified before completion.", 10, muted: true));
        DesktopTheme.Button(choose, "Choose file…");
        DesktopTheme.Row(body, DesktopTheme.Labeled("Windows file", DesktopTheme.Pair(DesktopTheme.Field(source, "Windows source file"), choose, 135)));
        target.AutoSize = true; target.MaximumSize = new Size(600, 0); target.Text = "A new transfer folder will be created on your drive.";
        DesktopTheme.Row(body, DesktopTheme.Labeled("Save on drive", target));
        DesktopTheme.Row(body, progress);
        detail.Text = "Choose a file to begin. Keep the drive connected until finished."; detail.AutoSize = true;
        detail.MaximumSize = new Size(600, 0); DesktopTheme.Row(body, detail);
        var actions = new FlowLayoutPanel { AutoSize = true, Dock = DockStyle.Top, WrapContents = true };
        DesktopTheme.Button(copy, "Start transfer", true); copy.Width = 165; copy.Enabled = false;
        DesktopTheme.Button(close, "Close"); close.Width = 110;
        actions.Controls.Add(copy); actions.Controls.Add(close); DesktopTheme.Row(body, actions);
        choose.Click += (_, _) => ChooseSource();
        if (chooseOnOpen) Shown += (_,_) => BeginInvoke((Action)ChooseSource);
        copy.Click += async (_, _) => await RunTransfer(); close.Click += (_, _) => Close();
        FormClosing += (_, args) => { if (busy) { args.Cancel = true; detail.Text = "Transfer is running. Wait for verification and safe close before leaving."; } };
    }
    private void ChooseSource()
    {
        if (busy || failed || IsDisposed) return;
        if (ValidationSourcePicker != null) { if (ValidationSourcePicker() is string selected) SelectSource(selected); return; }
        using var picker = new OpenFileDialog { Title = "Choose a Windows file to copy", CheckFileExists = true, Multiselect = false };
        if (picker.ShowDialog(this) == DialogResult.OK) SelectSource(picker.FileName);
    }

    internal void SelectSource(string path)
    {
        if (busy || failed) return;
        string full = Path.GetFullPath(path), name = Path.GetFileName(full);
        if (!File.Exists(full) || name.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0 || name.Length == 0) throw new IOException("Choose an ordinary Windows file.");
        source.Text = full;
        destination = $"/HFS Bridge Transfers {DateTime.Now:yyyy-MM-dd HHmmss} {Guid.NewGuid():N}/{name}";
        target.Text = destination; copy.Enabled = true; Completed = false; VerifiedHash = null;
        detail.Text = "Ready · keep the drive connected until the copy has been verified.";
    }

    private ProcessStartInfo StartInfo()
    {
        if (ValidationStart != null) return ValidationStart(source.Text, destination);
        var start = new ProcessStartInfo(Environment.ProcessPath!) { UseShellExecute = false, CreateNoWindow = true,
            RedirectStandardOutput = true, RedirectStandardError = true, StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8, WorkingDirectory = AppContext.BaseDirectory };
        foreach (string arg in new[] { "--binary", binary, "--transfer-session", plan.Encode(), source.Text, destination }) start.ArgumentList.Add(arg);
        return start;
    }

    internal async Task RunTransfer()
    {
        if (busy || failed || source.Text.Length == 0) return;
        busy = true; choose.Enabled = copy.Enabled = close.Enabled = false; progress.Value = 0; Completed = false;
        detail.Text = "Preparing source and checking drive…";
        var clock = Stopwatch.StartNew(); var updates = new Progress<TransferProgress>(item => {
            if (IsDisposed || Completed || failed) return;
            double fraction = item.Total == 0 ? 1 : (double)item.Bytes / item.Total;
            progress.Value = item.Phase switch { "copy" => Math.Clamp((int)(fraction * 75), 0, 75),
                "committing" => 75, "verify" => 75 + Math.Clamp((int)(fraction * 20), 0, 20), "verified" or "closed" => 95,
                _ => progress.Value };
            double mib = item.Bytes / 1048576.0, total = item.Total / 1048576.0;
            if (item.Phase == "copy") detail.Text = $"Copying · {mib:N1} / {total:N1} MiB · {mib / Math.Max(clock.Elapsed.TotalSeconds, .01):N1} MiB/s";
            else if (item.Phase == "committing") detail.Text = "Saving the completed file safely…";
            else if (item.Phase == "verify") detail.Text = $"Verifying saved copy · {mib:N1} / {total:N1} MiB";
            else if (item.Phase == "closed") detail.Text = "Copy verified · restoring drive availability…";
        });
        try
        {
            ProcessStartInfo start = StartInfo(); bool physical = ValidationStart == null;
            var result = await Task.Run(async () => {
                using var helper = Process.Start(start) ?? throw new IOException("The transfer helper did not start.");
                var errors = helper.StandardError.ReadToEndAsync();
                var protocol = new TransferProtocol(); string? line; string? invalid = null;
                while ((line = await helper.StandardOutput.ReadLineAsync()) != null)
                {
                    var item = TransferProgress.Parse(line);
                    if (item == null) { if (line.StartsWith("TRANSFER ", StringComparison.Ordinal)) invalid = "Invalid transfer progress."; continue; }
                    try { protocol.Accept(item); } catch (IOException protocolError) { invalid = protocolError.Message; continue; }
                    ((IProgress<TransferProgress>)updates).Report(item);
                }
                // Never time out, cancel or terminate a writer. Its supervisor
                // retains the source lock and disk state through clean close.
                await helper.WaitForExitAsync(); string error = await errors;
                if (helper.ExitCode != 0 || invalid != null || protocol.Hash == null || !protocol.Closed || physical && !protocol.Finished)
                    throw new IOException(invalid ?? (string.IsNullOrWhiteSpace(error) ? "Transfer did not finish safely. Check the drive before another write." : error.Trim()));
                return protocol.Hash;
            });
            VerifiedHash = result; Completed = true; progress.Value = 100;
            detail.Text = $"Complete · saved copy verified\n{destination}";
        }
        catch (Exception error) { failed = true; detail.Text = "Transfer stopped · " + error.Message; }
        finally { busy = false; choose.Enabled = !failed; copy.Enabled = false; close.Enabled = true; }
    }
}
