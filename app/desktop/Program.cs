using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;

namespace HfsBridge.Manager;

internal static class Program
{
    [STAThread]
    private static int Main(string[] args)
    {
        if (args.Length == 4 && args[0] == "--binary" && args[2] == "--write-session")
            return DriveWriteSession.RunPhysical(args[1], args[3]);
        if (args is ["--binary", var transferBinary, "--transfer-session", var transferPlan, var transferSource, var transferDestination])
            return DriveTransferSession.RunPhysical(transferBinary, transferPlan, transferSource, transferDestination);
        ApplicationConfiguration.Initialize();
        if (args is ["--startup-setup", var encodedSelection] || args is ["--startup-disable"])
        {
            try
            {
                if (args.Length == 2) StartupInstall.Enable(args[1]); else StartupInstall.Disable();
                MessageBox.Show(args.Length == 2 ? "Startup enabled. HFS Bridge will open the saved drive in the system tray when you next sign in." : "Startup disabled. The current drive session is unchanged.",
                    "HFS Bridge", MessageBoxButtons.OK, MessageBoxIcon.Information); return 0;
            }
            catch (Exception error) { MessageBox.Show(error.Message, "Startup settings", MessageBoxButtons.OK, MessageBoxIcon.Error); return 1; }
        }
        string binary = Path.Combine(AppContext.BaseDirectory, "bin", "hfs-bridge.exe");
        string? workflow = null;
        string? previews = null;
        string? driveWorkflow = null, protocolFixture = null, physicalInspection = null;
        bool drives = false, images = false, startup = false;
        DriveOpenRequest? openRequest = null;
        for (int i = 0; i < args.Length; i++)
        {
            if (args[i] == "--binary" && i + 1 < args.Length) binary = Path.GetFullPath(args[++i]);
            else if (args[i] == "--validate-workflow" && i + 1 < args.Length) workflow = Path.GetFullPath(args[++i]);
            else if (args[i] == "--drives") drives = true;
            else if (args[i] == "--images") images = true;
            else if (args[i] == "--startup") startup = true;
            else if (args[i] is "--open-drive" or "--open-drive-writable" or "--transfer-drive" && i + 3 < args.Length)
            {
                bool transfer = args[i] == "--transfer-drive", writable = transfer || args[i] == "--open-drive-writable";
                if (!uint.TryParse(args[++i], out uint number) || number > 4095) return 2;
                string serial = args[++i];
                if (string.IsNullOrWhiteSpace(serial) || serial.Length > 256 || !ulong.TryParse(args[++i], out ulong size) || size == 0) return 2;
                openRequest = new DriveOpenRequest(number, serial, size, writable, transfer); drives = true;
            }
            else if (args[i] == "--validate-drive-workflow" && i + 1 < args.Length) driveWorkflow = Path.GetFullPath(args[++i]);
            else if (args[i] == "--protocol-fixture" && i + 1 < args.Length) protocolFixture = Path.GetFullPath(args[++i]);
            else if (args[i] == "--physical-inspection" && i + 1 < args.Length) physicalInspection = Path.GetFullPath(args[++i]);
            else if (args[i] == "--render-previews" && i + 1 < args.Length) previews = Path.GetFullPath(args[++i]);
            else return 2;
        }
        try
        {
            if (startup)
            {
                if (args.Length != 1) return 2;
                StartupLog.Write("Starting automatic drive session.");
                using var automatic = new DriveWindow(binary, automaticProfile: StartupProfile.LoadInstalled(), startInTray: true);
                Application.Run(automatic); return 0;
            }
            if (images && drives || openRequest != null && (workflow != null || driveWorkflow != null || previews != null)) return 2;
            if (previews != null) { if (workflow != null || driveWorkflow != null || drives || protocolFixture != null || physicalInspection != null) return 2; return DesktopPreview.Render(binary, previews); }
            if (driveWorkflow != null) { if (workflow != null || drives || protocolFixture == null) return 2; using var driveWindow = new DriveWindow(binary); return driveWindow.ValidateWorkflow(driveWorkflow, protocolFixture, physicalInspection); }
            if (protocolFixture != null || physicalInspection != null) return 2;
            if (drives || !images && workflow == null)
            {
                if (workflow != null) return 2;
                using var driveWindow = new DriveWindow(binary, openRequest: openRequest); Application.Run(driveWindow);
                if (driveWindow.ReturnToImages) { using var imageWindow = new ManagerWindow(binary); Application.Run(imageWindow); }
                return 0;
            }
            using var manager = new ManagerWindow(binary);
            if (workflow != null) return manager.ValidateWorkflow(workflow);
            Application.Run(manager);
            return 0;
        }
        catch (Exception error)
        {
            if (previews != null) File.WriteAllText(Path.Combine(Path.GetDirectoryName(previews)!, "preview-error.log"), error.ToString());
            if (startup) StartupLog.Write("Startup failed: " + error);
            if (workflow == null && driveWorkflow == null && previews == null) MessageBox.Show(error.Message, "HFS Bridge", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return 1;
        }
    }
}

internal sealed partial class ManagerWindow : Form
{
    private readonly string binary;
    private readonly TextBox source = new(), output = new(), partition = new(), log = new();
    private readonly ComboBox letters = new ThemeComboBox();
    private readonly Button browse = new ThemeButton(), choose = new ThemeButton(), inspect = new ThemeButton(), mount = new ThemeButton(), unmount = new ThemeButton(), drives = new ThemeButton();
    private readonly Label status = new();
    private readonly System.Windows.Forms.Timer timer = new() { Interval = 100 };
    private readonly DesktopTray? tray;
    private Process? host, inspection;
    private Task<string?>? hostOut, hostErr;
    private Task<string>? inspectionOut, inspectionErr;
    private DateTime inspectionDeadline;
    private bool hostLogFailed;

    internal ManagerWindow(string executable, bool preview = false)
    {
        binary = Path.GetFullPath(executable);
        if (!File.Exists(binary)) throw new FileNotFoundException("The native HFS Bridge executable is missing.", binary);
        BuildLayout();
        if (!preview) tray = new DesktopTray(this, () => host != null,
            () => { if (letters.SelectedItem is string letter) System.Diagnostics.Process.Start(new ProcessStartInfo("explorer.exe", letter + "\\") { UseShellExecute = true }); },
            RequestUnmount, () => status.Text);
        browse.Click += (_, _) => BrowseSource(); choose.Click += (_, _) => ChooseOutput();
        inspect.Click += (_, _) => InspectImage(); mount.Click += (_, _) => StartMount(); unmount.Click += (_, _) => RequestUnmount();
        drives.Click += (_, _) => { using var window = new DriveWindow(binary); window.ShowDialog(this); };
        timer.Tick += (_, _) => PollHost();
        RefreshLetters(); if (!preview) timer.Start();
    }
    private void Append(string text)
    {
        log.AppendText(text.TrimEnd() + Environment.NewLine);
        if (log.TextLength > 200000) log.Text = log.Text[^100000..];
    }
    private void RefreshLetters()
    {
        string? previous = letters.SelectedItem as string;
        var used = new HashSet<string>(Directory.GetLogicalDrives().Select(p => p[..2]), StringComparer.OrdinalIgnoreCase);
        letters.Items.Clear();
        for (char c = 'Z'; c >= 'D'; c--) if (!used.Contains(c + ":")) letters.Items.Add(c + ":");
        if (previous != null && letters.Items.Contains(previous)) letters.SelectedItem = previous;
        else if (letters.Items.Count != 0) letters.SelectedIndex = 0;
    }
    private Process StartProcess(params string[] arguments)
    {
        var start = new ProcessStartInfo(binary) { WorkingDirectory = Path.GetDirectoryName(binary)!, UseShellExecute = false, CreateNoWindow = true, RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true };
        foreach (string argument in arguments) start.ArgumentList.Add(argument);
        var process = new Process { StartInfo = start };
        try { if (!process.Start()) throw new IOException("Could not start the HFS host."); return process; }
        catch { process.Dispose(); throw; }
    }
    private void BrowseSource()
    {
        using var dialog = new OpenFileDialog { Filter = "Disk images|*.img;*.cdr;*.raw|All files|*.*", RestoreDirectory = true };
        if (dialog.ShowDialog(this) == DialogResult.OK) source.Text = dialog.FileName;
    }
    private void ChooseOutput()
    {
        using var dialog = new SaveFileDialog { Filter = "Raw disk image|*.img", OverwritePrompt = false, RestoreDirectory = true, InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments) };
        if (dialog.ShowDialog(this) == DialogResult.OK)
        {
            if (File.Exists(dialog.FileName) || Directory.Exists(dialog.FileName)) Append("Choose a new output filename.");
            else output.Text = dialog.FileName;
        }
    }
    private void SetActive(bool active)
    {
        foreach (Control control in new Control[] { source, output, letters, partition, browse, choose, inspect, mount, drives }) control.Enabled = !active;
        unmount.Enabled = active;
    }
    private static string FullImagePath(string text, string instruction)
    {
        if (!Path.IsPathFullyQualified(text)) throw new IOException(instruction);
        return Path.GetFullPath(text);
    }
    private void InspectImage()
    {
        try
        {
            if (inspection != null || host != null) throw new IOException("Wait for the active operation.");
            if (string.IsNullOrWhiteSpace(source.Text)) throw new IOException("Choose a source image.");
            source.Text = FullImagePath(source.Text, "Use Browse to choose a source image with a full path.");
            inspection = StartProcess("partitions", source.Text);
            inspectionOut = inspection.StandardOutput.ReadToEndAsync(); inspectionErr = inspection.StandardError.ReadToEndAsync();
            inspectionDeadline = DateTime.UtcNow.AddSeconds(15);
            inspect.Enabled = false; mount.Enabled = false; drives.Enabled = false; status.Text = "Inspecting image…";
        }
        catch (Exception error) { Append(error.Message); }
    }
    private void StartMount()
    {
        try
        {
            if (host != null || inspection != null) throw new IOException("Wait for the active operation.");
            if (string.IsNullOrWhiteSpace(source.Text) || string.IsNullOrWhiteSpace(output.Text) || letters.SelectedItem is not string drive) throw new IOException("Choose the source, a new output file and a free drive letter.");
            source.Text = FullImagePath(source.Text, "Use Browse to choose a source image with a full path.");
            output.Text = FullImagePath(output.Text, "Use Choose to select a full output path in a writable folder, such as Documents.");
            if (File.Exists(output.Text) || Directory.Exists(output.Text)) throw new IOException("The output filename already exists.");
            var arguments = new List<string> { "mount", source.Text, drive, "--output", output.Text };
            if (!string.IsNullOrWhiteSpace(partition.Text))
            {
                if (!uint.TryParse(partition.Text, out uint number)) throw new IOException("Partition number must be a nonnegative integer.");
                arguments.AddRange(["--partition", number.ToString(System.Globalization.CultureInfo.InvariantCulture)]);
            }
            host = StartProcess(arguments.ToArray()); hostLogFailed = false;
            hostOut = host.StandardOutput.ReadLineAsync(); hostErr = host.StandardError.ReadLineAsync();
            SetActive(true); status.Text = "Starting mount…"; Append("Output: " + output.Text);
        }
        catch (Exception error) { Append(error.Message); status.Text = "Mount could not start"; }
    }
    private void RequestUnmount()
    {
        try
        {
            if (host is { HasExited: false }) { host.StandardInput.WriteLine(); host.StandardInput.Flush(); status.Text = "Waiting for files to close and unmount…"; }
        }
        catch (Exception error) { Append(error.Message); }
    }
    private void ReadLine(ref Task<string?>? task, StreamReader reader)
    {
        if (task == null || !task.IsCompleted) return;
        try
        {
            string? line = task.GetAwaiter().GetResult(); task = null;
            if (line == null) return;
            Append(line);
            if (line.StartsWith("Mounted disposable image", StringComparison.Ordinal)) status.Text = "Mounted · copy files through File Explorer";
            if (line.Contains("Open files remain", StringComparison.Ordinal)) status.Text = "Close open files, then click Unmount again";
            task = reader.ReadLineAsync();
        }
        catch (Exception error) { hostLogFailed = true; task = null; Append("Host log failure: " + error.Message); }
    }
    private void PollHost()
    {
        tray?.Update();
        if (IsDisposed || Disposing) return;
        if (inspection != null)
        {
            if (!inspection.HasExited && DateTime.UtcNow >= inspectionDeadline)
            {
                // This owned child only inspects a read-only input.
                inspection.Kill(); Append("Read-only inspection timed out.");
            }
            if (inspection.HasExited && inspectionOut!.IsCompleted && inspectionErr!.IsCompleted)
            {
                try { Append(inspectionOut.GetAwaiter().GetResult() + inspectionErr.GetAwaiter().GetResult()); status.Text = inspection.ExitCode == 0 ? "Inspection complete" : "Image inspection failed"; }
                catch (Exception error) { Append(error.Message); status.Text = "Inspection failed"; }
                inspection.Dispose(); inspection = null; inspect.Enabled = true; mount.Enabled = true; drives.Enabled = true;
            }
        }
        if (host == null) return;
        ReadLine(ref hostOut, host.StandardOutput); ReadLine(ref hostErr, host.StandardError);
        if (host.HasExited && hostOut == null && hostErr == null)
        {
            status.Text = host.ExitCode == 0 && !hostLogFailed ? "Unmounted · writable image saved" : "Host failed · retain logs and investigate the output";
            host.Dispose(); host = null; SetActive(false); RefreshLetters();
        }
    }
    protected override void OnFormClosing(FormClosingEventArgs e)
    {
        if (host != null)
        {
            e.Cancel = true;
            status.Text = e.CloseReason == CloseReason.UserClosing && tray?.CanHide == true
                ? "Drive stays open in the system tray" : "Closing drive safely · close files using this drive";
            tray?.RetainOnClose(e.CloseReason);
            Append("Close open files and click Unmount. Keep the host running until it can flush safely.");
        }
        else if (inspection != null)
        {
            if (!inspection.HasExited) inspection.Kill(); inspection.Dispose(); inspection = null;
        }
        base.OnFormClosing(e);
    }
    protected override void Dispose(bool disposing)
    {
        if (disposing) { tray?.Dispose(); timer.Dispose(); }
        base.Dispose(disposing);
    }
    internal int ValidateWorkflow(string directory)
    {
        if (Directory.Exists(directory) || File.Exists(directory)) throw new IOException("Evidence directory must be new.");
        Directory.CreateDirectory(directory);
        var checks = new List<string>(); string? failure = null; FileStream? held = null;
        void Wait(Func<bool> condition)
        {
            DateTime deadline = DateTime.UtcNow.AddSeconds(20);
            do { PollHost(); if (condition()) return; Thread.Sleep(50); } while (DateTime.UtcNow < deadline);
            throw new TimeoutException(status.Text);
        }
        string Hash(string file) { using var stream = File.OpenRead(file); return Convert.ToHexString(SHA256.HashData(stream)); }
        try
        {
            foreach (string ambiguous in new[] { "short-name.img", ".\\short-name.img", "C:short-name.img", "\\short-name.img" })
            {
                source.Text = Path.Combine(directory, "missing-source.img"); output.Text = ambiguous;
                StartMount();
                if (host != null || status.Text != "Mount could not start" || !log.Text.Contains("Use Choose", StringComparison.Ordinal)) throw new IOException("Ambiguous output path reached the host.");
                source.Text = ambiguous; output.Text = Path.Combine(directory, "must-not-exist.img");
                StartMount();
                if (host != null || status.Text != "Mount could not start" || !log.Text.Contains("Use Browse", StringComparison.Ordinal)) throw new IOException("Ambiguous source path reached the host.");
                InspectImage();
                if (inspection != null) throw new IOException("Ambiguous source reached partition inspection.");
            }
            if (File.Exists(Path.Combine(directory, "must-not-exist.img"))) throw new IOException("Refused path created an output.");
            checks.Add("relative, drive-relative and root-relative image paths refused before starting a host or inspection");
            source.Text = Path.Combine(directory, "source.img"); output.Text = Path.Combine(directory, "writable-copy.img");
            using (var fixture = StartProcess("fixture", source.Text, "--journaled"))
            {
                var stdout = fixture.StandardOutput.ReadToEndAsync(); var stderr = fixture.StandardError.ReadToEndAsync();
                if (!fixture.WaitForExit(10000) || fixture.ExitCode != 0) throw new IOException("Fixture failed.");
                Append(stdout.GetAwaiter().GetResult() + stderr.GetAwaiter().GetResult());
            }
            string sourceHash = Hash(source.Text), drive = (string?)letters.SelectedItem ?? throw new IOException("No free letter.");
            StartMount(); Wait(() => status.Text.StartsWith("Mounted", StringComparison.Ordinal) && Directory.Exists(drive + "\\"));
            if (mount.Enabled || drives.Enabled || !unmount.Enabled || source.Enabled || output.Enabled || letters.Enabled || partition.Enabled) throw new IOException("Active controls are editable.");
            checks.Add("mount host and lock active inputs");
            string payload = Path.Combine(drive + "\\", "desktop-manager.txt"); File.WriteAllText(payload, "Standalone manager payload");
            if (File.ReadAllText(payload) != "Standalone manager payload") throw new IOException("Mounted payload mismatch.");
            checks.Add("mounted Windows write/read");
            held = File.Open(payload, FileMode.Open, FileAccess.Read, FileShare.ReadWrite); RequestUnmount();
            Wait(() => status.Text.Contains("Close open files", StringComparison.Ordinal));
            if (host == null || host.HasExited || !Directory.Exists(drive + "\\")) throw new IOException("Busy host escaped.");
            var closing = new FormClosingEventArgs(CloseReason.UserClosing, false); OnFormClosing(closing);
            if (!closing.Cancel) throw new IOException("Window close did not retain host.");
            checks.Add("busy unmount and window close retain host");
            held.Dispose(); held = null; RequestUnmount(); Wait(() => host == null);
            if (status.Text != "Unmounted · writable image saved" || !mount.Enabled || unmount.Enabled || !source.Enabled || Directory.Exists(drive + "\\")) throw new IOException("Unmount did not finish correctly.");
            if (Hash(source.Text) != sourceHash) throw new IOException("Source changed.");
            checks.Add("retry unmount flushes and restores controls; source unchanged");
            string outputHash = Hash(output.Text); StartMount();
            if (host != null || status.Text != "Mount could not start" || Hash(output.Text) != outputHash) throw new IOException("Existing output changed.");
            checks.Add("existing output refused unchanged");
            InspectImage(); Wait(() => inspection == null);
            if (status.Text != "Inspection complete") throw new IOException("Read-only inspection failed.");
            checks.Add("asynchronous read-only partition inspection");
        }
        catch (Exception error) { failure = error.ToString(); }
        finally
        {
            held?.Dispose();
            if (host != null) { RequestUnmount(); try { Wait(() => host == null); } catch (Exception error) { failure += " " + error.Message; } }
            File.WriteAllText(Path.Combine(directory, "manager-host.log"), log.Text);
            File.WriteAllText(Path.Combine(directory, "result.json"), JsonSerializer.Serialize(new { Pass = failure == null, Failure = failure, Checks = checks, NativeBinarySHA256 = Hash(binary), VisualAcceptance = "PENDING", ProgrammaticControllerValidation = true }, new JsonSerializerOptions { WriteIndented = true }));
        }
        return failure == null ? 0 : 1;
    }
}
