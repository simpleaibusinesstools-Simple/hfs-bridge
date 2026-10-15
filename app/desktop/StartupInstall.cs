using System.Diagnostics;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text.Json;
using System.Xml.Linq;
using System.Runtime.InteropServices;

namespace HfsBridge.Manager;

internal static class StartupInstall
{
    private sealed record ManifestFile(string Path, string SHA256, long Bytes);
    private sealed record Manifest(ManifestFile[] Files);
    // COM interop may map ERROR_FILE_NOT_FOUND to FileNotFoundException,
    // rather than COMException. Only this exact code means a first install.
    internal static bool IsMissingTask(Exception error) => (uint)error.HResult == 0x80070002;
    private static bool AccountMatches(string? value, string sid)
    {
        if (string.IsNullOrWhiteSpace(value)) return false;
        try
        {
            string actual = value.StartsWith("S-1-", StringComparison.OrdinalIgnoreCase)
                ? new SecurityIdentifier(value).Value
                : ((SecurityIdentifier)new NTAccount(value).Translate(typeof(SecurityIdentifier))).Value;
            return actual == sid;
        }
        catch (Exception error) when (error is IdentityNotMappedException or ArgumentException) { return false; }
    }
    internal static void ValidateExistingTaskXml(string xml, string sid)
    {
        XNamespace ns = "http://schemas.microsoft.com/windows/2004/02/mit/task";
        var root = XDocument.Parse(xml).Root ?? throw new IOException("Missing startup task.");
        var principal = root.Element(ns + "Principals")?.Elements().ToArray();
        var actions = root.Element(ns + "Actions")?.Elements().ToArray();
        var triggers = root.Element(ns + "Triggers")?.Elements().ToArray();
        string expected = Path.Combine(StartupProfile.InstallDirectory(sid), "HfsBridge.Manager.exe");
        if (root.Name != ns + "Task" || principal is not { Length: 1 } || actions is not { Length: 1 } ||
            triggers is not { Length: 1 } || principal[0].Name != ns + "Principal" ||
            !AccountMatches(principal[0].Element(ns + "UserId")?.Value, sid) || principal[0].Element(ns + "LogonType")?.Value != "InteractiveToken" ||
            principal[0].Element(ns + "RunLevel")?.Value != "HighestAvailable" || actions[0].Name != ns + "Exec" ||
            !string.Equals(actions[0].Element(ns + "Command")?.Value, expected, StringComparison.OrdinalIgnoreCase) ||
            actions[0].Element(ns + "Arguments")?.Value != "--startup" ||
            !string.Equals(actions[0].Element(ns + "WorkingDirectory")?.Value, Path.GetDirectoryName(expected), StringComparison.OrdinalIgnoreCase) ||
            triggers[0].Name != ns + "LogonTrigger" || !AccountMatches(triggers[0].Element(ns + "UserId")?.Value, sid))
            throw new IOException("Startup task identity differs; no changes made.");
    }

    private static void NoLinks(string path)
    {
        var file = new FileInfo(Path.GetFullPath(path));
        if ((file.Exists || Directory.Exists(file.FullName)) && file.Attributes.HasFlag(FileAttributes.ReparsePoint))
            throw new IOException("Linked package and install paths are refused.");
        for (var parent = file.Directory; parent != null; parent = parent.Parent)
            if (parent.Exists && parent.Attributes.HasFlag(FileAttributes.ReparsePoint))
                throw new IOException("Linked package and install paths are refused.");
    }
    private static bool MatchesFile(string path, ManifestFile file)
    {
        NoLinks(path);
        using var input = File.OpenRead(path);
        return input.Length == file.Bytes && Convert.ToHexString(SHA256.HashData(input)) == file.SHA256.ToUpperInvariant();
    }
    internal static string TaskXml(string executable, string sid)
    {
        _ = new SecurityIdentifier(sid);
        if (!Path.IsPathFullyQualified(executable) || !Path.GetFullPath(executable).Equals(
            Path.Combine(StartupProfile.InstallDirectory(sid), "HfsBridge.Manager.exe"), StringComparison.OrdinalIgnoreCase))
            throw new IOException("Startup task requires the fixed protected executable path.");
        XNamespace ns = "http://schemas.microsoft.com/windows/2004/02/mit/task";
        XElement E(string name, object value) => new(ns + name, value);
        return new XDocument(new XElement(ns + "Task", new XAttribute("version", "1.4"),
            E("RegistrationInfo", E("Description", "HFS Bridge: open only the explicitly configured USB HFS volume at user sign-in.")),
            E("Triggers", new XElement(ns + "LogonTrigger", E("Enabled", true), E("Delay", "PT10S"), E("UserId", sid))),
            E("Principals", new XElement(ns + "Principal", new XAttribute("id", "Owner"), E("UserId", sid),
                E("LogonType", "InteractiveToken"), E("RunLevel", "HighestAvailable"))),
            E("Settings", new object[] { E("MultipleInstancesPolicy", "IgnoreNew"), E("DisallowStartIfOnBatteries", false),
                E("StopIfGoingOnBatteries", false), E("AllowHardTerminate", false), E("StartWhenAvailable", true),
                E("AllowStartOnDemand", true), E("Enabled", true), E("Hidden", false), E("ExecutionTimeLimit", "PT0S") }),
            new XElement(ns + "Actions", new XAttribute("Context", "Owner"), new XElement(ns + "Exec",
                E("Command", executable), E("Arguments", "--startup"), E("WorkingDirectory", Path.GetDirectoryName(executable)!)))))
            .ToString(SaveOptions.DisableFormatting);
    }
    private static string RunReader(ProcessStartInfo start)
    {
        using var process = Process.Start(start) ?? throw new IOException("Read-only setup check did not start.");
        var output = process.StandardOutput.ReadToEndAsync(); var error = process.StandardError.ReadToEndAsync();
        if (!process.WaitForExit(30000)) { process.Kill(); throw new IOException("Read-only setup check timed out."); }
        if (process.ExitCode != 0) throw new IOException(error.GetAwaiter().GetResult());
        return output.GetAwaiter().GetResult();
    }
    private static ProcessStartInfo NativeReader(string binary, params string[] args)
    {
        var start = new ProcessStartInfo(binary) { UseShellExecute = false, CreateNoWindow = true,
            RedirectStandardOutput = true, RedirectStandardError = true };
        foreach (string arg in args) start.ArgumentList.Add(arg); return start;
    }
    private static string AdminSid()
    {
        using var identity = WindowsIdentity.GetCurrent();
        if (!new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator))
            throw new IOException("Administrator approval is required for startup setup.");
        return identity.User?.Value ?? throw new IOException("Missing Windows account identity.");
    }
    private static void ProtectDirectory(string directory, string sid)
    {
        var security = new DirectorySecurity(); security.SetAccessRuleProtection(true, false);
        var admin = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        security.SetOwner(admin);
        foreach (var owner in new[] { admin, new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null) })
            security.AddAccessRule(new FileSystemAccessRule(owner, FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
        security.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(sid), FileSystemRights.ReadAndExecute,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
        new DirectoryInfo(directory).SetAccessControl(security);
    }
    private static Manifest VerifiedPackage(string source)
    {
        NoLinks(source);
        NoLinks(Path.Combine(source, "manifest.json"));
        if (new FileInfo(Path.Combine(source, "manifest.json")).Length > 65536) throw new IOException("Package manifest is too large.");
        var manifest = JsonSerializer.Deserialize<Manifest>(File.ReadAllText(Path.Combine(source, "manifest.json")), DriveInventory.Json)
            ?? throw new IOException("Use a complete packaged app for startup setup.");
        if (manifest.Files == null || manifest.Files.Length is < 4 or > 128) throw new IOException("Invalid package manifest.");
        var paths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var file in manifest.Files)
        {
            if (file == null || string.IsNullOrWhiteSpace(file.Path) || file.Path.Length > 240 ||
                file.Path.Split('/', '\\').Any(p => p.Length == 0 || p is "." or ".." || p.Any(c => !char.IsAsciiLetterOrDigit(c) && c is not ('.' or '_' or '-'))) ||
                !paths.Add(file.Path.Replace('\\', '/')) || file.Bytes < 0 || file.Bytes > 64 * 1024 * 1024 ||
                file.SHA256 is not { Length: 64 } || !file.SHA256.All(Uri.IsHexDigit)) throw new IOException("Invalid package entry.");
            string path = Path.GetFullPath(Path.Combine(source, file.Path));
            if (!MatchesFile(path, file)) throw new IOException("Package files changed; use the verified package.");
        }
        foreach (string required in new[] { "HfsBridge.Manager.exe", "HfsBridge.Manager.dll", "HfsBridge.Manager.deps.json", "HfsBridge.Manager.runtimeconfig.json", "bin/hfs-bridge.exe", "bin/runtime/winfsp-x64.dll" })
            if (!paths.Contains(required)) throw new IOException("The startup package is incomplete.");
        foreach (var pin in new[] {
            (Path: "bin/hfs-bridge.exe", Hash: "E34909C0D3946637F39F8BC4945F0B52CA2520EDC1A4A0D389B62CC559851C83"),
            (Path: "bin/runtime/winfsp-x64.dll", Hash: "08D7389B8D030770A4DE108A60A86047D5CDD00B9ECAFC6DD66E957BC51C2437") })
            if (!manifest.Files.Single(f => f.Path.Replace('\\', '/').Equals(pin.Path, StringComparison.OrdinalIgnoreCase)).SHA256.Equals(pin.Hash, StringComparison.OrdinalIgnoreCase))
                throw new IOException("Startup requires this build's verified engine and runtime.");
        return manifest;
    }
    internal static void ValidatePackage(string source) => _ = VerifiedPackage(source);
    internal static void Enable(string encodedSelection)
    {
        string sid = AdminSid(); var selection = StartupSelection.Decode(encodedSelection);
        if (selection.UserSid != sid) throw new IOException("Approve setup using the same Windows account.");
        string source = AppContext.BaseDirectory;
        // Validate all helper bytes before an elevated child is launched.
        var manifest = VerifiedPackage(source);
        string binary = Path.Combine(source, "bin", "hfs-bridge.exe");
        var inventory = DriveInventory.Parse(RunReader(DriveInventory.StartInfo()));
        if (inventory.ParagonActive) throw new IOException("Finish removing the conflicting filesystem driver before setup.");
        var matches = inventory.Disks.Where(d => d.External && d.SerialNumber.Trim() == selection.Serial && d.Size == selection.Size).ToArray();
        if (matches.Length != 1) throw new IOException("The selected USB drive is absent, changed or ambiguous.");
        var disk = matches[0];
        var inspection = DiskInspection.Parse(RunReader(NativeReader(binary, "disk-inspect", disk.Number.ToString(), "--json")), disk);
        var candidates = inspection.Partitions.Where(p => p.HfsCandidate && (selection.Partition == null || p.Number == selection.Partition)).ToArray();
        if (candidates.Length != 1) throw new IOException("Choose one HFS partition under Advanced before startup setup.");
        var part = candidates[0];
        var volume = DiskVolumeInspection.Parse(RunReader(NativeReader(binary, inspection.VolumeArguments(inventory, disk, part))), part);
        if (!volume.EngineAccess || volume.Refusal != null) throw new IOException(volume.Refusal ?? "This filesystem cannot be opened safely.");
        if (selection.Writable) _ = new DriveWritePlan(disk, part, selection.Letter).Validate(new(inventory, disk, inspection, volume), true);
        var profile = new StartupProfile(1, sid, disk.SerialNumber.Trim(), disk.Size, disk.LogicalSectorSize,
            disk.PhysicalSectorSize, part.Number, part.Offset, part.Length, StartupProfile.ReadVolumeId(disk, part), selection.Letter, selection.Writable);
        profile.Validate();
        string target = StartupProfile.InstallDirectory(sid);
        NoLinks(target);
        dynamic service = Activator.CreateInstance(Type.GetTypeFromProgID("Schedule.Service")!)!;
        service.Connect(); dynamic folder = service.GetFolder("\\"); dynamic? previous = null;
        try { previous = folder.GetTask(StartupProfile.TaskName(sid)); }
        catch (Exception error) when (IsMissingTask(error)) { }
        if (previous != null)
        {
            ValidateExistingTaskXml((string)previous.Xml, sid);
            if ((int)previous.State == 4) throw new IOException("Exit the startup copy of HFS Bridge from its tray before changing startup settings.");
        }
        foreach (var file in manifest.Files)
        {
            string destination = Path.Combine(target, file.Path); NoLinks(destination);
            if (File.Exists(destination) && !MatchesFile(destination, file))
                throw new IOException("Installed files differ. Use the same package to re-enable startup; upgrades need a separate review.");
        }
        Directory.CreateDirectory(target); ProtectDirectory(target, sid);
        foreach (var file in manifest.Files)
        {
            string destination = Path.Combine(target, file.Path); Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
            if (!File.Exists(destination)) File.Copy(Path.Combine(source, file.Path), destination, false);
            if (!MatchesFile(destination, file))
                throw new IOException("Copied startup files do not match; no task has been installed.");
        }
        string pending = Path.Combine(target, "startup-profile.pending-" + Guid.NewGuid().ToString("N") + ".json");
        using (var output = new FileStream(pending, FileMode.CreateNew, FileAccess.Write, FileShare.None))
        {
            JsonSerializer.Serialize(output, profile, new JsonSerializerOptions { WriteIndented = true }); output.Flush(true);
        }
        NoLinks(Path.Combine(target, "manifest.json")); NoLinks(Path.Combine(target, "startup-profile.json"));
        File.WriteAllText(Path.Combine(target, "manifest.json"), JsonSerializer.Serialize(manifest));
        string xml = TaskXml(Path.Combine(target, "HfsBridge.Manager.exe"), sid);
        XNamespace ns = "http://schemas.microsoft.com/windows/2004/02/mit/task";
        var definition = XDocument.Parse(xml); definition.Root!.Element(ns + "Settings")!.Element(ns + "Enabled")!.Value = "false";
        string security = $"D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;GRGX;;;{sid})";
        dynamic registered = folder.RegisterTask(StartupProfile.TaskName(sid), definition.ToString(), previous == null ? 2 : 6, sid, null, 3, security);
        // Keep the trigger disabled until the new configuration is committed.
        // Failed setup retains evidence and can be retried with identical files.
        File.Move(pending, Path.Combine(target, "startup-profile.json"), true);
        registered.Enabled = true;
        // A logon trigger is installed only; registration does not start a host.
    }
    internal static void Disable()
    {
        string sid = AdminSid(); dynamic service = Activator.CreateInstance(Type.GetTypeFromProgID("Schedule.Service")!)!;
        service.Connect(); dynamic task = service.GetFolder("\\").GetTask(StartupProfile.TaskName(sid));
        ValidateExistingTaskXml((string)task.Xml, sid);
        task.Enabled = false;
    }
}
