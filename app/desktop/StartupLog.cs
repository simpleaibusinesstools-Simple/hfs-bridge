using System.Security.Principal;

namespace HfsBridge.Manager;

internal static class StartupLog
{
    internal static void Write(string message)
    {
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            string folder = StartupProfile.InstallDirectory(identity.User!.Value);
            if (!Path.GetFullPath(AppContext.BaseDirectory).TrimEnd(Path.DirectorySeparatorChar)
                .Equals(folder, StringComparison.OrdinalIgnoreCase)) return;
            string path = Path.Combine(folder, "startup-activity.log");
            // Diagnostic metadata only, bounded without deleting old evidence.
            if (File.Exists(path) && (new FileInfo(path).Length > 256000 || File.GetAttributes(path).HasFlag(FileAttributes.ReparsePoint))) return;
            File.AppendAllText(path, DateTime.UtcNow.ToString("O") + " " + message + Environment.NewLine);
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException) { }
    }
}
