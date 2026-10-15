using System.Buffers.Binary;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace HfsBridge.Manager;

internal sealed record StartupSelection(string UserSid, string Serial, ulong Size, uint? Partition,
    string Letter, bool Writable)
{
    internal string Encode() => Convert.ToBase64String(JsonSerializer.SerializeToUtf8Bytes(this));
    internal static StartupSelection Decode(string value)
    {
        if (value.Length > 8192) throw new IOException("Startup selection is too large.");
        var selection = StartupProfile.ReadJson<StartupSelection>(Encoding.UTF8.GetString(Convert.FromBase64String(value)));
        _ = new SecurityIdentifier(selection.UserSid);
        if (string.IsNullOrWhiteSpace(selection.Serial) || selection.Serial.Length > 256 || selection.Size == 0 ||
            selection.Partition > 4095 || !StartupProfile.ValidLetter(selection.Letter)) throw new IOException("Invalid startup selection.");
        return selection;
    }
}

internal sealed record StartupProfile(int Schema, string UserSid, string Serial, ulong Size, uint LogicalSector,
    uint PhysicalSector, uint Partition, ulong Offset, ulong Length, string VolumeId, string Letter, bool Writable)
{
    internal static T ReadJson<T>(string text)
    {
        if (text.Length > 16384) throw new IOException("Startup configuration is too large.");
        using var document = JsonDocument.Parse(text);
        if (document.RootElement.ValueKind != JsonValueKind.Object) throw new IOException("Invalid startup configuration.");
        var fields = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var field in document.RootElement.EnumerateObject())
            if (!fields.Add(field.Name)) throw new IOException("Duplicate startup configuration field.");
        var options = new JsonSerializerOptions(DriveInventory.Json) { UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow };
        return JsonSerializer.Deserialize<T>(text, options) ?? throw new IOException("Missing startup configuration.");
    }
    internal static bool ValidLetter(string? value) => value is { Length: 2 } && value[0] is >= 'D' and <= 'Z' && value[1] == ':';
    internal void Validate()
    {
        _ = new SecurityIdentifier(UserSid);
        if (Schema != 1 || string.IsNullOrWhiteSpace(Serial) || Serial.Length > 256 || Size == 0 ||
            LogicalSector != 512 || PhysicalSector is not (0 or 512) || Partition > 4095 ||
            Offset > Size || Length == 0 || Length > Size - Offset || Offset % 512 != 0 || Length % 512 != 0 ||
            VolumeId is not { Length: 16 } || !VolumeId.All(Uri.IsHexDigit) || VolumeId.All(c => c == '0') || !ValidLetter(Letter))
            throw new IOException("Invalid automatic-mount profile.");
    }
    internal bool Matches(DiskItem disk) => disk.External && Serial == disk.SerialNumber.Trim() && Size == disk.Size &&
        LogicalSector == disk.LogicalSectorSize && PhysicalSector == disk.PhysicalSectorSize && (!Writable || !disk.IsReadOnly);
    internal bool Matches(DiskPartition part) => part.HfsCandidate && Partition == part.Number && Offset == part.Offset && Length == part.Length;

    internal static string ReadVolumeId(DiskItem disk, DiskPartition part)
    {
        if (!disk.External || disk.LogicalSectorSize != 512 || part.Offset > disk.Size || part.Length < 1536 ||
            part.Length > disk.Size - part.Offset || part.Offset > long.MaxValue - 1024)
            throw new IOException("Invalid HFS volume identity range.");
        // Read only the HFS header. The handle closes before the owning mount
        // starts; neither cached Windows disk numbers nor mutable headers are
        // used as the persistent identity.
        using var input = new FileStream($"\\\\.\\PhysicalDrive{disk.Number}", FileMode.Open,
            FileAccess.Read, FileShare.ReadWrite, 512, FileOptions.RandomAccess);
        input.Position = checked((long)part.Offset + 1024);
        byte[] header = new byte[512]; input.ReadExactly(header);
        ushort signature = BinaryPrimitives.ReadUInt16BigEndian(header);
        ushort version = BinaryPrimitives.ReadUInt16BigEndian(header.AsSpan(2));
        if (!(signature == 0x482b && version == 4 || signature == 0x4858 && version == 5))
            throw new IOException("Automatic mounting requires a recognized HFS+ volume.");
        string id = Convert.ToHexString(header.AsSpan(104, 8));
        if (id.All(c => c == '0')) throw new IOException("This volume has no persistent identifier; open it manually.");
        return id;
    }

    internal static string InstallDirectory(string sid)
    {
        _ = new SecurityIdentifier(sid);
        return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "SimpleAI Tools", "HFS Bridge", sid);
    }
    internal static string TaskName(string sid) => "SimpleAI Tools HFS Bridge " + new SecurityIdentifier(sid).Value;
    internal static StartupProfile LoadInstalled()
    {
        using var identity = WindowsIdentity.GetCurrent();
        if (!new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator))
            throw new IOException("Automatic mounting must run through the approved startup task.");
        string sid = identity.User?.Value ?? throw new IOException("Missing Windows user identity.");
        string folder = InstallDirectory(sid);
        if (!Path.GetFullPath(AppContext.BaseDirectory).TrimEnd(Path.DirectorySeparatorChar)
            .Equals(folder, StringComparison.OrdinalIgnoreCase)) throw new IOException("Use the installed, protected startup application.");
        StartupInstall.ValidatePackage(folder);
        for (var parent = new DirectoryInfo(folder); parent != null; parent = parent.Parent)
            if (parent.Attributes.HasFlag(FileAttributes.ReparsePoint)) throw new IOException("Linked startup paths are refused.");
        string path = Path.Combine(folder, "startup-profile.json");
        var item = new FileInfo(path);
        if (item.Attributes.HasFlag(FileAttributes.ReparsePoint) || item.Length > 16384) throw new IOException("Invalid startup profile file.");
        var profile = ReadJson<StartupProfile>(File.ReadAllText(path, Encoding.UTF8));
        profile.Validate();
        if (profile.UserSid != sid) throw new IOException("Startup profile belongs to another Windows account.");
        return profile;
    }
}
