using System.Diagnostics;
using System.Globalization;
using System.Text.Json;

namespace HfsBridge.Manager;

internal sealed record DiskItem(uint Number, string FriendlyName, string BusType, ulong Size,
    string SerialNumber, uint LogicalSectorSize, uint PhysicalSectorSize,
    bool IsBoot, bool IsSystem, bool IsOffline, bool IsReadOnly)
{
    internal bool External => BusType == "USB" && !IsBoot && !IsSystem && Number <= 4095 && Size > 0;
    public override string ToString() => $"{FriendlyName} · {Size / 1_000_000_000.0:F1} GB · disk {Number}";
}
internal sealed record DriverItem(string Name, string State);
internal sealed record DriveOpenRequest(uint Number, string Serial, ulong Size, bool Writable = false, bool Transfer = false)
{
    internal bool Matches(DiskItem disk) => disk.External && disk.Number == Number &&
        disk.SerialNumber == Serial && disk.Size == Size && !string.IsNullOrWhiteSpace(Serial);
}
internal sealed record DriveInventory(DiskItem[] Disks, DriverItem[] Drivers, bool ParagonRemovalPending)
{
    internal bool ParagonActive => ParagonRemovalPending || Drivers.Any(d => d.State.Equals("Running", StringComparison.OrdinalIgnoreCase));
    internal static readonly JsonSerializerOptions Json = new() { PropertyNameCaseInsensitive = true, RespectRequiredConstructorParameters = true };
    internal static DriveInventory Parse(string text)
    {
        if (text.Length > 1_000_000) throw new IOException("Drive inventory is too large.");
        var result = JsonSerializer.Deserialize<DriveInventory>(text, Json) ?? throw new IOException("Missing drive inventory.");
        if (result.Disks == null || result.Drivers == null || result.Disks.Length > 4096 || result.Drivers.Length > 16 ||
            result.Disks.Any(d => d == null || d.FriendlyName == null || d.BusType == null || d.SerialNumber == null) ||
            result.Drivers.Any(d => d == null || d.Name == null || d.State == null) ||
            result.Disks.Select(d => d.Number).Distinct().Count() != result.Disks.Length)
            throw new IOException("Invalid drive inventory.");
        return result;
    }
    // Fixed read-only commands. No disk number, path or other user text enters
    // the PowerShell program. Any failure prevents mounting from that snapshot.
    internal static ProcessStartInfo StartInfo()
    {
        const string command = """
            $ErrorActionPreference='Stop'
            [Console]::OutputEncoding=[System.Text.UTF8Encoding]::new($false)
            $disks=@(Get-Disk | ForEach-Object {
              [pscustomobject]@{Number=[uint32]$_.Number;FriendlyName=[string]$_.FriendlyName;BusType=[string]$_.BusType;Size=[uint64]$_.Size;SerialNumber=([string]$_.SerialNumber).Trim();LogicalSectorSize=[uint32]$_.LogicalSectorSize;PhysicalSectorSize=[uint32]$_.PhysicalSectorSize;IsBoot=[bool]$_.IsBoot;IsSystem=[bool]$_.IsSystem;IsOffline=[bool]$_.IsOffline;IsReadOnly=[bool]$_.IsReadOnly}
            })
            $drivers=@(Get-CimInstance Win32_SystemDriver -Filter "Name='Hfsplus' OR Name='HfsplusRec' OR Name='mounthlp' OR Name='apmwin' OR Name='gpt_loader' OR Name='csvol'" | Select-Object Name,State)
            $session=Get-Item -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -ErrorAction Stop
            $pending=@($session.GetValue('PendingFileRenameOperations',@()))
            $removalPending=@($pending|Where-Object {$_ -match '(\\|/)(hfsplus|hfsplusrec|mounthlp|apmwin|gpt_loader|csvol)\.sys$|Paragon Software[\\/]HFS\+ for Windows'}).Count -gt 0
            [pscustomobject]@{Disks=$disks;Drivers=$drivers;ParagonRemovalPending=[bool]$removalPending} | ConvertTo-Json -Depth 4 -Compress
            """;
        var start = new ProcessStartInfo(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "WindowsPowerShell", "v1.0", "powershell.exe"))
        { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true, StandardOutputEncoding = System.Text.Encoding.UTF8, StandardErrorEncoding = System.Text.Encoding.UTF8 };
        foreach (string arg in new[] { "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", command }) start.ArgumentList.Add(arg);
        return start;
    }
}
internal sealed record DiskPartition(uint Number, string Name, ulong Offset, ulong Length, bool HfsCandidate, bool Writable, string Token)
{
    public override string ToString() => $"{Number}: {Name} · {Length / 1_000_000_000.0:F1} GB";
}
internal sealed record DiskInspection(int Schema, uint Number, ulong Length, uint LogicalSector, uint PhysicalSector,
    uint BusType, string Serial, bool Offline, bool ReadOnly, bool PhysicalWriteSupported, bool RemovableMedia, bool VolumeLockSupported, DiskPartition[] Partitions)
{
    internal static DiskInspection Parse(string json, DiskItem selected)
    {
        if (json.Length > 2_000_000) throw new IOException("Inspection output is too large.");
        var result = JsonSerializer.Deserialize<DiskInspection>(json, DriveInventory.Json) ?? throw new IOException("Missing inspection.");
        if (!selected.External || result.Schema != 1 || result.Number != selected.Number || result.Length != selected.Size ||
            result.BusType != 7 || result.Serial == null || result.Serial.Trim() != selected.SerialNumber.Trim() ||
            result.LogicalSector != selected.LogicalSectorSize ||
            !new uint[] { 512, 4096 }.Contains(result.LogicalSector) || result.Length % result.LogicalSector != 0 ||
            (result.PhysicalSector == 0 ? result.PhysicalWriteSupported :
                result.PhysicalSector != selected.PhysicalSectorSize || !new uint[] { 512, 4096 }.Contains(result.PhysicalSector) ||
                result.PhysicalSector < result.LogicalSector || result.Length % result.PhysicalSector != 0) ||
            (result.VolumeLockSupported && (!result.RemovableMedia || result.LogicalSector != 512 ||
                result.PhysicalSector is not (0 or 512) || string.IsNullOrWhiteSpace(result.Serial))) ||
            result.Partitions == null || result.Partitions.Length > 4096 ||
            result.Partitions.Select(p => p?.Number).Distinct().Count() != result.Partitions.Length)
            throw new IOException("Disk identity changed or is unsupported. Refresh and inspect again.");
        foreach (var part in result.Partitions)
        {
            if (part == null || part.Name == null || part.Name.Length > 256 || part.Token == null || part.Length == 0 || part.Offset > result.Length || part.Length > result.Length - part.Offset ||
                part.Offset % result.LogicalSector != 0 || part.Length % result.LogicalSector != 0 ||
                (part.HfsCandidate && (part.Token.Length != 64 || !part.Token.All(Uri.IsHexDigit))))
                throw new IOException("Invalid partition inspection.");
        }
        return result;
    }
    internal string? Refusal(DriveInventory inventory, DiskItem disk, DiskPartition? partition, bool consent)
    {
        if (!disk.External || !inventory.Disks.Contains(disk) || disk.Number != Number || disk.Size != Length || disk.SerialNumber.Trim() != Serial.Trim() ||
            disk.LogicalSectorSize != LogicalSector || (PhysicalSector != 0 && disk.PhysicalSectorSize != PhysicalSector)) return "Refresh and inspect this drive again.";
        if (inventory.ParagonRemovalPending) return "Restart Windows to finish removing Paragon before direct-drive testing.";
        if (inventory.ParagonActive) return "Paragon's disk driver is running. Remove Paragon and restart before direct-drive testing.";
        bool lockedVolume = VolumeLockSupported && RemovableMedia && LogicalSector == 512 &&
            PhysicalSector is 0 or 512 && !string.IsNullOrWhiteSpace(Serial) && !Offline && !disk.IsOffline;
        if (!lockedVolume)
        {
            if (PhysicalSector == 0) return "This USB does not report the sector information required for this write method. Read-only filesystem checks are available.";
            if (!PhysicalWriteSupported || LogicalSector != 512 || PhysicalSector != 512 || string.IsNullOrWhiteSpace(Serial)) return "This build requires a USB drive with supported sectors and a stable serial.";
            if (!Offline || !disk.IsOffline) return "The selected disk must already be offline in Windows Disk Management.";
        }
        if (ReadOnly || disk.IsReadOnly) return "The selected disk is write-protected.";
        if (partition == null || !Partitions.Contains(partition) || !partition.HfsCandidate || !partition.Writable) return "Select a writable HFS partition.";
        if (!consent) return "Confirm direct changes to the selected drive before mounting.";
        return null;
    }
    internal string[] MountArguments(DriveInventory inventory, DiskItem disk, DiskPartition part, bool consent, string letter)
    {
        string? refusal = Refusal(inventory, disk, part, consent);
        if (refusal != null) throw new IOException(refusal);
        if (letter.Length != 2 || letter[0] < 'D' || letter[0] > 'Z' || letter[1] != ':') throw new IOException("Choose a free drive letter.");
        return [VolumeLockSupported && !Offline ? "mount-volume" : "mount-disk", Number.ToString(CultureInfo.InvariantCulture), letter, "--partition", part.Number.ToString(CultureInfo.InvariantCulture), "--identity", part.Token];
    }
    internal string[] VolumeArguments(DriveInventory inventory, DiskItem disk, DiskPartition part)
    {
        if (!disk.External || !inventory.Disks.Contains(disk) || disk.Number != Number || disk.Size != Length || disk.SerialNumber.Trim() != Serial.Trim() ||
            disk.LogicalSectorSize != LogicalSector || (PhysicalSector != 0 && disk.PhysicalSectorSize != PhysicalSector) || string.IsNullOrWhiteSpace(Serial) ||
            !Partitions.Contains(part) || !part.HfsCandidate)
            throw new IOException("Refresh and inspect this drive again before checking its filesystem.");
        return ["disk-volume", Number.ToString(CultureInfo.InvariantCulture), "--partition", part.Number.ToString(CultureInfo.InvariantCulture), "--identity", part.Token];
    }
    internal string[] ReadOnlyMountArguments(DriveInventory inventory, DiskItem disk, DiskPartition part, string letter)
    {
        // Reuse the read-only identity/partition checks; never relax writable mounting.
        _ = VolumeArguments(inventory, disk, part);
        if (inventory.ParagonActive) throw new IOException("Finish removing Paragon before opening this drive.");
        if (letter.Length != 2 || letter[0] < 'D' || letter[0] > 'Z' || letter[1] != ':')
            throw new IOException("Choose a free drive letter.");
        return ["mount-disk-readonly", Number.ToString(CultureInfo.InvariantCulture), letter,
            "--partition", part.Number.ToString(CultureInfo.InvariantCulture), "--identity", part.Token];
    }
}

internal sealed record DiskVolumeInspection(int Schema, string Operation, uint Signature, uint Version, uint Attributes,
    uint BlockSize, uint TotalBlocks, uint FreeBlocks, uint Files, uint Folders, uint WriteCount,
    bool AlternateMatches, bool AlternateCompatible, string Journal, bool EngineAccess, bool PhysicalWrites)
{
    internal string? Refusal => !AlternateCompatible ? "Filesystem headers disagree. Check this drive on a Mac before mounting."
        : (Attributes & 256) == 0 || (Attributes & 2048) != 0 ? "Filesystem needs checking on a Mac. Mounting stays disabled."
        : Journal == "pending" ? "Filesystem has pending journal work. Check this drive on a Mac before mounting."
        : null;
    internal static DiskVolumeInspection Parse(string json, DiskPartition partition)
    {
        if (json.Length > 16384 || !partition.HfsCandidate) throw new IOException("Invalid filesystem status report.");
        using var document = JsonDocument.Parse(json);
        if (document.RootElement.ValueKind != JsonValueKind.Object) throw new IOException("Invalid filesystem status report.");
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var property in document.RootElement.EnumerateObject())
            if (!names.Add(property.Name)) throw new IOException("Duplicate filesystem status field.");
        var result = JsonSerializer.Deserialize<DiskVolumeInspection>(json, DriveInventory.Json) ?? throw new IOException("Missing filesystem status.");
        ulong occupied = (ulong)result.BlockSize * result.TotalBlocks;
        if (result.Schema != 1 || result.Operation != "read-only volume inspection" || result.PhysicalWrites ||
            (result.Signature, result.Version) is not ((0x482b, 4) or (0x4858, 5)) ||
            result.BlockSize < 512 || (result.BlockSize & (result.BlockSize - 1)) != 0 || occupied < 2048 ||
            occupied > partition.Length || partition.Length - occupied >= result.BlockSize || result.FreeBlocks > result.TotalBlocks ||
            result.Journal is not ("absent" or "clean" or "pending") || ((result.Attributes & 8192) != 0) == (result.Journal == "absent") ||
            (result.AlternateMatches && !result.AlternateCompatible) || result.EngineAccess != (result.Refusal == null))
            throw new IOException("Invalid or contradictory filesystem status. Inspect and check the drive again.");
        return result;
    }
}
