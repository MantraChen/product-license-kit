using System.Buffers.Binary;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;

namespace ProductLicenseKit;

public static class HardwareIdentity
{
    internal static void Identifier(string value) => Protocol.Require(
        Regex.IsMatch(value, "\\A[A-Za-z0-9][A-Za-z0-9._-]{0,79}\\z"), "INVALID_IDENTIFIER");
    /// <summary>Hashes the raw SMBIOS type-1 UUID with product and schema separation. Does not assert hardware trust.</summary>
    public static Fingerprint FromRawSmbios(ReadOnlySpan<byte> raw, string productId, string schema)
    {
        Identifier(productId); Identifier(schema);
        Protocol.Require(raw.Length is >= 8 and <= 1048576 && BinaryPrimitives.ReadUInt32LittleEndian(raw[4..]) == raw.Length - 8,
            "INVALID_SMBIOS");
        string? uuid = null;
        var position = 8;
        while (position < raw.Length)
        {
            Protocol.Require(position + 4 <= raw.Length, "INVALID_SMBIOS");
            var type = raw[position]; var length = raw[position + 1];
            Protocol.Require(length >= 4 && position + length <= raw.Length, "INVALID_SMBIOS");
            if (type == 1 && length >= 24)
            {
                var value = raw.Slice(position + 8, 16);
                Protocol.Require(uuid is null && value.ContainsAnyExcept((byte)0) && value.ContainsAnyExcept((byte)255),
                    "HARDWARE_IDENTIFIER_UNAVAILABLE");
                uuid = Protocol.Hex(value);
            }
            var end = position + length;
            while (end + 1 < raw.Length && !(raw[end] == 0 && raw[end + 1] == 0)) end++;
            Protocol.Require(end + 1 < raw.Length, "INVALID_SMBIOS");
            position = end + 2;
            if (type == 127) break;
        }
        Protocol.Require(uuid is not null, "HARDWARE_IDENTIFIER_UNAVAILABLE");
        return new Fingerprint(schema, Protocol.Hex(SHA256.HashData(Encoding.UTF8.GetBytes(
            "product-license-kit-hwid-v1\0" + productId + "\0" + schema + "\0uuid:" + uuid))));
    }
    [SupportedOSPlatform("windows")]
    public static Fingerprint ReadWindows(string productId, string schema)
    {
        const uint rsmb = 0x52534d42;
        var size = GetSystemFirmwareTable(rsmb, 0, null, 0);
        Protocol.Require(size is > 0 and <= 1048576, "HARDWARE_IDENTIFIER_UNAVAILABLE");
        var buffer = new byte[size];
        try
        {
            Protocol.Require(GetSystemFirmwareTable(rsmb, 0, buffer, size) == size, "HARDWARE_IDENTIFIER_UNAVAILABLE");
            return FromRawSmbios(buffer, productId, schema);
        }
        finally { CryptographicOperations.ZeroMemory(buffer); }
    }
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint GetSystemFirmwareTable(uint provider, uint tableId, [Out] byte[]? buffer, uint size);
}

/// <summary>Current-user DPAPI software identity. TPM assurance remains a separate host adapter.</summary>
[SupportedOSPlatform("windows")]
public static class WindowsKeyStore
{
    public static DeviceKey LoadOrCreate(string productId, string accountId, string? storageRoot = null, bool allowCreation = false)
    {
        HardwareIdentity.Identifier(productId);
        Protocol.Require(Guid.TryParseExact(accountId, "D", out var account), "INVALID_ACCOUNT_ID");
        accountId = account.ToString("D");
        if (storageRoot is null)
        {
            var localData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            Protocol.Require(Path.IsPathFullyQualified(localData), "INVALID_IDENTITY_ROOT");
            storageRoot = Path.Combine(localData, "ProductLicenseKit", "Identity");
        }
        Protocol.Require(Path.IsPathFullyQualified(storageRoot), "INVALID_IDENTITY_ROOT");
        var root = Path.GetFullPath(storageRoot);
        var directory = Path.Combine(root, Protocol.Hex(SHA256.HashData(Encoding.UTF8.GetBytes(productId))), accountId);
        NoLinks(directory);
        Protocol.Require(allowCreation || File.Exists(Path.Combine(directory, "device.key")), "DEVICE_KEY_NOT_FOUND");
        Directory.CreateDirectory(directory);
        NoLinks(directory);
        var identity = WindowsIdentity.GetCurrent().User ?? throw new LicenseException("WINDOWS_USER_UNAVAILABLE");
        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(true, false);
        security.SetOwner(identity);
        security.AddAccessRule(new FileSystemAccessRule(identity, FileSystemRights.FullControl,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
        new DirectoryInfo(directory).SetAccessControl(security);
        var lockPath = Path.Combine(directory, "identity.lock");
        using var guard = Lock(lockPath);
        var path = Path.Combine(directory, "device.key");
        var entropy = Encoding.UTF8.GetBytes("product-license-kit-device-v1\0" + productId + "\0" + accountId);
        if (File.Exists(path)) return Read(path, entropy);
        NoLinks(path);
        var seed = RandomNumberGenerator.GetBytes(32);
        var temporary = Path.Combine(directory, Guid.NewGuid().ToString("N") + ".tmp");
        var ownsTemporary = false;
        try
        {
            var cipher = ProtectedData.Protect(seed, entropy, DataProtectionScope.CurrentUser);
            using (var stream = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                ownsTemporary = true;
                stream.Write(cipher); stream.Flush(true);
            }
            File.Move(temporary, path, false);
            return Read(path, entropy);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(seed);
            if (ownsTemporary && File.Exists(temporary)) File.Delete(temporary);
        }
    }
    private static DeviceKey Read(string path, byte[] entropy)
    {
        NoLinks(path);
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        Protocol.Require(stream.Length is > 0 and <= 4096, "INVALID_DEVICE_KEY_FILE");
        var cipher = new byte[stream.Length]; stream.ReadExactly(cipher);
        var seed = ProtectedData.Unprotect(cipher, entropy, DataProtectionScope.CurrentUser);
        try { return DeviceKey.FromEd25519Seed(seed); }
        finally { CryptographicOperations.ZeroMemory(seed); }
    }
    private static FileStream Lock(string path)
    {
        var clock = Stopwatch.StartNew();
        while (true)
        {
            NoLinks(path);
            try { return new FileStream(path, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None); }
            catch (IOException) when (clock.Elapsed < TimeSpan.FromSeconds(10)) { Thread.Sleep(50); }
        }
    }
    private static void NoLinks(string path)
    {
        for (var current = Path.GetFullPath(path); current is not null; current = Path.GetDirectoryName(current))
        {
            try { Protocol.Require((File.GetAttributes(current) & FileAttributes.ReparsePoint) == 0, "IDENTITY_PATH_REDIRECTED"); }
            catch (FileNotFoundException) { }
            catch (DirectoryNotFoundException) { }
        }
    }
}
