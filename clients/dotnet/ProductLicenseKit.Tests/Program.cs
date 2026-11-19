using System.Security.Cryptography;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;
using ProductLicenseKit;

static void Require(bool condition, string code) { if (!condition) throw new Exception(code); }
static void Reject(Action action, string code)
{
    try { action(); } catch (Exception error) when (error.Message != "ACCEPTED_INVALID_INPUT") { return; }
    throw new Exception("ACCEPTED_INVALID_INPUT:" + code);
}
if (args.Length == 2 && args[0] == "--interop")
{
    var config = Protocol.ParseJson(File.ReadAllBytes(args[1]));
    await Interop.Run(config);
    return;
}
if (args.Length == 2 && args[0] == "--storage" && OperatingSystem.IsWindows())
{
    var config = Protocol.ParseJson(File.ReadAllBytes(args[1]));
    var existing = Path.Combine(config.GetProperty("storageRoot").GetString()!, Convert.ToHexStringLower(SHA256.HashData(
        System.Text.Encoding.UTF8.GetBytes("sdk-interoperability"))), config.GetProperty("storageAccountId").GetString()!, "device.key");
    if (File.Exists(existing))
    {
        var current = WindowsIdentity.GetCurrent().User!;
        var rules = new FileInfo(existing).GetAccessControl().GetAccessRules(true, true, typeof(SecurityIdentifier)).OfType<FileSystemAccessRule>().ToArray();
        Require(rules.Length > 0, "IDENTITY_ACL_EXPOSED");
        foreach (var rule in rules)
            Require(rule.AccessControlType != AccessControlType.Allow || rule.IdentityReference.Equals(current), "IDENTITY_ACL_EXPOSED");
    }
    using var stored = WindowsKeyStore.LoadOrCreate("sdk-interoperability", config.GetProperty("storageAccountId").GetString()!,
        config.GetProperty("storageRoot").GetString(), config.GetProperty("allowCreateIdentity").GetBoolean());
    var hardware = HardwareIdentity.ReadWindows("sdk-interoperability", "sdk-hwid-v1");
    Console.WriteLine(JsonSerializer.Serialize(new { publicKey = stored.PublicKey, fingerprint = hardware }));
    return;
}

var accountId = Guid.NewGuid().ToString("D"); var challengeId = Guid.NewGuid().ToString("D");
var fingerprint = new Fingerprint("test-v1", new string('a', 64));
using var ed = DeviceKey.CreateEd25519();
using var rsa = DeviceKey.FromRsa(RSA.Create(2048));
var checkedCases = 0;
foreach (var key in new[] { ed, rsa })
{
    var payload = new { groupId = "desktop", publicKey = key.PublicKey, thumbprint = Protocol.DeviceThumbprint(key.PublicKey),
        fingerprint = new { schema = fingerprint.Schema, digest = fingerprint.Digest } };
    var challenge = JsonSerializer.Serialize(new object[] { "product-license-kit", 1, "enroll", challengeId, accountId, payload, Protocol.Base64Url(new byte[32]) });
    var context = new EnrollmentContext(challengeId, accountId, "desktop", fingerprint);
    Require(key.SignEnrollmentChallenge(challenge, context).Length == (key == ed ? 86 : 342), "SIGNATURE_LENGTH"); checkedCases++;
    Reject(() => key.SignEnrollmentChallenge(challenge, context with { AccountId = Guid.NewGuid().ToString("D") }), "account"); checkedCases++;
    Reject(() => key.SignEnrollmentChallenge(challenge, context with { Fingerprint = fingerprint with { Digest = new string('b', 64) } }), "fingerprint"); checkedCases++;
    Reject(() => key.SignEnrollmentChallenge(challenge.Replace("\"enroll\"", "\"license\""), context), "kind"); checkedCases++;
    Reject(() => key.SignEnrollmentChallenge(challenge.Replace("\"groupId\":\"desktop\"", "\"groupId\":\"desktop\",\"groupId\":\"desktop\""), context), "duplicate"); checkedCases++;
}
foreach (var text in new[] { "Zg=", "Zh", "+w", "a", "" }) { Reject(() => Protocol.DecodeBase64Url(text), "base64"); checkedCases++; }
foreach (var url in new[] { "http://public.example", "https://user:pass@example.com", "https://example.com/path", "https://example.com?q=1", "file:///tmp" })
{ Reject(() => new LicenseClient(url), "url"); checkedCases++; }
Reject(() => DeviceKey.FromRsa(RSA.Create(3072)), "rsa-size"); checkedCases++;
var smbios = new byte[34]; smbios[4] = 26; smbios[8] = 1; smbios[9] = 24;
for (var index = 0; index < 16; index++) smbios[index + 16] = (byte)(index + 1);
var first = HardwareIdentity.FromRawSmbios(smbios, "sample-tool", "sample-v1");
Require(first.Digest.Length == 64 && first != HardwareIdentity.FromRawSmbios(smbios, "sample-addon", "sample-v1"), "HWID_DOMAIN"); checkedCases++;
Reject(() => HardwareIdentity.FromRawSmbios(smbios.AsSpan(0, 33), "sample-tool", "sample-v1"), "smbios-length"); checkedCases++;
Array.Clear(smbios, 16, 16);
Reject(() => HardwareIdentity.FromRawSmbios(smbios, "sample-tool", "sample-v1"), "zero-uuid"); checkedCases++;
if (OperatingSystem.IsWindows())
{
    var root = Path.Combine(Path.GetTempPath(), "plk-sdk-" + Guid.NewGuid().ToString("N"));
    try
    {
        Reject(() => WindowsKeyStore.LoadOrCreate("sample-tool", accountId, "relative-root", allowCreation: true), "relative-identity-root"); checkedCases++;
        using var firstKey = WindowsKeyStore.LoadOrCreate("sample-tool", accountId, root, allowCreation: true);
        using var secondKey = WindowsKeyStore.LoadOrCreate("sample-tool", accountId, root);
        Require(firstKey.PublicKey == secondKey.PublicKey, "DPAPI_IDENTITY_CHANGED"); checkedCases++;
        using var otherKey = WindowsKeyStore.LoadOrCreate("sample-addon", accountId, root, allowCreation: true);
        Require(firstKey.PublicKey != otherKey.PublicKey, "DPAPI_SCOPE_COLLISION"); checkedCases++;
        var files = new[] { "sample-tool", "sample-addon" }.Select(product => Path.Combine(root,
            Convert.ToHexStringLower(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(product))), accountId, "device.key")).ToArray();
        var original = File.ReadAllBytes(files[0]); File.WriteAllBytes(files[0], [1, 2, 3]);
        Reject(() => WindowsKeyStore.LoadOrCreate("sample-tool", accountId, root), "dpapi-corruption");
        Require(File.ReadAllBytes(files[0]).SequenceEqual(new byte[] { 1, 2, 3 }), "CORRUPTION_REPLACED_KEY"); checkedCases++;
        File.WriteAllBytes(files[0], original);
        // Copying ciphertext across product/account scopes must never produce a replacement identity.
        File.WriteAllBytes(files[1], original);
        Reject(() => WindowsKeyStore.LoadOrCreate("sample-addon", accountId, root), "dpapi-entropy"); checkedCases++;
        File.Delete(files[0]);
        Reject(() => WindowsKeyStore.LoadOrCreate("sample-tool", accountId, root), "dpapi-missing");
        Require(!File.Exists(files[0]), "MISSING_KEY_RECREATED"); checkedCases++;
    }
    finally
    {
        var exact = Path.GetFullPath(root); var parent = Path.GetFullPath(Path.GetTempPath());
        Require(exact.StartsWith(parent, StringComparison.OrdinalIgnoreCase) && Path.GetFileName(exact).StartsWith("plk-sdk-"), "CLEANUP_SCOPE");
        if (Directory.Exists(exact)) Directory.Delete(exact, true);
    }
}
Console.WriteLine(JsonSerializer.Serialize(new { checks = checkedCases, windows = OperatingSystem.IsWindows() }));
