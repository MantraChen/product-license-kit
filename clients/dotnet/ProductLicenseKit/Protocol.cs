using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Org.BouncyCastle.Math.EC.Rfc8032;

namespace ProductLicenseKit;

public sealed class LicenseException(string code, int? status = null) : Exception(code)
{
    public string Code { get; } = code;
    public int? Status { get; } = status;
}

public sealed record Fingerprint(string Schema, string Digest);
public sealed record LicenseScope(string Issuer, string ProductId, string EditionId, string AccountId,
    string DeviceId, string DevicePublicKey, Fingerprint Fingerprint, string Channel = "stable", long? Generation = null);
public sealed record DistributionScope(string DistributionId, string EditionId, string ReleaseId);

public static class Protocol
{
    internal static readonly UTF8Encoding Utf8 = new(false, true);
    internal static readonly byte[] Ed25519Prefix = Convert.FromHexString("302a300506032b6570032100");
    internal static void Require(bool condition, string code)
    {
        if (!condition) throw new LicenseException(code);
    }
    public static string Base64Url(ReadOnlySpan<byte> value) => Convert.ToBase64String(value)
        .TrimEnd('=').Replace('+', '-').Replace('/', '_');
    public static byte[] DecodeBase64Url(string value)
    {
        Require(value.Length is > 0 and < 16384 && value.Length % 4 != 1 &&
            value.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_'), "INVALID_BASE64URL");
        var bytes = Convert.FromBase64String(value.Replace('-', '+').Replace('_', '/') + new string('=', (4 - value.Length % 4) % 4));
        Require(Base64Url(bytes) == value, "NONCANONICAL_BASE64URL");
        return bytes;
    }
    internal static string Hex(ReadOnlySpan<byte> value) => Convert.ToHexStringLower(value);
    internal static byte[] PublicDer(string pem)
    {
        Require(pem.Length <= 2048 && Regex.IsMatch(pem,
            @"\A\s*-----BEGIN PUBLIC KEY-----\r?\n[A-Za-z0-9+/=\r\n]+-----END PUBLIC KEY-----\s*\z"), "INVALID_PUBLIC_KEY");
        var encoded = pem.Replace("-----BEGIN PUBLIC KEY-----", "").Replace("-----END PUBLIC KEY-----", "");
        encoded = string.Concat(encoded.Where(c => !char.IsWhiteSpace(c)));
        byte[] der;
        try { der = Convert.FromBase64String(encoded); }
        catch (FormatException) { throw new LicenseException("INVALID_PUBLIC_KEY"); }
        Require(Convert.ToBase64String(der) == encoded, "INVALID_PUBLIC_KEY");
        return der;
    }
    internal static byte[] ServerPublicKey(string pem)
    {
        var der = PublicDer(pem);
        Require(der.Length == 44 && der.AsSpan(0, 12).SequenceEqual(Ed25519Prefix), "ED25519_REQUIRED");
        return der[12..];
    }
    public static string DeviceThumbprint(string pem)
    {
        var der = PublicDer(pem);
        if (der.Length == 44) _ = ServerPublicKey(pem);
        else
        {
            using var rsa = RSA.Create();
            try
            {
                rsa.ImportSubjectPublicKeyInfo(der, out var read);
                Require(read == der.Length && rsa.ExportSubjectPublicKeyInfo().AsSpan().SequenceEqual(der), "INVALID_DEVICE_KEY");
                DeviceKey.ValidateRsa(rsa);
            }
            catch (CryptographicException) { throw new LicenseException("INVALID_DEVICE_KEY"); }
        }
        return Hex(SHA256.HashData(der));
    }
    internal static string PublicPem(ReadOnlySpan<byte> key) =>
        "-----BEGIN PUBLIC KEY-----\n" + Convert.ToBase64String([.. Ed25519Prefix, .. key]) + "\n-----END PUBLIC KEY-----\n";

    public static JsonElement ParseJson(ReadOnlySpan<byte> bytes)
    {
        using var document = JsonDocument.Parse(Utf8.GetString(bytes), new JsonDocumentOptions { MaxDepth = 16 });
        CheckDuplicates(document.RootElement);
        return document.RootElement.Clone();
    }
    private static void CheckDuplicates(JsonElement element)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in element.EnumerateObject())
            {
                Require(names.Add(property.Name), "DUPLICATE_PROPERTY");
                CheckDuplicates(property.Value);
            }
        }
        else if (element.ValueKind == JsonValueKind.Array)
            foreach (var value in element.EnumerateArray()) CheckDuplicates(value);
    }
    internal static void Shape(JsonElement value, params string[] names) => Require(
        value.ValueKind == JsonValueKind.Object && value.EnumerateObject().Count() == names.Length &&
        names.All(name => value.TryGetProperty(name, out _)), "INVALID_CLAIMS");
    internal static string Text(JsonElement value, string name)
    {
        Require(value.TryGetProperty(name, out var property) && property.ValueKind == JsonValueKind.String, "INVALID_CLAIMS");
        return property.GetString()!;
    }
    internal static long Integer(JsonElement value, string name)
    {
        Require(value.TryGetProperty(name, out var property) && property.ValueKind == JsonValueKind.Number &&
            property.TryGetInt64(out _) , "INVALID_CLAIMS");
        var number = property.GetInt64();
        Require(number is >= -9007199254740991 and <= 9007199254740991, "INVALID_CLAIMS");
        return number;
    }
    public static JsonElement VerifyEnvelope(string token, string trustedPublicKey, string expectedType)
    {
        Require(token.Length < 16384, "INVALID_ENVELOPE");
        var parts = token.Split('.');
        Require(parts.Length == 3, "INVALID_ENVELOPE");
        var publicKey = ServerPublicKey(trustedPublicKey);
        var header = ParseJson(DecodeBase64Url(parts[0]));
        Shape(header, "alg", "typ", "kid");
        Require(Text(header, "alg") == "EdDSA" && Text(header, "typ") == expectedType &&
            Text(header, "kid") == Hex(SHA256.HashData(PublicDer(trustedPublicKey)))[..24], "INVALID_ENVELOPE_HEADER");
        var body = DecodeBase64Url(parts[1]);
        var signature = DecodeBase64Url(parts[2]);
        var signed = Utf8.GetBytes(parts[0] + "." + parts[1]);
        Require(signature.Length == 64 && Ed25519.Verify(signature, 0, publicKey, 0, signed, 0, signed.Length), "INVALID_SIGNATURE");
        return ParseJson(body);
    }
    public static JsonElement VerifyLicense(string token, string trustedPublicKey, LicenseScope expected, DateTimeOffset? now = null)
    {
        var claims = VerifyEnvelope(token, trustedPublicKey, "plk-license");
        Shape(claims, "iss", "aud", "sub", "edition", "device", "channel", "fingerprint", "keyThumbprint", "generation", "ownership", "iat", "nbf", "exp");
        Require(expected.Channel is "stable" or "beta", "INVALID_CHANNEL");
        foreach (var (name, value) in new[] { ("iss", expected.Issuer), ("aud", expected.ProductId), ("sub", expected.AccountId),
            ("edition", expected.EditionId), ("device", expected.DeviceId), ("channel", expected.Channel) })
            Require(Text(claims, name) == value, "LICENSE_SCOPE_MISMATCH");
        var fingerprint = claims.GetProperty("fingerprint");
        Shape(fingerprint, "schema", "digest");
        Require(Regex.IsMatch(expected.Fingerprint.Digest, "\\A[a-f0-9]{64}\\z") &&
            Text(fingerprint, "schema") == expected.Fingerprint.Schema && Text(fingerprint, "digest") == expected.Fingerprint.Digest &&
            Text(claims, "keyThumbprint") == DeviceThumbprint(expected.DevicePublicKey), "LICENSE_SCOPE_MISMATCH");
        var generation = Integer(claims, "generation");
        Require(generation > 0 && Text(claims, "ownership") == "perpetual", "INVALID_CLAIMS");
        Require(expected.Generation is null || expected.Generation == generation, "LICENSE_SCOPE_MISMATCH");
        var seconds = (now ?? DateTimeOffset.UtcNow).ToUnixTimeSeconds();
        var issued = Integer(claims, "iat"); var notBefore = Integer(claims, "nbf"); var expires = Integer(claims, "exp");
        Require(issued <= seconds && notBefore <= seconds && expires > seconds && expires > issued && expires > notBefore,
            "LICENSE_EXPIRED_OR_NOT_YET_VALID");
        return claims;
    }
    public static JsonElement VerifyDistribution(string token, string trustedPublicKey, ReadOnlySpan<byte> artifact, DistributionScope expected)
    {
        var manifest = VerifyEnvelope(token, trustedPublicKey, "plk-distribution");
        Shape(manifest, "distributionId", "editionId", "releaseId", "sha256", "issuedAt");
        _ = Integer(manifest, "issuedAt");
        Require(Text(manifest, "distributionId") == expected.DistributionId && Text(manifest, "editionId") == expected.EditionId &&
            Text(manifest, "releaseId") == expected.ReleaseId && Text(manifest, "sha256") == Hex(SHA256.HashData(artifact)), "DISTRIBUTION_MISMATCH");
        return manifest;
    }
}
