using System.Security.Cryptography;
using System.Text.Json;
using Org.BouncyCastle.Math.EC.Rfc8032;

namespace ProductLicenseKit;

public sealed record EnrollmentContext(string ChallengeId, string AccountId, string GroupId, Fingerprint Fingerprint);
public sealed record LicenseChallengeContext(string ChallengeId, string AccountId, string DeviceId, string EditionId,
    long Generation, string Channel = "stable");

/// <summary>Owns either an Ed25519 seed or a caller-supplied RSA signing provider. No private export API.</summary>
public sealed class DeviceKey : IDisposable
{
    private readonly byte[]? seed;
    private readonly RSA? rsa;
    private bool disposed;
    public string PublicKey { get; }
    private DeviceKey(ReadOnlySpan<byte> seed)
    {
        Protocol.Require(seed.Length == 32, "INVALID_SEED");
        this.seed = seed.ToArray();
        var publicKey = new byte[32];
        Ed25519.GeneratePublicKey(this.seed, 0, publicKey, 0);
        PublicKey = Protocol.PublicPem(publicKey);
    }
    private DeviceKey(RSA rsa)
    {
        ValidateRsa(rsa); this.rsa = rsa;
        PublicKey = rsa.ExportSubjectPublicKeyInfoPem().ReplaceLineEndings("\n").TrimEnd() + "\n";
    }
    public static DeviceKey FromEd25519Seed(ReadOnlySpan<byte> seed) => new(seed);
    public static DeviceKey CreateEd25519()
    {
        var seed = RandomNumberGenerator.GetBytes(32);
        try { return new DeviceKey(seed); }
        finally { CryptographicOperations.ZeroMemory(seed); }
    }
    /// <summary>Transfers ownership of the RSA provider only on successful construction.</summary>
    public static DeviceKey FromRsa(RSA provider) => new(provider);
    internal static void ValidateRsa(RSA provider)
    {
        var parameters = provider.ExportParameters(false);
        Protocol.Require(provider.KeySize == 2048 && parameters.Modulus?.Length == 256 &&
            parameters.Exponent is not null && parameters.Exponent.AsSpan().SequenceEqual(new byte[] { 1, 0, 1 }), "INVALID_DEVICE_KEY");
    }
    public string SignEnrollmentChallenge(string message, EnrollmentContext expected)
    {
        var payload = JsonSerializer.SerializeToElement(new { groupId = expected.GroupId, publicKey = PublicKey,
            thumbprint = Protocol.DeviceThumbprint(PublicKey), fingerprint = new { schema = expected.Fingerprint.Schema, digest = expected.Fingerprint.Digest } });
        return Sign(message, "enroll", expected.ChallengeId, expected.AccountId, payload);
    }
    public string SignLicenseChallenge(string message, LicenseChallengeContext expected)
    {
        Protocol.Require(expected.Channel is "stable" or "beta" && expected.Generation > 0, "INVALID_CHALLENGE");
        var payload = JsonSerializer.SerializeToElement(new { deviceId = expected.DeviceId, editionId = expected.EditionId,
            channel = expected.Channel, generation = expected.Generation });
        return Sign(message, "license", expected.ChallengeId, expected.AccountId, payload);
    }
    private string Sign(string message, string kind, string challengeId, string accountId, JsonElement payload)
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        Protocol.Require(Protocol.Utf8.GetByteCount(message) < 16384, "INVALID_CHALLENGE");
        var challenge = Protocol.ParseJson(Protocol.Utf8.GetBytes(message));
        Protocol.Require(challenge.ValueKind == JsonValueKind.Array && challenge.GetArrayLength() == 7, "INVALID_CHALLENGE");
        Protocol.Require(challenge[0].ValueKind == JsonValueKind.String && challenge[0].GetString() == "product-license-kit" &&
            challenge[1].ValueKind == JsonValueKind.Number && challenge[1].TryGetInt32(out var version) && version == 1 &&
            challenge[2].GetString() == kind && challenge[3].GetString() == challengeId && challenge[4].GetString() == accountId &&
            Guid.TryParseExact(challengeId, "D", out _) && Guid.TryParseExact(accountId, "D", out _) &&
            JsonElement.DeepEquals(challenge[5], payload) && challenge[6].ValueKind == JsonValueKind.String &&
            Protocol.DecodeBase64Url(challenge[6].GetString()!).Length == 32, "CHALLENGE_SCOPE_MISMATCH");
        var bytes = Protocol.Utf8.GetBytes(message);
        if (rsa is not null) return Protocol.Base64Url(rsa.SignData(bytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pss));
        var signature = new byte[64];
        Ed25519.Sign(seed!, 0, bytes, 0, bytes.Length, signature, 0);
        return Protocol.Base64Url(signature);
    }
    public void Dispose()
    {
        if (disposed) return;
        disposed = true;
        if (seed is not null) CryptographicOperations.ZeroMemory(seed);
        rsa?.Dispose();
    }
}
