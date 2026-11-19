using System.Security.Cryptography;
using System.Text.Json;
using ProductLicenseKit;

internal static class Interop
{
    private static string Text(JsonElement value, string name) => value.GetProperty(name).GetString()!;
    private static void Check(bool condition) { if (!condition) throw new Exception("INTEROP_ASSERTION_FAILED"); }
    private static void Reject(Action action)
    {
        try { action(); } catch (Exception) { return; }
        throw new Exception("ACCEPTED_INVALID_INPUT");
    }
    private static async Task RejectRequest(Func<Task<JsonElement>> action, string code, int? status = null)
    {
        try { await action(); }
        catch (LicenseException error) when (error.Code == code && (status is null || error.Status == status)) { return; }
        catch (LicenseException error) { throw new Exception($"UNEXPECTED_API_RESULT:{error.Code}:{error.Status}:expected:{code}:{status}"); }
        throw new Exception("ACCEPTED_INVALID_REQUEST");
    }
    internal static async Task Run(JsonElement config)
    {
        using var client = new LicenseClient(Text(config, "origin"));
        var trusted = Text(config, "publicKey");
        var admin = Text(config, "adminToken");
        var now = DateTimeOffset.FromUnixTimeMilliseconds(config.GetProperty("now").GetInt64());
        var checks = 0;
        DeviceKey? stored = null;
        if (OperatingSystem.IsWindows())
        {
            stored = WindowsKeyStore.LoadOrCreate("sdk-interoperability", Text(config, "storageAccountId"), Text(config, "storageRoot"));
            Check(stored.PublicKey == Text(config, "protectedPublicKey")); checks++;
            var hardware = HardwareIdentity.ReadWindows("sdk-interoperability", "sdk-hwid-v1");
            Check(hardware.Digest == Text(config.GetProperty("fingerprint"), "digest")); checks++;
        }
        using var storedLifetime = stored;
        foreach (var subject in config.GetProperty("cases").EnumerateArray())
        {
            using var key = Text(subject, "algorithm") == "Ed25519" ? stored ?? DeviceKey.CreateEd25519() : DeviceKey.FromRsa(RSA.Create(2048));
            var session = await client.RequestAsync("/v1/auth/register", new { ticket = Text(subject, "ticket"), proof = Text(subject, "proof") });
            var accountId = Text(session, "accountId"); var access = Text(session, "accessToken");
            var order = await client.RequestAsync("/v1/orders", new { offerId = "buy-tool-1" }, access, Guid.NewGuid().ToString("D"));
            await client.RequestAsync("/v1/admin/orders/" + Text(order, "orderId") + "/confirm", new { method = "manual-bank",
                reference = Guid.NewGuid().ToString("D"), amount = 5000, currency = "CNY" }, admin);
            var fingerprint = new Fingerprint("sdk-test-v1", new string('a', 64));
            var enrollment = await client.RequestAsync("/v1/devices/challenges", new { groupId = "desktop", publicKey = key.PublicKey,
                fingerprint = new { schema = fingerprint.Schema, digest = fingerprint.Digest } }, access);
            var enrollSignature = key.SignEnrollmentChallenge(Text(enrollment, "message"), new EnrollmentContext(
                Text(enrollment, "challengeId"), accountId, "desktop", fingerprint));
            var activateBody = new { challengeId = Text(enrollment, "challengeId"), signature = enrollSignature };
            var activateKey = Guid.NewGuid().ToString("D");
            var binding = await client.RequestAsync("/v1/devices/activate", activateBody, access, activateKey);
            var replayed = await client.RequestAsync("/v1/devices/activate", activateBody, access, activateKey);
            Check(JsonElement.DeepEquals(binding, replayed)); checks++;
            var deviceId = Text(binding, "deviceId"); var generation = binding.GetProperty("generation").GetInt64();
            var challenge = await client.RequestAsync("/v1/licenses/challenges", new { deviceId, editionId = "tool-1", channel = "stable" });
            var signature = key.SignLicenseChallenge(Text(challenge, "message"), new LicenseChallengeContext(
                Text(challenge, "challengeId"), accountId, deviceId, "tool-1", generation));
            var issueBody = new { challengeId = Text(challenge, "challengeId"), signature };
            var issued = await client.RequestAsync("/v1/licenses/issue", issueBody);
            var token = Text(issued, "token");
            var scope = new LicenseScope("test-issuer", "sample-tool", "tool-1", accountId, deviceId, key.PublicKey, fingerprint, Generation: generation);
            _ = Protocol.VerifyLicense(token, trusted, scope, now); checks++;
            foreach (var invalid in new[] { scope with { Issuer = "other" }, scope with { ProductId = "other" }, scope with { EditionId = "other" },
                scope with { AccountId = Guid.NewGuid().ToString("D") }, scope with { DeviceId = Guid.NewGuid().ToString("D") },
                scope with { Channel = "beta" }, scope with { Generation = generation + 1 },
                scope with { Fingerprint = fingerprint with { Digest = new string('b', 64) } } })
            { Reject(() => Protocol.VerifyLicense(token, trusted, invalid, now)); checks++; }
            Reject(() => Protocol.VerifyLicense(token, trusted, scope, now.AddMinutes(16))); checks++;
            await RejectRequest(() => client.RequestAsync("/v1/licenses/issue", issueBody), "API_REQUEST_FAILED", 401); checks++;
            var vectors = await client.RequestAsync("/v1/test/vectors", new { token }, access);
            foreach (var vector in vectors.EnumerateArray())
            { Reject(() => Protocol.VerifyLicense(Text(vector, "token"), trusted, scope, now)); checks++; }
            var artifact = Convert.FromBase64String(Text(config, "artifact"));
            var distribution = await client.RequestAsync("/v1/admin/distributions", new { accountId, editionId = "tool-1", releaseId = "sdk-test" }, admin, Guid.NewGuid().ToString("D"));
            var distributionId = Text(distribution, "distributionId");
            var finalized = await client.RequestAsync("/v1/admin/distributions/" + distributionId + "/finalize",
                new { sha256 = Convert.ToHexStringLower(SHA256.HashData(artifact)) }, admin);
            var manifest = Text(finalized, "manifest"); var distributionScope = new DistributionScope(distributionId, "tool-1", "sdk-test");
            _ = Protocol.VerifyDistribution(manifest, trusted, artifact, distributionScope); checks++;
            Reject(() => Protocol.VerifyDistribution(manifest, trusted, new byte[] { 1 }, distributionScope)); checks++;
            Reject(() => Protocol.VerifyDistribution(manifest, trusted, artifact, distributionScope with { ReleaseId = "other" })); checks++;
            await client.RequestAsync("/v1/auth/logout", new { }, access);
            await RejectRequest(() => client.RequestAsync("/v1/me", accessToken: access), "API_REQUEST_FAILED", 401); checks++;
        }
        foreach (var path in new[] { "https://other.example/v1/me", "//other.example/v1/me", "/v1/../health", "/v1/%2e%2e/health", "/v1/\\other", "/v1/me#fragment", "/v1/me\r\n" })
        { await RejectRequest(() => client.RequestAsync(path), "INVALID_API_PATH"); checks++; }
        await RejectRequest(() => client.RequestAsync("/v1/test/redirect", accessToken: admin), "API_REQUEST_FAILED", 302); checks++;
        await RejectRequest(() => client.RequestAsync("/v1/test/oversized"), "RESPONSE_TOO_LARGE"); checks++;
        await RejectRequest(() => client.RequestAsync("/v1/test/chunked"), "RESPONSE_TOO_LARGE"); checks++;
        Console.WriteLine(JsonSerializer.Serialize(new { language = "dotnet", cases = config.GetProperty("cases").GetArrayLength(), checks }));
    }
}
