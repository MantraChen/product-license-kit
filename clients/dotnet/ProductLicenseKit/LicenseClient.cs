using System.Net.Http.Headers;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace ProductLicenseKit;

/// <summary>Headless bearer API client. Requests are never automatically retried or redirected.</summary>
public sealed class LicenseClient : IDisposable
{
    private readonly Uri origin;
    private readonly HttpClient http;
    public LicenseClient(string baseUrl)
    {
        Protocol.Require(Uri.TryCreate(baseUrl, UriKind.Absolute, out var parsed) && parsed.UserInfo.Length == 0 &&
            parsed.AbsolutePath == "/" && parsed.Query.Length == 0 && parsed.Fragment.Length == 0, "INVALID_SERVER_URL");
        origin = parsed!;
        Protocol.Require(origin.Scheme == "https" || origin.Scheme == "http" &&
            origin.Host is "127.0.0.1" or "localhost" or "[::1]", "HTTPS_REQUIRED");
        http = new HttpClient(new HttpClientHandler { AllowAutoRedirect = false, UseCookies = false }) { Timeout = Timeout.InfiniteTimeSpan };
    }
    public async Task<JsonElement> RequestAsync(string path, object? body = null, string? accessToken = null,
        string? idempotencyKey = null, CancellationToken cancellationToken = default)
    {
        Protocol.Require(path.Length <= 8192 && Regex.IsMatch(path, @"\A/v1/[A-Za-z0-9/_.-]+(?:\?[A-Za-z0-9_%=&.~-]*)?\z") &&
            !path.Split('?')[0].Split('/').Any(p => p is "." or ".."), "INVALID_API_PATH");
        Protocol.Require(accessToken is null || Regex.IsMatch(accessToken, "\\A[A-Za-z0-9_-]{32,512}\\z"), "INVALID_ACCESS_TOKEN");
        Protocol.Require(idempotencyKey is null || Regex.IsMatch(idempotencyKey, "\\A[A-Za-z0-9_-]{16,128}\\z"), "INVALID_IDEMPOTENCY_KEY");
        using var request = new HttpRequestMessage(body is null ? HttpMethod.Get : HttpMethod.Post, new Uri(origin, path));
        if (accessToken is not null) request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        if (idempotencyKey is not null) request.Headers.Add("Idempotency-Key", idempotencyKey);
        if (body is not null)
        {
            var bytes = JsonSerializer.SerializeToUtf8Bytes(body);
            Protocol.Require(bytes.Length <= 16384, "REQUEST_TOO_LARGE");
            request.Content = new ByteArrayContent(bytes);
            request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
        }
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(TimeSpan.FromSeconds(10));
        using var response = await http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, deadline.Token).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode) throw new LicenseException("API_REQUEST_FAILED", (int)response.StatusCode);
        const int maxResponse = 1048576;
        Protocol.Require(response.Content.Headers.ContentLength is null or <= maxResponse, "RESPONSE_TOO_LARGE");
        using var stream = await response.Content.ReadAsStreamAsync(deadline.Token).ConfigureAwait(false);
        using var output = new MemoryStream();
        var buffer = new byte[8192];
        int read;
        while ((read = await stream.ReadAsync(buffer, deadline.Token).ConfigureAwait(false)) != 0)
        {
            Protocol.Require(output.Length + read <= maxResponse, "RESPONSE_TOO_LARGE");
            output.Write(buffer, 0, read);
        }
        return Protocol.ParseJson(output.ToArray());
    }
    public void Dispose() => http.Dispose();
}
