using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Xunit;

namespace Sufficit.Identity.Tests.Infrastructure;

/// <summary>
/// Thin wrappers around the "/test-only/*" endpoints registered by
/// <see cref="SufficitIdentityTestFactory"/> (never present in the real
/// src/server host) — see that file for the rationale.
/// </summary>
internal static class TestOnlyEndpoints
{
    /// <summary>
    /// Signs the named user into the shared HttpClient's cookie container via
    /// the ASP.NET Core Identity application cookie, so subsequent requests
    /// on the SAME <paramref name="client"/> (e.g. GET /connect/authorize,
    /// POST ~/connect/device) are treated as an authenticated browser session.
    /// </summary>
    public static async Task SignInAsync(HttpClient client, string username)
    {
        var (status, _) = await client.PostFormAsync("/test-only/signin", new Dictionary<string, string>
        {
            ["username"] = username,
        });
        Assert.Equal(HttpStatusCode.OK, status);
    }

    /// <summary>
    /// Fetches a real antiforgery token pair: the cookie half lands in
    /// <paramref name="client"/>'s cookie container automatically, and the
    /// request-token half is returned so the caller can attach it as the
    /// "__RequestVerificationToken" form field on a subsequent POST.
    /// </summary>
    public static async Task<string> GetAntiforgeryTokenAsync(HttpClient client)
    {
        var response = await client.GetAsync("/test-only/antiforgery");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var body = await response.Content.ReadFromJsonAsync<JsonElement>();
        var token = body.GetProperty("requestToken").GetString();
        Assert.False(string.IsNullOrEmpty(token));
        return token!;
    }
}
