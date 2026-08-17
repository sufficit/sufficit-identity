using NUnit.Framework;

namespace Sufficit.Identity.BrowserTests;

/// <summary>
/// Skips a browser test run when no Identity server is listening at the
/// configured base URL (SUFFICIT_TEST_BASE_URL, default
/// https://localhost:5001). The suite is meant to run against a live
/// deployment; on CI (no server fixture) every test self-skips instead of
/// failing on connection refused.
/// </summary>
internal static class TestServerProbe
{
    private static readonly Lazy<(bool Reachable, string BaseUrl)> Probe = new(() =>
    {
        var baseUrl = Environment.GetEnvironmentVariable("SUFFICIT_TEST_BASE_URL")
            ?? "https://localhost:5001";
        var handler = new HttpClientHandler
        {
            ServerCertificateCustomValidationCallback =
                HttpClientHandler.DangerousAcceptAnyServerCertificateValidator,
        };
        using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(3) };
        try
        {
            using var _ = client.Send(new HttpRequestMessage(HttpMethod.Head, baseUrl));
            // Any HTTP response — even a 404/redirect — means a server is up.
            return (true, baseUrl);
        }
        catch (Exception)
        {
            return (false, baseUrl);
        }
    });

    /// <summary>Call from [SetUp]; ignores the test when the server is down.</summary>
    public static void EnsureServerAvailable()
    {
        var (reachable, baseUrl) = Probe.Value;
        if (!reachable)
        {
            Assert.Ignore(
                $"No Identity server at {baseUrl} (set SUFFICIT_TEST_BASE_URL or start one). " +
                "Browser tests run against a live deployment.");
        }
    }
}
