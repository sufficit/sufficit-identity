using System.Net;
using Sufficit.Identity.Tests.Infrastructure;
using Xunit;

namespace Sufficit.Identity.Tests;

public sealed class CorsTests
{
    [Fact]
    public async Task Preflight_returns_headers_for_an_explicit_browser_origin()
    {
        const string origin = "https://blazor.tests.local:26508";
        using var factory = SufficitIdentityTestFactory.CreateIsolated(new Dictionary<string, string?>
        {
            ["Sufficit:Identity:Cors:Enabled"] = "true",
            ["Sufficit:Identity:Cors:AllowedOrigins:0"] = origin,
        });
        await ((IAsyncLifetime)factory).InitializeAsync();

        using var request = new HttpRequestMessage(HttpMethod.Options, "/connect/userinfo");
        request.Headers.TryAddWithoutValidation("Origin", origin);
        request.Headers.TryAddWithoutValidation("Access-Control-Request-Method", "GET");
        request.Headers.TryAddWithoutValidation("Access-Control-Request-Headers", "authorization");

        using var response = await factory.CreateClient().SendAsync(request);

        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
        Assert.Equal(origin,
            response.Headers.GetValues("Access-Control-Allow-Origin").Single());
        Assert.Contains("authorization",
            response.Headers.GetValues("Access-Control-Allow-Headers").Single(),
            StringComparison.OrdinalIgnoreCase);
        Assert.Contains("GET",
            response.Headers.GetValues("Access-Control-Allow-Methods").Single(),
            StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Preflight_does_not_reflect_an_unconfigured_origin()
    {
        const string allowedOrigin = "https://blazor.tests.local:26508";
        const string rejectedOrigin = "https://evil.tests.local";
        using var factory = SufficitIdentityTestFactory.CreateIsolated(new Dictionary<string, string?>
        {
            ["Sufficit:Identity:Cors:Enabled"] = "true",
            ["Sufficit:Identity:Cors:AllowedOrigins:0"] = allowedOrigin,
        });
        await ((IAsyncLifetime)factory).InitializeAsync();

        using var request = new HttpRequestMessage(HttpMethod.Options, "/connect/userinfo");
        request.Headers.TryAddWithoutValidation("Origin", rejectedOrigin);
        request.Headers.TryAddWithoutValidation("Access-Control-Request-Method", "GET");
        request.Headers.TryAddWithoutValidation("Access-Control-Request-Headers", "authorization");

        using var response = await factory.CreateClient().SendAsync(request);

        Assert.DoesNotContain("Access-Control-Allow-Origin", response.Headers.Select(header => header.Key));
    }
}
