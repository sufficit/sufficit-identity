using System.Net;
using Microsoft.AspNetCore.Mvc.Testing;
using Sufficit.Identity.Tests.Infrastructure;
using Xunit;

namespace Sufficit.Identity.Tests;

[Collection(StsCollection.Name)]
public sealed class PasswordLoginControllerTests(
    SufficitIdentityTestFactory factory)
{
    [Fact]
    public async Task Password_login_issues_cookie_on_normal_http_response()
    {
        using var client = CreateClient();
        var antiforgeryToken =
            await TestOnlyEndpoints.GetAntiforgeryTokenAsync(client);

        using var response = await client.PostAsync(
            "/account/login/password",
            Form(
                antiforgeryToken,
                TestDataSeeder.DefaultUsername,
                TestDataSeeder.DefaultPassword,
                "/connect/authorize?client_id=test-client"));

        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Assert.Equal(
            "/connect/authorize?client_id=test-client",
            response.Headers.Location?.OriginalString);
        Assert.Contains(
            response.Headers.GetValues("Set-Cookie"),
            value => value.Contains(
                ".AspNetCore.Identity.Application=",
                StringComparison.Ordinal));
    }

    [Fact]
    public async Task Password_login_rejects_missing_antiforgery_without_signing_in()
    {
        using var client = CreateClient();

        using var response = await client.PostAsync(
            "/account/login/password",
            Form(
                antiforgeryToken: null,
                TestDataSeeder.DefaultUsername,
                TestDataSeeder.DefaultPassword,
                "/protected"));

        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Assert.Equal(
            "/account/login?error=request_expired&returnUrl=%2Fprotected",
            response.Headers.Location?.OriginalString);
        Assert.False(
            response.Headers.TryGetValues("Set-Cookie", out var cookies)
            && cookies.Any(value => value.Contains(
                ".AspNetCore.Identity.Application=",
                StringComparison.Ordinal)));
    }

    [Fact]
    public async Task Password_login_does_not_redirect_off_origin()
    {
        using var client = CreateClient();
        var antiforgeryToken =
            await TestOnlyEndpoints.GetAntiforgeryTokenAsync(client);

        using var response = await client.PostAsync(
            "/account/login/password",
            Form(
                antiforgeryToken,
                TestDataSeeder.DefaultUsername,
                TestDataSeeder.DefaultPassword,
                "https://attacker.invalid/collect"));

        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Assert.Equal("/", response.Headers.Location?.OriginalString);
    }

    private HttpClient CreateClient() => factory.CreateClient(
        new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
        });

    private static FormUrlEncodedContent Form(
        string? antiforgeryToken,
        string userName,
        string password,
        string returnUrl)
    {
        var values = new Dictionary<string, string>
        {
            ["UserName"] = userName,
            ["Password"] = password,
            ["ReturnUrl"] = returnUrl,
        };
        if (!string.IsNullOrWhiteSpace(antiforgeryToken))
        {
            values["__RequestVerificationToken"] = antiforgeryToken;
        }

        return new FormUrlEncodedContent(values);
    }
}
