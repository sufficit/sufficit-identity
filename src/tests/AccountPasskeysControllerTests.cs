using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.Tests.Infrastructure;
using Xunit;

namespace Sufficit.Identity.Tests;

[Collection(StsCollection.Name)]
public sealed class AccountPasskeysControllerTests(
    SufficitIdentityTestFactory factory)
{
    [Fact]
    public async Task Authenticated_creation_options_issue_a_real_webauthn_challenge()
    {
        var username = await CreateUserAsync();
        using var client = CreateClient();
        await TestOnlyEndpoints.SignInAsync(client, username);
        var token = await TestOnlyEndpoints.GetAntiforgeryTokenAsync(client);

        using var response = await client.PostAsync(
            "/account/passkeys/creation-options",
            Form(token));
        var body = await response.Content.ReadFromJsonAsync<JsonElement>();

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.False(string.IsNullOrWhiteSpace(
            body.GetProperty("challenge").GetString()));
        Assert.Equal(
            username,
            body.GetProperty("user").GetProperty("name").GetString());
        Assert.True(body.TryGetProperty("rp", out _));
    }

    [Fact]
    public async Task Registration_endpoints_require_authentication_and_antiforgery()
    {
        using var anonymous = CreateClient();
        using var anonymousResponse = await anonymous.PostAsync(
            "/account/passkeys/creation-options",
            new FormUrlEncodedContent([]));
        Assert.Equal(HttpStatusCode.Unauthorized, anonymousResponse.StatusCode);

        var username = await CreateUserAsync();
        using var authenticated = CreateClient();
        await TestOnlyEndpoints.SignInAsync(authenticated, username);
        using var missingToken = await authenticated.PostAsync(
            "/account/passkeys/creation-options",
            new FormUrlEncodedContent([]));
        var body = await missingToken.Content.ReadFromJsonAsync<JsonElement>();

        Assert.Equal(HttpStatusCode.BadRequest, missingToken.StatusCode);
        Assert.Contains(
            body.GetProperty("errors").EnumerateArray(),
            error => error.GetProperty("code").GetString()
                == "antiforgery-invalid");
    }

    [Fact]
    public async Task Registration_validation_returns_a_stable_error_contract()
    {
        var username = await CreateUserAsync();
        using var client = CreateClient();
        await TestOnlyEndpoints.SignInAsync(client, username);
        var token = await TestOnlyEndpoints.GetAntiforgeryTokenAsync(client);

        using var response = await client.PostAsync(
            "/account/passkeys/register",
            Form(token, ("credentialJson", ""), ("name", "workstation")));
        var body = await response.Content.ReadFromJsonAsync<JsonElement>();

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.False(body.GetProperty("succeeded").GetBoolean());
        Assert.Contains(
            body.GetProperty("errors").EnumerateArray(),
            error => error.GetProperty("code").GetString()
                == "passkey-credential-required");
    }

    [Fact]
    public async Task Anonymous_request_options_support_discoverable_credentials_and_antiforgery()
    {
        using var client = CreateClient();
        var token = await TestOnlyEndpoints.GetAntiforgeryTokenAsync(client);

        using var response = await client.PostAsync(
            "/account/passkeys/request-options",
            Form(token));
        var body = await response.Content.ReadFromJsonAsync<JsonElement>();

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.False(string.IsNullOrWhiteSpace(
            body.GetProperty("challenge").GetString()));
        Assert.False(body.TryGetProperty("allowCredentials", out var allowed)
            && allowed.GetArrayLength() > 0);
    }

    [Fact]
    public async Task Authentication_endpoint_rejects_missing_antiforgery_and_payload()
    {
        using var client = CreateClient();
        using var missingToken = await client.PostAsync(
            "/account/passkeys/authenticate",
            new FormUrlEncodedContent([]));
        Assert.Equal(HttpStatusCode.BadRequest, missingToken.StatusCode);

        var token = await TestOnlyEndpoints.GetAntiforgeryTokenAsync(client);
        using var missingCredential = await client.PostAsync(
            "/account/passkeys/authenticate",
            Form(token));
        var body = await missingCredential.Content.ReadFromJsonAsync<JsonElement>();

        Assert.Equal(HttpStatusCode.BadRequest, missingCredential.StatusCode);
        Assert.Contains(
            body.GetProperty("errors").EnumerateArray(),
            error => error.GetProperty("code").GetString()
                == "passkey-credential-required");
    }

    private HttpClient CreateClient() =>
        factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
        });

    private async Task<string> CreateUserAsync()
    {
        var username = $"passkey-http-{Guid.NewGuid():N}";
        await using var scope = factory.Services.CreateAsyncScope();
        var users = scope.ServiceProvider
            .GetRequiredService<UserManager<ApplicationUser>>();
        await TestDataSeeder.CreateUserAsync(
            users,
            username,
            TestDataSeeder.DefaultPassword);
        return username;
    }

    private static FormUrlEncodedContent Form(
        string token,
        params (string Key, string Value)[] values)
    {
        var form = new Dictionary<string, string>
        {
            ["__RequestVerificationToken"] = token,
        };
        foreach (var (key, value) in values)
        {
            form[key] = value;
        }

        return new FormUrlEncodedContent(form);
    }
}
