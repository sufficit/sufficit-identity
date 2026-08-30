using System.Net;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Management.Audit;
using Sufficit.Identity.Management.Clients;
using Sufficit.Identity.Management.Controllers;
using Sufficit.Identity.Tests.Infrastructure;
using Xunit;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Sufficit.Identity.Tests;

public sealed partial class ClientsControllerTests
{
    [Fact]
    public async Task Create_without_consent_type_persents_explicit_consent()
    {
        using var factory = new ManagementTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        var client = factory.CreateClient();

        var request = ConfidentialClient($"cc-explicit-{Guid.NewGuid():N}",
            "https://client.tests.local/callback");

        using var response = await client.PostAsJsonAsync("/api/clients", request);
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);

        var body = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal(ConsentTypes.Explicit, body.GetProperty("consentType").GetString());
    }

    [Fact]
    public async Task Create_persists_a_public_https_jwks_uri()
    {
        using var factory = new ManagementTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        var client = factory.CreateClient();
        var request = ConfidentialClient(
            $"cc-jwks-{Guid.NewGuid():N}",
            "https://client.tests.local/callback");
        request.JwksUri = "https://keys.example/jwks.json";

        using var response = await client.PostAsJsonAsync("/api/clients", request);

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<ManagementClientDetail>();
        Assert.Equal(request.JwksUri, body?.JwksUri);
    }

    [Fact]
    public async Task Create_persists_per_application_token_lifetimes()
    {
        using var factory = new ManagementTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        var client = factory.CreateClient();
        var request = new CreateClientRequest
        {
            ClientId = $"cc-lifetime-{Guid.NewGuid():N}",
            ClientSecret = "lifetime-secret",
            GrantTypes = [Permissions.GrantTypes.ClientCredentials],
            AccessTokenLifetimeMinutes = 7 * 24 * 60,
            IdentityTokenLifetimeMinutes = 8,
            RefreshTokenLifetimeDays = 31,
        };

        using var created = await client.PostAsJsonAsync("/api/clients", request);

        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        var body = await created.Content.ReadFromJsonAsync<ManagementClientDetail>();
        Assert.Equal(7 * 24 * 60, body?.AccessTokenLifetimeMinutes);
        Assert.Equal(8, body?.IdentityTokenLifetimeMinutes);
        Assert.Equal(31, body?.RefreshTokenLifetimeDays);

        var (status, token) = await client.PostFormAsync(
            "/connect/token",
            new Dictionary<string, string>
            {
                ["grant_type"] = "client_credentials",
                ["client_id"] = request.ClientId,
                ["client_secret"] = request.ClientSecret!,
            });
        Assert.Equal(HttpStatusCode.OK, status);
        Assert.InRange(
            token.GetProperty("expires_in").GetInt32(),
            7 * 24 * 60 * 60 - 2,
            7 * 24 * 60 * 60);
    }

    [Fact]
    public async Task Detail_exposes_the_effective_global_token_lifetimes()
    {
        using var factory = new ManagementTestFactory(extraConfiguration:
            new Dictionary<string, string?>
            {
                ["Sufficit:Identity:Tokens:AccessTokenLifetimeMinutes"] = "37",
                ["Sufficit:Identity:Tokens:IdentityTokenLifetimeMinutes"] = "13",
                ["Sufficit:Identity:Tokens:RefreshTokenLifetimeDays"] = "2.5",
            });
        await ((IAsyncLifetime)factory).InitializeAsync();
        var client = factory.CreateClient();
        var request = ConfidentialClient(
            $"cc-global-lifetime-{Guid.NewGuid():N}",
            "https://client.tests.local/callback");

        using var created = await client.PostAsJsonAsync("/api/clients", request);

        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        var body = await created.Content.ReadFromJsonAsync<ManagementClientDetail>();
        Assert.NotNull(body);
        Assert.Null(body.AccessTokenLifetimeMinutes);
        Assert.Null(body.IdentityTokenLifetimeMinutes);
        Assert.Null(body.RefreshTokenLifetimeDays);
        Assert.Equal(37, body.GlobalAccessTokenLifetimeMinutes);
        Assert.Equal(13, body.GlobalIdentityTokenLifetimeMinutes);
        Assert.Equal(2.5, body.GlobalRefreshTokenLifetimeDays);
    }

    [Theory]
    [InlineData(0, null, null)]
    [InlineData(10081, null, null)]
    [InlineData(null, 121, null)]
    [InlineData(null, null, 366)]
    public async Task Create_rejects_token_lifetimes_outside_safe_bounds(
        int? accessTokenLifetimeMinutes,
        int? identityTokenLifetimeMinutes,
        int? refreshTokenLifetimeDays)
    {
        using var factory = new ManagementTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        var client = factory.CreateClient();
        var request = new CreateClientRequest
        {
            ClientId = $"cc-invalid-lifetime-{Guid.NewGuid():N}",
            ClientSecret = "lifetime-secret",
            GrantTypes = [Permissions.GrantTypes.ClientCredentials],
            AccessTokenLifetimeMinutes = accessTokenLifetimeMinutes,
            IdentityTokenLifetimeMinutes = identityTokenLifetimeMinutes,
            RefreshTokenLifetimeDays = refreshTokenLifetimeDays,
        };

        using var response = await client.PostAsJsonAsync("/api/clients", request);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Theory]
    [InlineData("http://keys.example/jwks.json")]
    [InlineData("https://127.0.0.1/jwks.json")]
    [InlineData("https://10.0.0.1/jwks.json")]
    public async Task Create_rejects_an_unsafe_jwks_uri(string jwksUri)
    {
        using var factory = new ManagementTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        var client = factory.CreateClient();
        var request = ConfidentialClient(
            $"cc-jwks-invalid-{Guid.NewGuid():N}",
            "https://client.tests.local/callback");
        request.JwksUri = jwksUri;

        using var response = await client.PostAsJsonAsync("/api/clients", request);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Contains("jwks_uri_invalid", await response.Content.ReadAsStringAsync(),
            StringComparison.Ordinal);
    }

    [Fact]
    public async Task Create_with_explicit_implicit_consent_type_is_honored()
    {
        // The default flipped to Explicit, but a caller can still opt into
        // Implicit explicitly (e.g. for a first-party trusted client). This
        // proves the override path works and we did not hardcode Explicit.
        using var factory = new ManagementTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        var client = factory.CreateClient();

        var request = ConfidentialClient($"cc-implicit-{Guid.NewGuid():N}",
            "https://client.tests.local/callback");
        request.ConsentType = "implicit";

        using var response = await client.PostAsJsonAsync("/api/clients", request);
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);

        var body = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal(ConsentTypes.Implicit, body.GetProperty("consentType").GetString());
    }

    [Fact]
    public async Task Create_rejects_public_http_redirect_uri()
    {
        using var factory = new ManagementTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        var client = factory.CreateClient();

        var request = ConfidentialClient($"cc-http-{Guid.NewGuid():N}",
            "http://insecure.example.com/callback");

        using var response = await client.PostAsJsonAsync("/api/clients", request);
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        // BadRequest(string) returns plain text, not JSON — read as string.
        var error = await response.Content.ReadAsStringAsync();
        Assert.Contains("https", error, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("loopback", error, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Create_accepts_http_redirect_uri_for_loopback()
    {
        // Dev convenience: http://localhost and http://127.0.0.1 must still be
        // accepted (local dev servers are plain http). Only public hosts are
        // forced to https.
        using var factory = new ManagementTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        var client = factory.CreateClient();

        var request = ConfidentialClient($"cc-loopback-{Guid.NewGuid():N}",
            "http://localhost:5000/callback");

        using var response = await client.PostAsJsonAsync("/api/clients", request);
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
    }

    [Fact]
    public async Task Create_rejects_redirect_uri_with_fragment()
    {
        // OAuth 2.1 forbids fragments in redirect_uri; rejecting at creation
        // gives the operator early feedback instead of a runtime match failure.
        using var factory = new ManagementTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        var client = factory.CreateClient();

        var request = ConfidentialClient($"cc-fragment-{Guid.NewGuid():N}",
            "https://client.tests.local/callback#section");

        using var response = await client.PostAsJsonAsync("/api/clients", request);
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        // BadRequest(string) returns plain text, not JSON — read as string.
        var error = await response.Content.ReadAsStringAsync();
        Assert.Contains("fragment", error, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Create_accepts_https_redirect_uri()
    {
        using var factory = new ManagementTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        var client = factory.CreateClient();

        var request = ConfidentialClient($"cc-https-{Guid.NewGuid():N}",
            "https://client.tests.local/callback");

        using var response = await client.PostAsJsonAsync("/api/clients", request);
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
    }

    [Fact]
    public async Task Create_projects_pkce_for_confidential_authorization_code_only()
    {
        using var factory = new ManagementTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        var client = factory.CreateClient();

        using var interactiveResponse = await client.PostAsJsonAsync(
            "/api/clients",
            ConfidentialClient(
                $"confidential-code-{Guid.NewGuid():N}",
                "https://client.tests.local/callback"));
        using var serviceResponse = await client.PostAsJsonAsync(
            "/api/clients",
            new CreateClientRequest
            {
                ClientId = $"confidential-service-{Guid.NewGuid():N}",
                ClientSecret = $"secret-{Guid.NewGuid():N}",
                GrantTypes = [Permissions.GrantTypes.ClientCredentials],
            });

        Assert.Equal(HttpStatusCode.Created, interactiveResponse.StatusCode);
        Assert.Equal(HttpStatusCode.Created, serviceResponse.StatusCode);
        var interactive = await interactiveResponse.Content
            .ReadFromJsonAsync<JsonElement>();
        var service = await serviceResponse.Content
            .ReadFromJsonAsync<JsonElement>();
        Assert.Contains(
            interactive.GetProperty("requirements").EnumerateArray(),
            requirement => requirement.GetString()
                == Requirements.Features.ProofKeyForCodeExchange);
        if (service.TryGetProperty("requirements", out var requirements))
        {
            Assert.DoesNotContain(
                requirements.EnumerateArray(),
                requirement => requirement.GetString()
                    == Requirements.Features.ProofKeyForCodeExchange);
        }
    }

    [Fact]
    public async Task Create_rejects_unknown_consent_type()
    {
        using var factory = new ManagementTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        var client = factory.CreateClient();

        var request = ConfidentialClient($"cc-badconsent-{Guid.NewGuid():N}",
            "https://client.tests.local/callback");
        request.ConsentType = "bogus";

        using var response = await client.PostAsJsonAsync("/api/clients", request);
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task Create_rejects_unknown_grant_type_before_persisting_client()
    {
        using var factory = new ManagementTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        var client = factory.CreateClient();

        var request = ConfidentialClient(
            $"cc-badgrant-{Guid.NewGuid():N}",
            "https://client.tests.local/callback");
        request.GrantTypes = ["urn:example:grant:made-up"];

        using var response = await client.PostAsJsonAsync("/api/clients", request);
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Contains(
            "unsupported_grant_type",
            await response.Content.ReadAsStringAsync(),
            StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Create_with_require_par_persists_the_par_requirement()
    {
        using var factory = new ManagementTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        var client = factory.CreateClient();

        var request = ConfidentialClient($"cc-par-{Guid.NewGuid():N}",
            "https://client.tests.local/callback");
        request.RequirePar = true;

        using var response = await client.PostAsJsonAsync("/api/clients", request);
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);

        var body = await response.Content.ReadFromJsonAsync<JsonElement>();
        var requirements = body.GetProperty("requirements");
        Assert.Contains(requirements.EnumerateArray(),
            r => string.Equals(r.GetString(),
                OpenIddictConstants.Requirements.Features.PushedAuthorizationRequests,
                StringComparison.Ordinal));
        var permissions = body.GetProperty("permissions");
        Assert.Contains(permissions.EnumerateArray(),
            permission => string.Equals(permission.GetString(),
                OpenIddictConstants.Permissions.Endpoints.PushedAuthorization,
                StringComparison.Ordinal));
    }

    [Fact]
    public async Task Create_without_require_par_does_not_persist_the_par_requirement()
    {
        // Regression guard: PAR must be opt-in. A client created without the
        // flag must NOT carry the requirement, otherwise it would be rejected
        // at /connect/authorize for a request_uri it never obtained.
        using var factory = new ManagementTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        var client = factory.CreateClient();

        var request = ConfidentialClient($"cc-nopar-{Guid.NewGuid():N}",
            "https://client.tests.local/callback");
        // RequirePar defaults to false.

        using var response = await client.PostAsJsonAsync("/api/clients", request);
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);

        var body = await response.Content.ReadFromJsonAsync<JsonElement>();
        if (body.TryGetProperty("requirements", out var requirements))
        {
            Assert.DoesNotContain(requirements.EnumerateArray(),
                r => string.Equals(r.GetString(),
                    OpenIddictConstants.Requirements.Features.PushedAuthorizationRequests,
                    StringComparison.Ordinal));
        }
        // If "requirements" is absent entirely, that also satisfies the assertion
        // (no requirement was persisted).
    }

    [Fact]
    public async Task Native_return_uris_round_trip_through_create_and_update()
    {
        using var factory = new ManagementTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        var client = factory.CreateClient();
        var clientId = $"cc-native-{Guid.NewGuid():N}";

        var createRequest = ConfidentialClient(
            clientId,
            "https://client.tests.local/callback");
        createRequest.NativeReturnUris = ["example-app://auth-complete"];
        using var created = await client.PostAsJsonAsync("/api/clients", createRequest);
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        var before = await created.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal(
            "example-app://auth-complete",
            before.GetProperty("nativeReturnUris")[0].GetString());

        using var updated = await client.PutAsJsonAsync(
            $"/api/clients/{Uri.EscapeDataString(clientId)}",
            new UpdateClientRequest
            {
                DisplayName = "Native client",
                ConsentType = "explicit",
                GrantTypes = [Permissions.GrantTypes.AuthorizationCode],
                Scopes = ["profile"],
                RedirectUris = ["https://client.tests.local/callback"],
                ExpectedVersion = before.GetProperty("version").GetString(),
                NativeReturnUris = [],
            });
        Assert.Equal(HttpStatusCode.OK, updated.StatusCode);
        var after = await updated.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Empty(after.GetProperty("nativeReturnUris").EnumerateArray());
    }

    [Fact]
    public async Task Native_return_uris_reject_a_scheme_that_executes_in_the_browser()
    {
        using var factory = new ManagementTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        var client = factory.CreateClient();

        var request = ConfidentialClient(
            $"cc-native-bad-{Guid.NewGuid():N}",
            "https://client.tests.local/callback");
        request.NativeReturnUris = ["javascript:alert(1)"];

        using var response = await client.PostAsJsonAsync("/api/clients", request);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Contains(
            "native_return_uri_scheme_denied",
            await response.Content.ReadAsStringAsync(),
            StringComparison.Ordinal);
    }
}
