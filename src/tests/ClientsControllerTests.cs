using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Abstractions;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Management.Audit;
using Sufficit.Identity.Management.Clients;
using Sufficit.Identity.Management.Controllers;
using Sufficit.Identity.Tests.Infrastructure;
using Xunit;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Sufficit.Identity.Tests;

/// <summary>
/// Covers <c>ClientsController.Create</c> secure-by-default changes (eval M4 /
/// plan item 2.4): the consent type defaults to <c>Explicit</c> when omitted,
/// and <c>redirect_uri</c> entries are validated (https required except for
/// loopback; fragments rejected). Uses <see cref="ManagementTestFactory"/>,
/// which wires the management module with authorization disabled (item 5.2 —
/// MFA/authz — is a later wave).
/// </summary>
public sealed class ClientsControllerTests
{
    [Fact]
    public async Task List_supports_server_paging_and_composable_filters()
    {
        using var factory = new ManagementTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        var client = factory.CreateClient();

        foreach (var suffix in new[] { "one", "two", "three" })
        {
            var request = ConfidentialClient(
                $"paged-{suffix}-{Guid.NewGuid():N}",
                "https://client.tests.local/callback");
            request.DisplayName = $"Paginated alpha {suffix}";
            request.GrantTypes = [Permissions.GrantTypes.AuthorizationCode];
            request.Scopes = ["openid"];
            using var created = await client.PostAsJsonAsync("/api/clients", request);
            Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        }

        using var response = await client.GetAsync(
            "/api/clients?q=alpha&type=confidential&grant=authorization_code&page=2&pageSize=1");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var page = await response.Content.ReadFromJsonAsync<ManagementClientPage>();
        Assert.NotNull(page);
        Assert.Equal(3, page.TotalCount);
        Assert.Equal(2, page.Page);
        Assert.Equal(1, page.PageSize);
        Assert.Single(page.Items);
        Assert.Contains("alpha", page.Items[0].DisplayName,
            StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task List_rejects_an_unbounded_page_size()
    {
        using var factory = new ManagementTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        var client = factory.CreateClient();

        using var response = await client.GetAsync("/api/clients?pageSize=101");

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Contains("pageSize", await response.Content.ReadAsStringAsync(),
            StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task List_returns_an_empty_page_for_a_reproducible_filter_deep_link()
    {
        using var factory = new ManagementTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        var client = factory.CreateClient();

        using var response = await client.GetAsync(
            "/api/clients?q=does-not-exist&type=confidential&grant=device_code"
            + "&origin=manifest&status=active&page=3&pageSize=10");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var page = await response.Content.ReadFromJsonAsync<ManagementClientPage>();
        Assert.NotNull(page);
        Assert.Equal(0, page.TotalCount);
        Assert.Empty(page.Items);
        Assert.Equal(3, page.Page);
        Assert.Equal(10, page.PageSize);
    }

    private static CreateClientRequest ConfidentialClient(string clientId, params string[] redirectUris) => new()
    {
        ClientId = clientId,
        ClientSecret = $"secret-{clientId}",
        DisplayName = $"Test client {clientId}",
        GrantTypes = { Permissions.GrantTypes.AuthorizationCode },
        RedirectUris = redirectUris.ToList(),
    };

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
            AccessTokenLifetimeMinutes = 17,
            IdentityTokenLifetimeMinutes = 8,
            RefreshTokenLifetimeDays = 31,
        };

        using var created = await client.PostAsJsonAsync("/api/clients", request);

        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        var body = await created.Content.ReadFromJsonAsync<ManagementClientDetail>();
        Assert.Equal(17, body?.AccessTokenLifetimeMinutes);
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
        Assert.InRange(token.GetProperty("expires_in").GetInt32(), 17 * 60 - 2, 17 * 60);
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
    public async Task Client_credentials_client_can_issue_token_and_delete_dependents()
    {
        using var factory = new ManagementTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        var client = factory.CreateClient();
        var clientId = $"cc-machine-{Guid.NewGuid():N}";
        var clientSecret = $"secret-{Guid.NewGuid():N}";
        var request = new CreateClientRequest
        {
            ClientId = clientId,
            ClientSecret = clientSecret,
            DisplayName = "Machine client",
            GrantTypes = ["client_credentials"],
            Scopes = [TestDataSeeder.ScopeName]
        };

        using var created = await client.PostAsJsonAsync(
            "/api/clients",
            request);
        var createdBody = await created.Content
            .ReadFromJsonAsync<JsonElement>();

        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        Assert.Contains(
            createdBody.GetProperty("permissions").EnumerateArray(),
            permission => permission.GetString()
                == Permissions.Endpoints.Token);

        var (status, token) = await client.PostFormAsync(
            "/connect/token",
            new Dictionary<string, string>
            {
                ["grant_type"] = "client_credentials",
                ["client_id"] = clientId,
                ["client_secret"] = clientSecret,
                ["scope"] = TestDataSeeder.ScopeName
            });

        Assert.Equal(HttpStatusCode.OK, status);
        Assert.False(string.IsNullOrWhiteSpace(
            token.GetProperty("access_token").GetString()));

        using var deleted = await client.DeleteAsync(
            $"/api/clients/{Uri.EscapeDataString(clientId)}");
        Assert.Equal(HttpStatusCode.NoContent, deleted.StatusCode);

        await using var verification = factory.Services.CreateAsyncScope();
        var database = verification.ServiceProvider
            .GetRequiredService<AppDbContext>();
        Assert.False(await database.Set<
            OpenIddict.EntityFrameworkCore.Models
                .OpenIddictEntityFrameworkCoreApplication>()
            .AnyAsync(application => application.ClientId == clientId));
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

    // ----------------------------------------------------------------------
    // Item 3.3 — Pushed Authorization Request (RFC 9126) requirement, opt-in
    // per client. Proves the requirement is persisted when requested and
    // absent when not (so legacy clients are unaffected).
    // ----------------------------------------------------------------------

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

    // ----------------------------------------------------------------------
    // Eval test-coverage gap: assert that the management authz gate actually
    // rejects requests without the admin scope. Uses a factory variant that
    // does NOT bypass authorization (the real ScopeHandler runs).
    // ----------------------------------------------------------------------

    [Fact]
    public async Task Management_endpoints_reject_request_without_admin_scope()
    {
        using var factory = ManagementTestFactory.CreateWithRealAuthz();
        await ((IAsyncLifetime)factory).InitializeAsync();
        var client = factory.CreateClient();

        // No Authorization header → the [Authorize(Policy=...)] gate rejects.
        using var response = await client.GetAsync("/api/clients");
        Assert.True(response.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden,
            $"Expected 401/403 without admin scope, got {response.StatusCode}.");
        Assert.Null(response.Headers.Location);
        Assert.Contains(
            response.Headers.WwwAuthenticate,
            challenge => string.Equals(
                challenge.Scheme,
                "Bearer",
                StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task Detail_returns_the_canonical_client_contract()
    {
        using var factory = new ManagementTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        var client = factory.CreateClient();
        var clientId = $"cc-detail-{Guid.NewGuid():N}";
        var request = ConfidentialClient(
            clientId,
            "https://client.tests.local/callback");
        request.RequirePar = true;

        using var created = await client.PostAsJsonAsync("/api/clients", request);
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);

        using var response = await client.GetAsync(
            $"/api/clients/{Uri.EscapeDataString(clientId)}");
        var body = await response.Content.ReadFromJsonAsync<JsonElement>();

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(clientId, body.GetProperty("clientId").GetString());
        Assert.Contains(
            body.GetProperty("redirectUris").EnumerateArray(),
            value => value.GetString() == "https://client.tests.local/callback");
        Assert.False(body.TryGetProperty("clientSecret", out _));
    }

    [Fact]
    public async Task Update_preserves_secret_and_rejects_stale_version()
    {
        using var factory = new ManagementTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        var client = factory.CreateClient();
        var clientId = $"cc-update-{Guid.NewGuid():N}";
        var secret = $"secret-{Guid.NewGuid():N}";

        var createRequest = ConfidentialClient(
            clientId,
            "https://client.tests.local/callback");
        createRequest.ClientSecret = secret;
        using var created = await client.PostAsJsonAsync(
            "/api/clients",
            createRequest);
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        var before = await created.Content.ReadFromJsonAsync<JsonElement>();
        var version = before.GetProperty("version").GetString();

        using var updated = await client.PutAsJsonAsync(
            $"/api/clients/{Uri.EscapeDataString(clientId)}",
            new UpdateClientRequest
            {
                DisplayName = "Updated client",
                ConsentType = "explicit",
                GrantTypes = [Permissions.GrantTypes.AuthorizationCode],
                Scopes = ["profile"],
                RedirectUris = ["https://client.tests.local/updated"],
                ExpectedVersion = version,
                AccessTokenLifetimeMinutes = 23,
                IdentityTokenLifetimeMinutes = 11,
                RefreshTokenLifetimeDays = 42,
            });
        Assert.Equal(HttpStatusCode.OK, updated.StatusCode);
        var after = await updated.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal("Updated client", after.GetProperty("displayName").GetString());
        Assert.Equal(23, after.GetProperty("accessTokenLifetimeMinutes").GetInt32());
        Assert.Equal(11, after.GetProperty("identityTokenLifetimeMinutes").GetInt32());
        Assert.Equal(42, after.GetProperty("refreshTokenLifetimeDays").GetInt32());
        Assert.False(after.TryGetProperty("clientSecret", out _));

        using var inherited = await client.PutAsJsonAsync(
            $"/api/clients/{Uri.EscapeDataString(clientId)}",
            new UpdateClientRequest
            {
                DisplayName = "Updated client",
                ConsentType = "explicit",
                GrantTypes = [Permissions.GrantTypes.AuthorizationCode],
                Scopes = ["profile"],
                RedirectUris = ["https://client.tests.local/updated"],
                ExpectedVersion = after.GetProperty("version").GetString(),
                ClearAccessTokenLifetime = true,
                ClearIdentityTokenLifetime = true,
                ClearRefreshTokenLifetime = true,
            });
        Assert.Equal(HttpStatusCode.OK, inherited.StatusCode);
        var inheritedBody = await inherited.Content.ReadFromJsonAsync<JsonElement>();
        Assert.True(inheritedBody.GetProperty("accessTokenLifetimeMinutes").ValueKind is JsonValueKind.Null);
        Assert.True(inheritedBody.GetProperty("identityTokenLifetimeMinutes").ValueKind is JsonValueKind.Null);
        Assert.True(inheritedBody.GetProperty("refreshTokenLifetimeDays").ValueKind is JsonValueKind.Null);

        await using (var scope = factory.Services.CreateAsyncScope())
        {
            var applications = scope.ServiceProvider
                .GetRequiredService<IOpenIddictApplicationManager>();
            var application = await applications.FindByClientIdAsync(clientId);
            Assert.NotNull(application);
            Assert.True(await applications.ValidateClientSecretAsync(application, secret));
        }

        using var stale = await client.PutAsJsonAsync(
            $"/api/clients/{Uri.EscapeDataString(clientId)}",
            new UpdateClientRequest
            {
                DisplayName = "Stale update",
                GrantTypes = [Permissions.GrantTypes.AuthorizationCode],
                RedirectUris = ["https://client.tests.local/updated"],
                ExpectedVersion = version
            });
        Assert.Equal(HttpStatusCode.Conflict, stale.StatusCode);
    }

    [Fact]
    public async Task Create_and_delete_append_redacted_audit_events()
    {
        using var factory = new ManagementTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        var client = factory.CreateClient();
        var clientId = $"cc-audit-{Guid.NewGuid():N}";
        var secret = $"secret-{Guid.NewGuid():N}";
        var request = ConfidentialClient(
            clientId,
            "https://client.tests.local/callback");
        request.ClientSecret = secret;

        using var created = await client.PostAsJsonAsync("/api/clients", request);
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);

        using var deleted = await client.DeleteAsync(
            $"/api/clients/{Uri.EscapeDataString(clientId)}");
        Assert.Equal(HttpStatusCode.NoContent, deleted.StatusCode);

        await using var scope = factory.Services.CreateAsyncScope();
        var database = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var events = await database.ManagementAuditEvents
            .Where(entry => entry.ResourceId == clientId)
            .OrderBy(entry => entry.Id)
            .ToArrayAsync();

        Assert.Collection(
            events,
            entry =>
            {
                Assert.Equal("identity.clients.create", entry.Capability);
                Assert.Equal("succeeded", entry.OperationOutcome);
            },
            entry =>
            {
                Assert.Equal("identity.clients.delete", entry.Capability);
                Assert.Equal("succeeded", entry.OperationOutcome);
            });
        Assert.All(events, entry =>
        {
            Assert.DoesNotContain(secret, entry.OperatorSubject, StringComparison.Ordinal);
            Assert.DoesNotContain(secret, entry.CorrelationId, StringComparison.Ordinal);
        });
    }

    [Fact]
    public async Task Audit_endpoint_returns_persisted_mutations()
    {
        using var factory = new ManagementTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        var client = factory.CreateClient();
        var clientId = $"cc-audit-list-{Guid.NewGuid():N}";

        using var created = await client.PostAsJsonAsync(
            "/api/clients",
            ConfidentialClient(
                clientId,
                "https://client.tests.local/callback"));
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);

        using var response = await client.GetAsync("/api/audit?limit=10");
        var records = await response.Content
            .ReadFromJsonAsync<ManagementAuditRecord[]>();

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Contains(
            records!,
            entry => entry.ResourceId == clientId
                && entry.Capability == "identity.clients.create");
    }
}
