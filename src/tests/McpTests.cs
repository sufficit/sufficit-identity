using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Abstractions;
using Sufficit.Identity.Management.Controllers;
using Sufficit.Identity.STS.Controllers;
using Sufficit.Identity.Tests.Infrastructure;
using Xunit;

namespace Sufficit.Identity.Tests;

/// <summary>
/// Covers Onda 4 MCP/agent-AI features: RFC 9728 protected-resource metadata
/// (4.1) and RFC 7591 Dynamic Client Registration (4.3). Resource indicators
/// (4.2) are covered by <see cref="ResourceIndicatorTests"/>.
/// </summary>
[Collection(StsCollection.Name)]
public sealed class McpMetadataTests
{
    private readonly SufficitIdentityTestFactory _factory;

    public McpMetadataTests(SufficitIdentityTestFactory factory) => _factory = factory;

    [Fact]
    public async Task Protected_resource_metadata_document_points_back_to_the_issuer()
    {
        // RFC 9728: /.well-known/oauth-protected-resource must return a JSON
        // document with `resource` and `authorization_servers`. A client (incl.
        // an MCP client) reads this to find the AS that issues tokens the RS
        // accepts. The configured test issuer is https://sts.tests.local.
        var client = _factory.CreateClient();
        var response = await client.GetAsync("/.well-known/oauth-protected-resource");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var json = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal("https://sts.tests.local",
            json.GetProperty("resource").GetString());
        var authServers = json.GetProperty("authorization_servers").EnumerateArray()
            .Select(a => a.GetString()!).ToArray();
        Assert.Contains("https://sts.tests.local", authServers);
        // bearer_methods_supported must include "header" (the only method an
        // MCP/RS accepts — query param is forbidden by RFC 6750 §2.3).
        var methods = json.GetProperty("bearer_methods_supported").EnumerateArray()
            .Select(m => m.GetString()!).ToArray();
        Assert.Contains("header", methods);
    }
}

/// <summary>
/// Covers RFC 7591 Dynamic Client Registration (item 4.3) gating: off by
/// default, requires the initial access token when enabled, and rejects
/// insecure client metadata (mirroring ClientsController validation).
/// </summary>
public sealed class DcrTests
{
    [Fact]
    public async Task Dcr_endpoint_is_404_when_disabled()
    {
        // Default config: Dcr.Enabled=false. The endpoint must not be usable.
        using var factory = SufficitIdentityTestFactory.CreateIsolated(new Dictionary<string, string?>());
        await ((IAsyncLifetime)factory).InitializeAsync();
        var client = factory.CreateClient();

        var request = new { client_id = $"dcr-off-{Guid.NewGuid():N}", grant_types = new[] { "client_credentials" } };
        using var response = await client.PostAsJsonAsync("/connect/register", request);
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact]
    public async Task Dcr_requires_the_initial_access_token_when_enabled()
    {
        using var factory = SufficitIdentityTestFactory.CreateIsolated(new Dictionary<string, string?>
        {
            ["Sufficit:Identity:Mcp:Dcr:Enabled"] = "true",
            ["Sufficit:Identity:Mcp:Dcr:InitialAccessToken"] = "secret-init-token",
            ["Sufficit:Identity:Mcp:Dcr:InitialAccessTokenExpiresAtUtc"] = "2099-01-01T00:00:00Z",
        });
        await ((IAsyncLifetime)factory).InitializeAsync();
        var client = factory.CreateClient();

        var request = new { client_id = $"dcr-notoken-{Guid.NewGuid():N}" };
        // No Authorization header → 401.
        using var noToken = await client.PostAsJsonAsync("/connect/register", request);
        Assert.Equal(HttpStatusCode.Unauthorized, noToken.StatusCode);

        // Wrong token → 401.
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", "wrong-token");
        using var wrongToken = await client.PostAsJsonAsync("/connect/register", request);
        Assert.Equal(HttpStatusCode.Unauthorized, wrongToken.StatusCode);
    }

    [Fact]
    public async Task Dcr_with_valid_token_registers_a_secure_default_client()
    {
        using var factory = SufficitIdentityTestFactory.CreateIsolated(new Dictionary<string, string?>
        {
            ["Sufficit:Identity:Mcp:Dcr:Enabled"] = "true",
            ["Sufficit:Identity:Mcp:Dcr:InitialAccessToken"] = "secret-init-token",
            ["Sufficit:Identity:Mcp:Dcr:InitialAccessTokenExpiresAtUtc"] = "2099-01-01T00:00:00Z",
            ["Sufficit:Identity:Mcp:Dcr:AllowedGrantTypes:0"] = "client_credentials",
            ["Sufficit:Identity:Mcp:Dcr:AllowedScopes:0"] = "test.scope",
        });
        await ((IAsyncLifetime)factory).InitializeAsync();
        var client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", "secret-init-token");

        var request = new DcrRequest
        {
            TokenEndpointAuthMethod = "client_secret_basic",
            GrantTypes = new() { "client_credentials" },
            Scopes = new() { "test.scope" },
        };
        using var response = await client.PostAsJsonAsync("/connect/register", request);
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);

        var body = await response.Content.ReadFromJsonAsync<JsonElement>();
        var clientId = body.GetProperty("client_id").GetString()
            ?? throw new InvalidOperationException("DCR client_id missing.");
        var clientSecret = body.GetProperty("client_secret").GetString()
            ?? throw new InvalidOperationException("DCR client_secret missing.");
        Assert.StartsWith("dcr_", clientId, StringComparison.Ordinal);
        Assert.True(clientSecret.Length >= 64);

        using (var scope = factory.Services.CreateScope())
        {
            var applications = scope.ServiceProvider
                .GetRequiredService<IOpenIddictApplicationManager>();
            var application = await applications.FindByClientIdAsync(clientId);
            Assert.NotNull(application);
            Assert.DoesNotContain(
                OpenIddictConstants.Requirements.Features.ProofKeyForCodeExchange,
                await applications.GetRequirementsAsync(application!));
        }

        // The registered client must be usable immediately: a token grant works.
        var tokenClient = factory.CreateClient();
        var (status, tokenBody) = await tokenClient.PostFormAsync("/connect/token", new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = clientId,
            ["client_secret"] = clientSecret,
            ["scope"] = "test.scope",
        });
        Assert.Equal(HttpStatusCode.OK, status);
        Assert.False(string.IsNullOrEmpty(tokenBody.GetProperty("access_token").GetString()));

        using var replay = await client.PostAsJsonAsync(
            "/connect/register",
            new DcrRequest
            {
                TokenEndpointAuthMethod = "client_secret_basic",
                GrantTypes = new() { "client_credentials" },
                Scopes = new() { "test.scope" },
            });
        Assert.Equal(HttpStatusCode.Unauthorized, replay.StatusCode);
    }

    [Fact]
    public async Task Dcr_authorization_code_clients_always_require_pkce()
    {
        using var factory = SufficitIdentityTestFactory.CreateIsolated(new Dictionary<string, string?>
        {
            ["Sufficit:Identity:Mcp:Dcr:Enabled"] = "true",
            ["Sufficit:Identity:Mcp:Dcr:InitialAccessToken"] = "secret-init-token",
            ["Sufficit:Identity:Mcp:Dcr:InitialAccessTokenExpiresAtUtc"] = "2099-01-01T00:00:00Z",
            ["Sufficit:Identity:Mcp:Dcr:AllowedGrantTypes:0"] = "authorization_code",
            ["Sufficit:Identity:Mcp:Dcr:AllowedScopes:0"] = "openid",
        });
        await ((IAsyncLifetime)factory).InitializeAsync();
        var client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", "secret-init-token");

        using var response = await client.PostAsJsonAsync("/connect/register", new DcrRequest
        {
            TokenEndpointAuthMethod = "client_secret_basic",
            GrantTypes = new() { "authorization_code" },
            Scopes = new() { "openid" },
            RedirectUris = new() { new Uri("https://client.tests.local/callback") },
        });
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);

        var body = await response.Content.ReadFromJsonAsync<JsonElement>();
        var registeredId = body.GetProperty("client_id").GetString();
        Assert.False(string.IsNullOrWhiteSpace(registeredId));

        using var scope = factory.Services.CreateScope();
        var applications = scope.ServiceProvider
            .GetRequiredService<IOpenIddictApplicationManager>();
        var application = await applications.FindByClientIdAsync(registeredId!);
        Assert.NotNull(application);
        var requirements = await applications.GetRequirementsAsync(application!);
        Assert.Contains(
            OpenIddictConstants.Requirements.Features.ProofKeyForCodeExchange,
            requirements);
    }

    [Fact]
    public async Task Dcr_rejects_insecure_redirect_uri()
    {
        // DCR must not be a bypass for weaker client registration: the same
        // redirect_uri validation (https except loopback, no fragment) as
        // ClientsController applies.
        using var factory = SufficitIdentityTestFactory.CreateIsolated(new Dictionary<string, string?>
        {
            ["Sufficit:Identity:Mcp:Dcr:Enabled"] = "true",
            ["Sufficit:Identity:Mcp:Dcr:InitialAccessToken"] = "secret-init-token",
            ["Sufficit:Identity:Mcp:Dcr:InitialAccessTokenExpiresAtUtc"] = "2099-01-01T00:00:00Z",
        });
        await ((IAsyncLifetime)factory).InitializeAsync();
        var client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", "secret-init-token");

        var request = new DcrRequest
        {
            GrantTypes = new() { "authorization_code" },
            RedirectUris = new() { new Uri("http://insecure.example.com/callback") },
        };
        using var response = await client.PostAsJsonAsync("/connect/register", request);
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task Dcr_persists_public_jwks_uri_and_rejects_private_targets()
    {
        using var factory = SufficitIdentityTestFactory.CreateIsolated(
            new Dictionary<string, string?>
            {
                ["Sufficit:Identity:Mcp:Dcr:Enabled"] = "true",
                ["Sufficit:Identity:Mcp:Dcr:InitialAccessToken"] =
                    "secret-init-token",
                ["Sufficit:Identity:Mcp:Dcr:InitialAccessTokenExpiresAtUtc"] =
                    "2099-01-01T00:00:00Z",
                ["Sufficit:Identity:Mcp:Dcr:InitialAccessTokenSingleUse"] =
                    "false",
            });
        await ((IAsyncLifetime)factory).InitializeAsync();
        var client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", "secret-init-token");

        using var accepted = await client.PostAsJsonAsync(
            "/connect/register",
            new DcrRequest
            {
                JwksUri = new Uri("https://keys.example/jwks.json"),
            });
        Assert.Equal(HttpStatusCode.Created, accepted.StatusCode);
        var body = await accepted.Content.ReadFromJsonAsync<JsonElement>();
        var clientId = body.GetProperty("client_id").GetString();

        using var scope = factory.Services.CreateScope();
        var applications = scope.ServiceProvider
            .GetRequiredService<IOpenIddictApplicationManager>();
        var application = await applications.FindByClientIdAsync(clientId!);
        Assert.NotNull(application);
        var settings = await applications.GetSettingsAsync(application!);
        Assert.Equal(
            "https://keys.example/jwks.json",
            settings["jwks_uri"]);

        using var rejected = await client.PostAsJsonAsync(
            "/connect/register",
            new DcrRequest
            {
                JwksUri = new Uri("https://127.0.0.1/jwks.json"),
            });
        Assert.Equal(HttpStatusCode.BadRequest, rejected.StatusCode);
    }

    [Fact]
    public async Task Dcr_rejects_grants_and_scopes_outside_the_operator_allowlist()
    {
        using var factory = SufficitIdentityTestFactory.CreateIsolated(new Dictionary<string, string?>
        {
            ["Sufficit:Identity:Mcp:Dcr:Enabled"] = "true",
            ["Sufficit:Identity:Mcp:Dcr:InitialAccessToken"] = "secret-init-token",
            ["Sufficit:Identity:Mcp:Dcr:InitialAccessTokenExpiresAtUtc"] = "2099-01-01T00:00:00Z",
            ["Sufficit:Identity:Mcp:Dcr:InitialAccessTokenSingleUse"] = "false",
        });
        await ((IAsyncLifetime)factory).InitializeAsync();
        var client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", "secret-init-token");

        using var grantResponse = await client.PostAsJsonAsync("/connect/register", new DcrRequest
        {
            TokenEndpointAuthMethod = "client_secret_basic",
            GrantTypes = new() { "client_credentials" },
        });
        Assert.Equal(HttpStatusCode.BadRequest, grantResponse.StatusCode);

        using var scopeResponse = await client.PostAsJsonAsync("/connect/register", new DcrRequest
        {
            GrantTypes = new() { "authorization_code" },
            Scopes = new() { "identity.management" },
            RedirectUris = new() { new Uri("https://client.example/callback") },
        });
        Assert.Equal(HttpStatusCode.BadRequest, scopeResponse.StatusCode);
    }

    [Fact]
    public async Task Dcr_rejects_caller_supplied_identifiers_and_secrets()
    {
        using var factory = SufficitIdentityTestFactory.CreateIsolated(
            new Dictionary<string, string?>
            {
                ["Sufficit:Identity:Mcp:Dcr:Enabled"] = "true",
                ["Sufficit:Identity:Mcp:Dcr:InitialAccessToken"] =
                    "secret-init-token",
                ["Sufficit:Identity:Mcp:Dcr:InitialAccessTokenExpiresAtUtc"] =
                    "2099-01-01T00:00:00Z",
                ["Sufficit:Identity:Mcp:Dcr:InitialAccessTokenSingleUse"] =
                    "false",
                ["Sufficit:Identity:Mcp:Dcr:AllowCallerSuppliedClientIds"] =
                    "false",
                ["Sufficit:Identity:Mcp:Dcr:AllowCallerSuppliedSecrets"] =
                    "false",
            });
        await ((IAsyncLifetime)factory).InitializeAsync();
        var client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", "secret-init-token");

        using var identifierResponse = await client.PostAsJsonAsync(
            "/connect/register",
            new DcrRequest { ClientId = "caller-controlled" });
        using var secretResponse = await client.PostAsJsonAsync(
            "/connect/register",
            new DcrRequest
            {
                ClientSecret = "caller-controlled",
                TokenEndpointAuthMethod = "client_secret_basic",
            });

        Assert.Equal(HttpStatusCode.BadRequest, identifierResponse.StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, secretResponse.StatusCode);
    }
}
