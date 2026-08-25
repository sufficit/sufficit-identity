using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Abstractions;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.Management.Mcp;
using Sufficit.Identity.STS;
using Sufficit.Identity.Tests.Infrastructure;
using static OpenIddict.Abstractions.OpenIddictConstants;
using Xunit;

namespace Sufficit.Identity.Tests;

public sealed class IdentityMcpTests
{
    [Fact]
    public void Sessions_are_bound_to_the_authenticated_subject()
    {
        using var manager = new McpSessionManager();

        var session = manager.Create("alice");

        Assert.True(manager.Validate(session, "alice"));
        Assert.False(manager.Validate(session, "bob"));
    }

    [Fact]
    public void Implicit_scope_policy_is_restricted_to_the_trusted_genius_client()
    {
        var policy = new McpScopeGrantPolicy(new SufficitIdentityOptions());

        var geniusScopes = policy.Resolve(
            "sufficit-ai-genius",
            ["openid", "offline_access"]);
        var unrelatedScopes = policy.Resolve(
            "unrelated-client",
            ["openid", "offline_access"]);

        Assert.Contains(
            McpResourceMetadataChallenge.DefaultRequiredScope,
            geniusScopes);
        Assert.DoesNotContain(
            McpResourceMetadataChallenge.DefaultRequiredScope,
            unrelatedScopes);
    }

    [Fact]
    public async Task Mcp_requires_a_bearer_authenticated_caller()
    {
        await using var factory = ManagementTestFactory.CreateWithRealAuthz();
        await ((IAsyncLifetime)factory).InitializeAsync();
        using var client = factory.CreateClient();

        using var response = await client.PostAsJsonAsync(
            "/api/mcp",
            new { jsonrpc = "2.0", id = 1, method = "initialize" });

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        // RFC 9728 §5.1: the challenge must point at the metadata document so
        // an MCP client can discover the authorization server on its own.
        var challenge = Assert.Single(response.Headers.WwwAuthenticate);
        Assert.Equal("Bearer", challenge.Scheme);
        Assert.Contains(
            "resource_metadata=\"http://localhost/.well-known/oauth-protected-resource\"",
            challenge.Parameter);
    }

    [Fact]
    public async Task Mcp_initialize_returns_a_session_and_lists_vault_and_self_service_tools()
    {
        await using var factory = ManagementTestFactory.CreateWithRealAuthz();
        await ((IAsyncLifetime)factory).InitializeAsync();
        using var client = factory.CreateClient();
        await AuthenticateAsync(client);

        using var initialize = await client.PostAsJsonAsync(
            "/api/mcp",
            new
            {
                jsonrpc = "2.0",
                id = 1,
                method = "initialize",
                @params = new { protocolVersion = "2025-06-18" }
            });

        Assert.Equal(HttpStatusCode.OK, initialize.StatusCode);
        Assert.True(initialize.Headers.TryGetValues("mcp-session-id", out var values));
        var sessionId = Assert.Single(values!);
        Assert.False(string.IsNullOrWhiteSpace(sessionId));

        client.DefaultRequestHeaders.Add("mcp-session-id", sessionId);
        using var list = await client.PostAsJsonAsync(
            "/api/mcp",
            new { jsonrpc = "2.0", id = 2, method = "tools/list" });

        Assert.Equal(HttpStatusCode.OK, list.StatusCode);
        var body = await list.Content.ReadFromJsonAsync<JsonElement>();
        var names = body.GetProperty("result")
            .GetProperty("tools")
            .EnumerateArray()
            .Select(tool => tool.GetProperty("name").GetString())
            .ToArray();

        Assert.Contains("vault_list", names);
        Assert.Contains("vault_resolve", names);
        Assert.Contains("me_get", names);
        Assert.Contains("me_session_revoke", names);

        using var me = await client.PostAsJsonAsync(
            "/api/mcp",
            new
            {
                jsonrpc = "2.0",
                id = 3,
                method = "tools/call",
                @params = new
                {
                    name = "me_get",
                    arguments = new { }
                }
            });

        Assert.Equal(HttpStatusCode.OK, me.StatusCode);
        var meBody = await me.Content.ReadFromJsonAsync<JsonElement>();
        var profileText = meBody.GetProperty("result")
            .GetProperty("content")[0]
            .GetProperty("text")
            .GetString();
        Assert.Equal(
            TestDataSeeder.DefaultUsername,
            JsonDocument.Parse(profileText!).RootElement
                .GetProperty("userName")
                .GetString());
    }

    [Fact]
    public async Task Mcp_rejects_an_authenticated_caller_without_the_dedicated_scope()
    {
        await using var factory = ManagementTestFactory.CreateWithRealAuthz();
        await ((IAsyncLifetime)factory).InitializeAsync();
        using var client = factory.CreateClient();
        await AuthenticateAsync(client, includeMcpScope: false);

        using var response = await client.PostAsJsonAsync(
            "/api/mcp",
            new { jsonrpc = "2.0", id = 1, method = "initialize" });

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task Personal_vault_http_surface_is_scope_gated_and_subject_isolated()
    {
        await using var factory = new ManagementTestFactory(
            bypassAuthz: false,
            enablePersonalVaultTestSurface: true);
        await ((IAsyncLifetime)factory).InitializeAsync();

        using var alice = factory.CreateClient();
        await AuthenticateAsync(alice);
        const string path =
            "/api/vault/personal/secrets/genius/device-1/external/github-token";
        using var saved = await alice.PutAsJsonAsync(path, new
        {
            value = "alice-secret",
        });
        Assert.Equal(HttpStatusCode.OK, saved.StatusCode);

        using var listed = await alice.GetAsync("/api/vault/personal/secrets");
        Assert.Equal(HttpStatusCode.OK, listed.StatusCode);
        var listedBody = await listed.Content.ReadFromJsonAsync<JsonElement>();
        var listedSecret = Assert.Single(
            listedBody.GetProperty("secrets").EnumerateArray());
        Assert.Equal(
            "genius/device-1/external/github-token",
            listedSecret.GetProperty("name").GetString());
        Assert.False(listedSecret.TryGetProperty("value", out _));

        using var resolved = await alice.GetAsync(path);
        Assert.Equal(HttpStatusCode.OK, resolved.StatusCode);
        var resolvedBody = await resolved.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal("alice-secret", resolvedBody.GetProperty("value").GetString());

        var bobName = $"bob-{Guid.NewGuid():N}";
        const string bobPassword = "Str0ng!Passw0rd#Mcp";
        using (var scope = factory.Services.CreateScope())
        {
            await TestDataSeeder.CreateUserAsync(
                scope.ServiceProvider.GetRequiredService<
                    UserManager<ApplicationUser>>(),
                bobName,
                bobPassword);
        }

        using var bob = factory.CreateClient();
        await AuthenticateAsync(
            bob,
            username: bobName,
            password: bobPassword);
        using var isolated = await bob.GetAsync(path);
        Assert.Equal(HttpStatusCode.NotFound, isolated.StatusCode);

        using var bobListed = await bob.GetAsync("/api/vault/personal/secrets");
        Assert.Equal(HttpStatusCode.OK, bobListed.StatusCode);
        var bobListBody = await bobListed.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Empty(bobListBody.GetProperty("secrets").EnumerateArray());
    }

    [Fact]
    public async Task Personal_account_profile_is_subject_bound_and_includes_no_secrets()
    {
        await using var factory = ManagementTestFactory.CreateWithRealAuthz();
        await ((IAsyncLifetime)factory).InitializeAsync();
        using var client = factory.CreateClient();
        await AuthenticateAsync(client);

        using var response = await client.GetAsync("/api/account/personal");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal(
            TestDataSeeder.DefaultUsername,
            body.GetProperty("userName").GetString());
        Assert.True(body.TryGetProperty("avatarUrl", out _));
        Assert.False(body.TryGetProperty("passwordHash", out _));
    }

    [Fact]
    public async Task Startup_provisioner_reconciles_the_scope_and_trusted_client_permission()
    {
        await using var factory = new ManagementTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();

        using var scope = factory.Services.CreateScope();
        var applications = scope.ServiceProvider
            .GetRequiredService<IOpenIddictApplicationManager>();
        var application = await applications.FindByClientIdAsync(
            TestDataSeeder.DeviceClientId);
        Assert.NotNull(application);
        var descriptor = new OpenIddictApplicationDescriptor();
        await applications.PopulateAsync(descriptor, application!);
        descriptor.Permissions.Remove(
            Permissions.Prefixes.Scope + McpResourceMetadataChallenge.DefaultRequiredScope);
        await applications.UpdateAsync(application!, descriptor);

        await scope.ServiceProvider
            .GetRequiredService<McpScopeProvisioner>()
            .ProvisionAsync();
        await scope.ServiceProvider
            .GetRequiredService<McpScopeProvisioner>()
            .ProvisionAsync();

        Assert.NotNull(await scope.ServiceProvider
            .GetRequiredService<IOpenIddictScopeManager>()
            .FindByNameAsync(McpResourceMetadataChallenge.DefaultRequiredScope));
        Assert.True(await applications.HasPermissionAsync(
            application!,
            Permissions.Prefixes.Scope
                + McpResourceMetadataChallenge.DefaultRequiredScope));
    }

    [Fact]
    public void Challenge_pointer_merges_into_an_existing_bearer_header()
    {
        var context = new DefaultHttpContext();
        context.Request.Scheme = "https";
        context.Request.Host = new HostString("identity.sufficit.com.br");
        context.SetEndpoint(new Endpoint(
            _ => Task.CompletedTask,
            new EndpointMetadataCollection(
                new AuthorizeAttribute(McpResourceMetadataChallenge.PolicyName)),
            "mcp"));
        Assert.True(McpResourceMetadataChallenge.TargetsMcpEndpoint(context));

        context.Response.StatusCode = 401;
        context.Response.Headers["WWW-Authenticate"] =
            "Bearer error=\"invalid_token\"";
        McpResourceMetadataChallenge.Advertise(context);

        var header = context.Response.Headers["WWW-Authenticate"].ToString();
        Assert.Contains("error=\"invalid_token\"", header);
        Assert.Contains(
            "resource_metadata=\"https://identity.sufficit.com.br/.well-known/oauth-protected-resource\"",
            header);
    }

    [Fact]
    public async Task Integration_oauth_is_scope_gated_and_never_asks_for_a_provider_token()
    {
        await using var factory = new ManagementTestFactory(
            bypassAuthz: false,
            extraConfiguration: new Dictionary<string, string?>
            {
                ["Sufficit:Identity:ExternalProviders:Google:Enabled"] = "true",
                ["Sufficit:Identity:ExternalProviders:Google:ClientId"] =
                    "test-google-client.apps.googleusercontent.com",
                ["Sufficit:Identity:ExternalProviders:Google:ClientSecret"] =
                    "test-google-secret",
                ["Sufficit:Identity:ExternalProviders:Google:ProjectId"] =
                    "test-google-project",
            },
            enablePersonalVaultTestSurface: true);
        await ((IAsyncLifetime)factory).InitializeAsync();

        using var anonymous = factory.CreateClient(
            new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
        using var denied = await anonymous.PostAsync(
            "/api/integrations/oauth/google-workspace/authorize",
            content: null);
        Assert.Equal(HttpStatusCode.Unauthorized, denied.StatusCode);

        using var client = factory.CreateClient(
            new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
        await AuthenticateAsync(client);
        using var status = await client.GetAsync(
            "/api/integrations/oauth/google-workspace/status");
        Assert.Equal(HttpStatusCode.OK, status.StatusCode);
        var statusBody = await status.Content.ReadFromJsonAsync<JsonElement>();
        Assert.True(statusBody.GetProperty("available").GetBoolean());
        Assert.False(statusBody.GetProperty("connected").GetBoolean());

        using var authorization = await client.PostAsync(
            "/api/integrations/oauth/google-workspace/authorize",
            content: null);
        Assert.Equal(HttpStatusCode.OK, authorization.StatusCode);
        var body = await authorization.Content.ReadFromJsonAsync<JsonElement>();
        var authorizationUrl = body.GetProperty("authorizationUrl").GetString();
        Assert.NotNull(authorizationUrl);
        Assert.StartsWith(
            "http://localhost/api/integrations/oauth/google-workspace/start?ticket=",
            authorizationUrl,
            StringComparison.Ordinal);
        var serialized = body.GetRawText();
        Assert.DoesNotContain("test-google-secret", serialized, StringComparison.Ordinal);
        Assert.DoesNotContain("access_token", serialized, StringComparison.OrdinalIgnoreCase);

        using var challenge = await client.GetAsync(authorizationUrl);
        Assert.Equal(HttpStatusCode.Redirect, challenge.StatusCode);
        var location = challenge.Headers.Location?.ToString();
        Assert.NotNull(location);
        Assert.StartsWith(
            "https://accounts.google.com/o/oauth2/v2/auth",
            location,
            StringComparison.Ordinal);
        Assert.Contains("gmail.modify", Uri.UnescapeDataString(location));
        Assert.Contains("/auth/documents", Uri.UnescapeDataString(location));

        using var malformed = await client.GetAsync(
            "/api/integrations/oauth/google-workspace/start?ticket=invalid");
        Assert.Equal(HttpStatusCode.BadRequest, malformed.StatusCode);
    }

    [Fact]
    public async Task Unconfigured_static_provider_is_reported_without_manual_token_fallback()
    {
        await using var factory = new ManagementTestFactory(
            bypassAuthz: false,
            enablePersonalVaultTestSurface: true);
        await ((IAsyncLifetime)factory).InitializeAsync();
        using var client = factory.CreateClient();
        await AuthenticateAsync(client);

        using var status = await client.GetAsync(
            "/api/integrations/oauth/github/status");
        Assert.Equal(HttpStatusCode.OK, status.StatusCode);
        var statusBody = await status.Content.ReadFromJsonAsync<JsonElement>();
        Assert.False(statusBody.GetProperty("available").GetBoolean());
        Assert.False(statusBody.GetProperty("connected").GetBoolean());

        using var authorize = await client.PostAsync(
            "/api/integrations/oauth/github/authorize",
            content: null);
        Assert.Equal(HttpStatusCode.Conflict, authorize.StatusCode);
        Assert.DoesNotContain(
            "token",
            await authorize.Content.ReadAsStringAsync(),
            StringComparison.OrdinalIgnoreCase);
    }

    private static async Task AuthenticateAsync(
        HttpClient client,
        bool includeMcpScope = true,
        string? username = null,
        string? password = null)
    {
        using var response = await client.PostAsync(
            "/connect/token",
            new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "password",
                ["client_id"] = TestDataSeeder.PasswordClientId,
                ["client_secret"] = TestDataSeeder.PasswordClientSecret,
                ["username"] = username ?? TestDataSeeder.DefaultUsername,
                ["password"] = password ?? TestDataSeeder.DefaultPassword,
                ["scope"] = includeMcpScope
                    ? $"{TestDataSeeder.ScopeName} {McpResourceMetadataChallenge.DefaultRequiredScope}"
                    : TestDataSeeder.ScopeName
            }));
        response.EnsureSuccessStatusCode();
        var body = await response.Content.ReadFromJsonAsync<JsonElement>();
        client.DefaultRequestHeaders.Authorization =
            new System.Net.Http.Headers.AuthenticationHeaderValue(
                "Bearer",
                body.GetProperty("access_token").GetString());
    }
}
