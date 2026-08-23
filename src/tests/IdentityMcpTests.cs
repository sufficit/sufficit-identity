using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Sufficit.Identity.Management.Mcp;
using Sufficit.Identity.Tests.Infrastructure;
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
        await using var factory = new ManagementTestFactory();
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

    /// <summary>
    /// Regression (eval 2026-08-23, S-6): the MCP policy used to require only
    /// an authenticated bearer, so ANY token this issuer minted reached the
    /// self-service and personal-vault tools — agent access came for free with
    /// authentication instead of being granted. A token without the dedicated
    /// scope must now be refused.
    /// </summary>
    [Fact]
    public async Task Mcp_rejects_a_token_without_the_mcp_scope()
    {
        await using var factory = ManagementTestFactory.CreateWithRealAuthz();
        await ((IAsyncLifetime)factory).InitializeAsync();
        using var client = factory.CreateClient();
        await AuthenticateAsync(client, TestDataSeeder.ScopeName);

        using var response = await client.PostAsJsonAsync(
            "/api/mcp",
            new { jsonrpc = "2.0", id = 1, method = "initialize" });

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task Mcp_accepts_a_token_carrying_the_mcp_scope()
    {
        await using var factory = ManagementTestFactory.CreateWithRealAuthz();
        await ((IAsyncLifetime)factory).InitializeAsync();
        using var client = factory.CreateClient();
        await AuthenticateAsync(client, "mcp");

        using var response = await client.PostAsJsonAsync(
            "/api/mcp",
            new
            {
                jsonrpc = "2.0",
                id = 1,
                method = "initialize",
                @params = new { protocolVersion = "2025-06-18" }
            });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
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

    private static async Task AuthenticateAsync(
        HttpClient client,
        string? scope = null)
    {
        using var response = await client.PostAsync(
            "/connect/token",
            new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "password",
                ["client_id"] = TestDataSeeder.PasswordClientId,
                ["client_secret"] = TestDataSeeder.PasswordClientSecret,
                ["username"] = TestDataSeeder.DefaultUsername,
                ["password"] = TestDataSeeder.DefaultPassword,
                ["scope"] = scope ?? TestDataSeeder.ScopeName
            }));
        response.EnsureSuccessStatusCode();
        var body = await response.Content.ReadFromJsonAsync<JsonElement>();
        client.DefaultRequestHeaders.Authorization =
            new System.Net.Http.Headers.AuthenticationHeaderValue(
                "Bearer",
                body.GetProperty("access_token").GetString());
    }
}
