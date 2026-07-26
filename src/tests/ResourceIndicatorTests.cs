using System.Net;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Abstractions;
using Sufficit.Identity.Tests.Infrastructure;
using Xunit;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Sufficit.Identity.Tests;

/// <summary>
/// Covers RFC 8707 resource indicators (item 4.2): a token requested with an
/// explicit <c>resource</c> parameter carries that resource as its audience
/// (<c>aud</c>), so resource servers can reject tokens minted for a different
/// resource (confused-deputy mitigation — critical for MCP server binding).
/// </summary>
/// <remarks>
/// The shared <see cref="StsCollection"/> fixture has no MCP-resource client.
/// This class builds its own isolated factory and seeds a client_credentials
/// client granted the <c>oi_rprm</c> permission for a test resource, then
/// confirms the issued token's <c>aud</c> (via introspection) includes that
/// resource.
/// </remarks>
public sealed class ResourceIndicatorTests
{
    private const string ResourceClientId = "test-resource-cc";
    private const string ResourceClientSecret = "test-resource-cc-secret";
    private const string McpResource = "https://mcp.tests.local";

    [Fact]
    public async Task Token_requested_with_resource_carries_it_as_audience()
    {
        using var factory = SufficitIdentityTestFactory.CreateIsolated(new Dictionary<string, string?>
        {
            // Register the MCP resource as a valid audience so OpenIddict
            // accepts `resource=https://mcp.tests.local` (item 4.2).
            ["Sufficit:Identity:Mcp:Resources:0"] = McpResource,
        });
        await ((IAsyncLifetime)factory).InitializeAsync();
        await EnsureResourceClientAsync(factory);

        var client = factory.CreateClient();
        var (status, body) = await client.PostFormAsync("/connect/token", new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = ResourceClientId,
            ["client_secret"] = ResourceClientSecret,
            ["scope"] = TestDataSeeder.ScopeName,
            // The RFC 8707 resource indicator — what we expect to land in aud.
            ["resource"] = McpResource,
        });

        Assert.Equal(HttpStatusCode.OK, status);
        var accessToken = body.GetProperty("access_token").GetString();
        Assert.False(string.IsNullOrEmpty(accessToken));

        // Introspect to read the aud claim. The introspection client must be an
        // audience of the token to see non-standard fields — but aud itself is
        // standard, so it surfaces regardless. Seed the introspection client as
        // a resource of the test scope (it already is, per TestDataSeeder).
        client.DefaultRequestHeaders.Authorization = IntrospectionTests.BasicAuthFor(
            TestDataSeeder.IntrospectionClientId, TestDataSeeder.IntrospectionClientSecret);
        var (_, introspectBody) = await client.PostFormAsync("/connect/introspect", new Dictionary<string, string>
        {
            ["token"] = accessToken!,
        });

        Assert.True(introspectBody.GetProperty("active").GetBoolean());

        // aud must include the requested resource (RFC 8707). aud may be a
        // single string or an array; accept either.
        var aud = introspectBody.GetProperty("aud");
        var audiences = aud.ValueKind == System.Text.Json.JsonValueKind.Array
            ? aud.EnumerateArray().Select(a => a.GetString()!).ToArray()
            : new[] { aud.GetString()! };
        Assert.Contains(McpResource, audiences);
    }

    private static async Task EnsureResourceClientAsync(SufficitIdentityTestFactory factory)
    {
        using var scope = factory.Services.CreateScope();
        var appManager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
        if (await appManager.FindByClientIdAsync(ResourceClientId) is null)
        {
            await appManager.CreateAsync(new OpenIddictApplicationDescriptor
            {
                ClientId = ResourceClientId,
                ClientSecret = ResourceClientSecret,
                ClientType = ClientTypes.Confidential,
                Permissions =
                {
                    Permissions.Endpoints.Token,
                    Permissions.GrantTypes.ClientCredentials,
                    Permissions.Prefixes.Scope + TestDataSeeder.ScopeName,
                    // oi_rprm permission: authorizes this client to request the
                    // MCP resource as an audience (RFC 8707). Without it,
                    // OpenIddict rejects the resource parameter.
                    Permissions.Prefixes.Resource + McpResource,
                },
            });
        }
    }
}
