using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Sufficit.Identity.Tests.Infrastructure;
using Xunit;

namespace Sufficit.Identity.Tests;

/// <summary>
/// A delegated agent credential never carries the Identity MCP scope; the personal
/// Vault scope opens the owner's whole personal Vault to it, and nothing else.
/// </summary>
public sealed class PersonalVaultNarrowScopeTests
{
    [Fact]
    public async Task Vault_scope_reaches_the_whole_personal_vault_but_not_the_identity_mcp()
    {
        await using var factory = new ManagementTestFactory(
            bypassAuthz: false,
            extraConfiguration: new Dictionary<string, string?>
            {
                // The password client is no longer an implicit Identity MCP client here,
                // so its token carries only what it asks for.
                ["Sufficit:Identity:Mcp:ImplicitClientIds:1"] = "not-the-password-client",
                ["Sufficit:Identity:ApplicationScopes:0"] = "identity.vault",
            },
            enablePersonalVaultTestSurface: true);
        await ((IAsyncLifetime)factory).InitializeAsync();

        using var owner = factory.CreateClient();
        await IdentityMcpTests.AuthenticateAsync(owner);
        Assert.Equal(HttpStatusCode.OK, (await owner.PutAsJsonAsync(
            "/api/vault/personal/secrets/personal/bank/password", new { value = "private" })).StatusCode);

        using var agent = factory.CreateClient();
        await AuthenticateNarrowAsync(agent);

        // Everything of the owner, read and written, by the owner's decision.
        var read = await (await agent.GetAsync("/api/vault/personal/secrets/personal/bank/password"))
            .Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal("private", read.GetProperty("value").GetString());
        const string own = "/api/vault/personal/secrets/6bfda9ed-9a1e-43b1-8f1c-8ef3e58069b7/telegram-token";
        Assert.Equal(HttpStatusCode.OK, (await agent.PutAsJsonAsync(own, new { value = "bot" })).StatusCode);
        var listed = await (await agent.GetAsync("/api/vault/personal/secrets")).Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal(2, listed.GetProperty("secrets").GetArrayLength());
        Assert.Equal(HttpStatusCode.NoContent, (await agent.DeleteAsync(own)).StatusCode);

        // The rest of the Identity MCP stays closed to it.
        using var mcp = await agent.PostAsJsonAsync("/api/mcp", new { jsonrpc = "2.0", id = 1, method = "initialize" });
        Assert.True(mcp.StatusCode is HttpStatusCode.Forbidden or HttpStatusCode.Unauthorized);
    }

    private static async Task AuthenticateNarrowAsync(HttpClient client)
    {
        using var response = await client.PostAsync("/connect/token", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "password",
            ["client_id"] = TestDataSeeder.PasswordClientId,
            ["client_secret"] = TestDataSeeder.PasswordClientSecret,
            ["username"] = TestDataSeeder.DefaultUsername,
            ["password"] = TestDataSeeder.DefaultPassword,
            ["scope"] = $"{TestDataSeeder.ScopeName} identity.vault",
        }));
        response.EnsureSuccessStatusCode();
        var body = await response.Content.ReadFromJsonAsync<JsonElement>();
        if (body.TryGetProperty("scope", out var scope)) Assert.DoesNotContain("identity.mcp", scope.GetString() ?? "");
        client.DefaultRequestHeaders.Authorization =
            new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", body.GetProperty("access_token").GetString());
    }
}
