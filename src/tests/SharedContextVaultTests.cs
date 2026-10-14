using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Sufficit.Identity.Tests.Infrastructure;
using Xunit;

namespace Sufficit.Identity.Tests;

/// <summary>
/// A group conversation of a shared agent never touches a personal Vault; it reads credentials of
/// a shared context, under the same rule as the Identity MCP: the Vault resolve capability.
/// </summary>
public sealed class SharedContextVaultTests
{
    [Fact]
    public async Task Shared_context_reads_need_the_vault_capability_and_never_reach_a_personal_vault()
    {
        await using var factory = new ManagementTestFactory(
            bypassAuthz: false,
            extraConfiguration: new Dictionary<string, string?>
            {
                ["Sufficit:Identity:Mcp:ImplicitClientIds:1"] = "not-the-password-client",
                ["Sufficit:Identity:ApplicationScopes:0"] = "identity.vault",
            },
            enablePersonalVaultTestSurface: true);
        await ((IAsyncLifetime)factory).InitializeAsync();

        using var agent = factory.CreateClient();
        await AuthenticateNarrowAsync(agent);

        using var withoutCapability = await agent.GetAsync(
            "/api/vault/context/secrets/resolve?contextId=d21cfb04-9d37-473b-837c-67591a26feed&name=ai/asaas/token");
        Assert.Equal(HttpStatusCode.Forbidden, withoutCapability.StatusCode);

        using var personal = await agent.GetAsync(
            "/api/vault/context/secrets/resolve?contextId=user-someone&name=personal/bank/password");
        Assert.Equal(HttpStatusCode.BadRequest, personal.StatusCode);

        using var missing = await agent.GetAsync("/api/vault/context/secrets/resolve?name=ai/x");
        Assert.Equal(HttpStatusCode.BadRequest, missing.StatusCode);

        using var anonymous = factory.CreateClient();
        using var refused = await anonymous.GetAsync(
            "/api/vault/context/secrets/resolve?contextId=global&name=ai/x");
        Assert.True(refused.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden);
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
        client.DefaultRequestHeaders.Authorization =
            new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", body.GetProperty("access_token").GetString());
    }
}
