using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Sufficit.Identity.Tests.Infrastructure;
using Xunit;

namespace Sufficit.Identity.Tests;

/// <summary>
/// A delegated agent credential never carries the Identity MCP scope; the narrow
/// personal Vault scope lets it keep its own channel tokens under <c>genius/</c>
/// and read what the owner shares under <c>ai/</c>, and nothing else.
/// </summary>
public sealed class PersonalVaultNarrowScopeTests
{
    [Fact]
    public async Task Narrow_scope_reaches_only_the_agent_namespaces()
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
            "/api/vault/personal/secrets/ai/shared/github-token", new { value = "shared" })).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await owner.PutAsJsonAsync(
            "/api/vault/personal/secrets/personal/bank/password", new { value = "private" })).StatusCode);

        using var agent = factory.CreateClient();
        await AuthenticateNarrowAsync(agent);

        // Its own channel token: written, read and removed under genius/.
        const string own = "/api/vault/personal/secrets/genius/device-1/telegram.bot-token";
        Assert.Equal(HttpStatusCode.OK, (await agent.PutAsJsonAsync(own, new { value = "bot" })).StatusCode);
        var read = await (await agent.GetAsync(own)).Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal("bot", read.GetProperty("value").GetString());

        // What the owner shares with agents: readable, not writable.
        Assert.Equal(HttpStatusCode.OK, (await agent.GetAsync("/api/vault/personal/secrets/ai/shared/github-token")).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await agent.PutAsJsonAsync(
            "/api/vault/personal/secrets/ai/shared/github-token", new { value = "x" })).StatusCode);

        // Everything else stays out of reach, and out of the list.
        Assert.Equal(HttpStatusCode.Forbidden, (await agent.GetAsync("/api/vault/personal/secrets/personal/bank/password")).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await agent.DeleteAsync("/api/vault/personal/secrets/personal/bank/password")).StatusCode);
        var listed = await (await agent.GetAsync("/api/vault/personal/secrets")).Content.ReadFromJsonAsync<JsonElement>();
        var names = listed.GetProperty("secrets").EnumerateArray().Select(item => item.GetProperty("name").GetString()).ToList();
        Assert.Equal(["ai/shared/github-token", "genius/device-1/telegram.bot-token"], names.Order().ToList());

        Assert.Equal(HttpStatusCode.NoContent, (await agent.DeleteAsync(own)).StatusCode);

        // The full scope still sees the whole personal Vault.
        Assert.Equal(HttpStatusCode.OK, (await owner.GetAsync("/api/vault/personal/secrets/personal/bank/password")).StatusCode);
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
