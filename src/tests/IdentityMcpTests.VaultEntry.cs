using System.Net.Http.Json;
using System.Text.Json;
using Sufficit.Identity.Tests.Infrastructure;
using Xunit;

namespace Sufficit.Identity.Tests;

public sealed partial class IdentityMcpTests
{
    [Fact]
    public async Task Prepared_entry_has_complete_url_and_exact_reference_without_creating_a_secret()
    {
        await using var factory = new ManagementTestFactory(bypassAuthz: false, enablePersonalVaultTestSurface: true);
        await ((IAsyncLifetime)factory).InitializeAsync();
        using var client = factory.CreateClient();
        await AuthenticateAsync(client);
        var prepared = await CallEntryAsync(client, "ASAAS/production/api-key");
        Assert.False(prepared.TryGetProperty("isError", out var failed) && failed.GetBoolean());
        var result = JsonDocument.Parse(prepared.GetProperty("content")[0].GetProperty("text").GetString()!).RootElement;
        Assert.Equal("personal/asaas/production/api-key", result.GetProperty("secretName").GetString());
        Assert.Equal("http://localhost/vault/new?name=asaas%2Fproduction%2Fapi-key", result.GetProperty("url").GetString());
        Assert.False(result.GetProperty("exists").GetBoolean());
        Assert.False(result.GetProperty("saved").GetBoolean());
        using var listed = await client.GetAsync("/api/vault/personal/secrets");
        var body = await listed.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Empty(body.GetProperty("secrets").EnumerateArray());
        using var saved = await client.PutAsJsonAsync("/api/vault/personal/secrets/personal/asaas/production/api-key", new { value = "fixture-only-key" });
        saved.EnsureSuccessStatusCode();
        var repeated = await CallEntryAsync(client, "asaas/production/api-key");
        var repeatedResult = JsonDocument.Parse(repeated.GetProperty("content")[0].GetProperty("text").GetString()!).RootElement;
        Assert.True(repeatedResult.GetProperty("exists").GetBoolean());
        Assert.DoesNotContain("fixture-only-key", repeated.GetRawText());
    }

    [Theory]
    [InlineData("../admin/key")]
    [InlineData("/asaas/key")]
    [InlineData("asaas/key?value=secret")]
    [InlineData("")]
    public async Task Prepared_entry_rejects_invalid_names(string name)
    {
        await using var factory = new ManagementTestFactory(bypassAuthz: false, enablePersonalVaultTestSurface: true);
        await ((IAsyncLifetime)factory).InitializeAsync();
        using var client = factory.CreateClient();
        await AuthenticateAsync(client);
        var response = await CallEntryAsync(client, name);
        Assert.True(response.GetProperty("isError").GetBoolean());
    }

    private static async Task<JsonElement> CallEntryAsync(HttpClient client, string name)
    {
        if (!client.DefaultRequestHeaders.Contains("mcp-session-id"))
        {
            using var initialized = await client.PostAsJsonAsync("/api/mcp", new
            {
                jsonrpc = "2.0", id = 0, method = "initialize",
                @params = new { protocolVersion = "2025-06-18" }
            });
            initialized.EnsureSuccessStatusCode();
            client.DefaultRequestHeaders.Add("mcp-session-id", initialized.Headers.GetValues("mcp-session-id").Single());
        }
        using var response = await client.PostAsJsonAsync("/api/mcp", new
        {
            jsonrpc = "2.0", id = 1, method = "tools/call",
            @params = new { name = "vault_prepare_entry", arguments = new { name } }
        });
        response.EnsureSuccessStatusCode();
        var body = await response.Content.ReadFromJsonAsync<JsonElement>();
        return body.GetProperty("result").Clone();
    }
}
