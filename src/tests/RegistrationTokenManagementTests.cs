using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.STS.Controllers;
using Sufficit.Identity.Tests.Infrastructure;
using Xunit;

namespace Sufficit.Identity.Tests;

/// <summary>
/// Initial access tokens for dynamic client registration issued through the
/// management API: the value is shown once, a registration consumes it, and
/// issuance and revocation are audited.
/// </summary>
public sealed class RegistrationTokenManagementTests
{
    [Fact]
    public async Task Issued_token_registers_one_client_and_can_be_revoked()
    {
        using var factory = new ManagementTestFactory(extraConfiguration: new Dictionary<string, string?>
        {
            ["Sufficit:Identity:Mcp:Dcr:Enabled"] = "true",
        });
        await ((IAsyncLifetime)factory).InitializeAsync();
        var client = factory.CreateClient();

        using var issued = await client.PostAsJsonAsync(
            "/api/registration-tokens",
            new { label = "partner agent", lifetimeHours = 2 });
        Assert.Equal(HttpStatusCode.OK, issued.StatusCode);
        var issueBody = await issued.Content.ReadFromJsonAsync<JsonElement>();
        var token = issueBody.GetProperty("initialAccessToken").GetString()!;
        var tokenId = issueBody.GetProperty("token").GetProperty("id").GetString()!;
        Assert.StartsWith("dcr_iat_", token, StringComparison.Ordinal);
        Assert.Equal("active", issueBody.GetProperty("token").GetProperty("status").GetString());

        var registrant = factory.CreateClient();
        registrant.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        using var registered = await registrant.PostAsJsonAsync("/connect/register", new DcrRequest());
        Assert.Equal(HttpStatusCode.Created, registered.StatusCode);

        var listed = await client.GetFromJsonAsync<JsonElement>("/api/registration-tokens");
        var summary = Assert.Single(listed.EnumerateArray());
        Assert.Equal("used", summary.GetProperty("status").GetString());
        Assert.Equal(1, summary.GetProperty("registrationCount").GetInt32());
        Assert.DoesNotContain(token, listed.GetRawText(), StringComparison.Ordinal);

        using var invalidLifetime = await client.PostAsJsonAsync(
            "/api/registration-tokens",
            new { label = "too long", lifetimeHours = 10_000 });
        Assert.Equal(HttpStatusCode.BadRequest, invalidLifetime.StatusCode);

        using var second = await client.PostAsJsonAsync(
            "/api/registration-tokens",
            new { label = "reusable", singleUse = false });
        var secondBody = await second.Content.ReadFromJsonAsync<JsonElement>();
        var secondToken = secondBody.GetProperty("initialAccessToken").GetString()!;
        var secondId = secondBody.GetProperty("token").GetProperty("id").GetString()!;

        using var revoked = await client.DeleteAsync($"/api/registration-tokens/{secondId}");
        Assert.Equal(HttpStatusCode.NoContent, revoked.StatusCode);

        registrant.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", secondToken);
        using var afterRevocation = await registrant.PostAsJsonAsync("/connect/register", new DcrRequest());
        Assert.Equal(HttpStatusCode.Unauthorized, afterRevocation.StatusCode);

        using var scope = factory.Services.CreateScope();
        var database = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var reasons = await database.ManagementAuditEvents.AsNoTracking()
            .Where(audit => audit.ResourceId == tokenId || audit.ResourceId == secondId)
            .Select(audit => audit.ReasonCode)
            .ToListAsync();
        Assert.Equal(2, reasons.Count(reason => reason == "dcr_initial_access_token_issued"));
        Assert.Single(reasons, reason => reason == "dcr_initial_access_token_revoked");
    }
}
