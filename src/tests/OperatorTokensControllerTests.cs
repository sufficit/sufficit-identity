using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Management.Authorization;
using Sufficit.Identity.Management.OperatorTokens;
using Sufficit.Identity.Tests.Infrastructure;
using Xunit;

namespace Sufficit.Identity.Tests;

public sealed class OperatorTokensControllerTests
{
    [Fact]
    public async Task Issue_list_and_revoke_use_attenuated_metadata_without_auditing_secret()
    {
        await using var factory = new ManagementTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        using var client = factory.CreateClient();
        var requestedCapabilities = new[]
        {
            ManagementCapabilities.ClientsRead,
            ManagementCapabilities.ClientsUpdate,
        };

        using var issueResponse = await client.PostAsJsonAsync(
            "/api/operator-tokens",
            new IssueOperatorTokenCommand(
                "Atualizar clientes Hermes",
                300,
                requestedCapabilities));

        Assert.Equal(HttpStatusCode.OK, issueResponse.StatusCode);
        var issued = await issueResponse.Content
            .ReadFromJsonAsync<OperatorTokenIssueResult>();
        Assert.NotNull(issued);
        Assert.False(string.IsNullOrWhiteSpace(issued.AccessToken));
        Assert.Equal("Bearer", issued.TokenType);
        Assert.Equal(["identity.management"], issued.Scopes);
        Assert.Equal(requestedCapabilities, issued.Capabilities);
        Assert.Equal("Atualizar clientes Hermes", issued.Token.Purpose);
        Assert.InRange(
            issued.ExpiresAtUtc,
            DateTimeOffset.UtcNow.AddSeconds(275),
            DateTimeOffset.UtcNow.AddSeconds(325));

        using var listResponse = await client.GetAsync("/api/operator-tokens");
        Assert.Equal(HttpStatusCode.OK, listResponse.StatusCode);
        var workspace = await listResponse.Content
            .ReadFromJsonAsync<OperatorTokenWorkspace>();
        Assert.NotNull(workspace);
        Assert.True(workspace.IssuanceEnabled);
        var active = Assert.Single(workspace.ActiveTokens);
        Assert.Equal(issued.Token.Id, active.Id);
        Assert.Equal(requestedCapabilities, active.Capabilities);
        Assert.DoesNotContain(
            ManagementCapabilities.OperatorTokensIssue,
            workspace.AvailableCapabilities);
        Assert.DoesNotContain(
            ManagementCapabilities.OperatorTokensRevoke,
            workspace.AvailableCapabilities);

        using (var scope = factory.Services.CreateScope())
        {
            var database = scope.ServiceProvider
                .GetRequiredService<AppDbContext>();
            var audit = Assert.Single(
                await database.ManagementAuditEvents
                    .AsNoTracking()
                    .Where(entry => entry.ReasonCode ==
                        "temporary_operator_token_issued")
                    .ToArrayAsync());
            Assert.Equal("succeeded", audit.OperationOutcome);
            Assert.Equal(
                ManagementCapabilities.OperatorTokensIssue,
                audit.Capability);
            Assert.DoesNotContain(
                issued.AccessToken,
                audit.ResourceId ?? string.Empty,
                StringComparison.Ordinal);
        }

        using var revokeResponse = await client.DeleteAsync(
            $"/api/operator-tokens/{issued.Token.Id}");
        Assert.Equal(HttpStatusCode.NoContent, revokeResponse.StatusCode);

        using var listAfterRevokeResponse = await client.GetAsync(
            "/api/operator-tokens");
        Assert.Equal(HttpStatusCode.OK, listAfterRevokeResponse.StatusCode);
        var afterRevoke = await listAfterRevokeResponse.Content
            .ReadFromJsonAsync<OperatorTokenWorkspace>();
        Assert.NotNull(afterRevoke);
        Assert.Empty(afterRevoke.ActiveTokens);

        using (var scope = factory.Services.CreateScope())
        {
            var database = scope.ServiceProvider
                .GetRequiredService<AppDbContext>();
            Assert.Contains(
                await database.ManagementAuditEvents
                    .AsNoTracking()
                    .ToArrayAsync(),
                entry => entry.ReasonCode ==
                    "temporary_operator_token_revoked"
                    && entry.OperationOutcome == "succeeded");
        }
    }

    [Fact]
    public async Task Issue_rejects_token_management_capabilities_as_non_delegable()
    {
        await using var factory = new ManagementTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        using var client = factory.CreateClient();

        using var response = await client.PostAsJsonAsync(
            "/api/operator-tokens",
            new IssueOperatorTokenCommand(
                "Tentar delegar emissão",
                300,
                [ManagementCapabilities.OperatorTokensIssue]));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var problem = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal(
            "operator_token_capability_not_delegable",
            problem.GetProperty("reasonCode").GetString());

        using var scope = factory.Services.CreateScope();
        var database = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        Assert.Contains(
            await database.ManagementAuditEvents.AsNoTracking().ToArrayAsync(),
            entry => entry.ReasonCode ==
                "operator_token_capability_not_delegable"
                && entry.OperationOutcome == "rejected");
    }

    [Fact]
    public async Task Issue_rejects_lifetime_above_the_one_hour_hard_limit()
    {
        await using var factory = new ManagementTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        using var client = factory.CreateClient();

        using var response = await client.PostAsJsonAsync(
            "/api/operator-tokens",
            new IssueOperatorTokenCommand(
                "Validade excessiva",
                3601,
                [ManagementCapabilities.ClientsRead]));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var problem = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal(
            "operator_token_lifetime_invalid",
            problem.GetProperty("reasonCode").GetString());
    }
}
