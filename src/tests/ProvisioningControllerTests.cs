using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Abstractions;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Management.Authorization;
using Sufficit.Identity.Management.Provisioning;
using Sufficit.Identity.Tests.Infrastructure;
using Xunit;

namespace Sufficit.Identity.Tests;

public sealed class ProvisioningControllerTests
{
    [Fact]
    public async Task Preview_uses_the_canonical_service_and_persists_audit()
    {
        await using var factory = new ManagementTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        using var client = factory.CreateClient();

        using var response = await client.PostAsJsonAsync(
            "/api/provisioning/manifest/preview",
            EmptyManifest());

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var plan = await response.Content
            .ReadFromJsonAsync<IdentityProvisioningPlan>();
        Assert.NotNull(plan);
        Assert.Empty(plan.Changes);

        using var scope = factory.Services.CreateScope();
        var database = scope.ServiceProvider
            .GetRequiredService<AppDbContext>();
        Assert.Contains(
            await database.ManagementAuditEvents
                .AsNoTracking()
                .ToArrayAsync(),
            entry =>
                entry.Capability ==
                    ManagementCapabilities.ProvisioningPreview
                && entry.OperationOutcome == "succeeded"
                && entry.ReasonCode ==
                    "provisioning_manifest_current");
    }

    [Fact]
    public async Task Inventory_reports_undeclared_clients_without_mutation()
    {
        await using var factory = new ManagementTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        using var client = factory.CreateClient();

        using var response = await client.PostAsJsonAsync(
            "/api/provisioning/manifest/inventory",
            EmptyManifest());

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var inventory = await response.Content
            .ReadFromJsonAsync<IdentityProvisioningInventory>();
        Assert.NotNull(inventory);
        Assert.Null(inventory.ManifestId);
        Assert.True(inventory.GeneratedAtUtc.HasValue);
        Assert.False(string.IsNullOrWhiteSpace(inventory.CorrelationId));
        Assert.Equal(
            inventory.Entries.Count,
            inventory.StatusCounts.Values.Sum());
        Assert.Contains(
            inventory.Entries,
            entry =>
                entry.ClientId == TestDataSeeder.ClientCredentialsClientId
                && entry.Status ==
                    IdentityManifestInventoryStatus.UnmanagedAndUndeclared);
        Assert.True(
            inventory.StatusCounts.TryGetValue(
                nameof(IdentityManifestInventoryStatus.UnmanagedAndUndeclared),
                out var unmanagedCount));
        Assert.True(unmanagedCount > 0);
        using var scope = factory.Services.CreateScope();
        var database = scope.ServiceProvider
            .GetRequiredService<AppDbContext>();
        Assert.Contains(
            await database
                .ManagementAuditEvents
                .AsNoTracking()
                .ToArrayAsync(),
            entry =>
                entry.Capability ==
                    ManagementCapabilities.ProvisioningPreview
                && entry.OperationOutcome == "succeeded"
                && entry.ReasonCode ==
                    "provisioning_manifest_inventory");
    }

    [Fact]
    public async Task Apply_is_transactional_and_persists_audit()
    {
        await using var factory = new ManagementTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        using var client = factory.CreateClient();
        var scopeName = $"provisioned_{Guid.NewGuid():N}";
        var manifest = EmptyManifest();
        manifest.Scopes =
        [
            new
            {
                name = scopeName,
                displayName = "Provisioned scope",
                resources = new[] { "test-api" }
            }
        ];

        using var response = await client.PostAsJsonAsync(
            "/api/provisioning/manifest/apply",
            manifest);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var plan = await response.Content
            .ReadFromJsonAsync<IdentityProvisioningPlan>();
        Assert.NotNull(plan);
        Assert.Contains(
            plan.Changes,
            change =>
                change.Identifier == scopeName
                && change.Kind == IdentityManifestChangeKind.Create);

        using var scope = factory.Services.CreateScope();
        var database = scope.ServiceProvider
            .GetRequiredService<AppDbContext>();
        var scopes = scope.ServiceProvider
            .GetRequiredService<IOpenIddictScopeManager>();
        Assert.NotNull(await scopes.FindByNameAsync(scopeName));
        Assert.Contains(
            await database.ManagementAuditEvents
                .AsNoTracking()
                .ToArrayAsync(),
            entry =>
                entry.Capability ==
                    ManagementCapabilities.ProvisioningApply
                && entry.OperationOutcome == "succeeded"
                && entry.ReasonCode ==
                    "provisioning_manifest_applied");
    }

    [Fact]
    public async Task Invalid_manifest_returns_structured_errors()
    {
        await using var factory = new ManagementTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        using var client = factory.CreateClient();
        var invalid = EmptyManifest();
        invalid.SchemaVersion = 99;

        using var response = await client.PostAsJsonAsync(
            "/api/provisioning/manifest/preview",
            invalid);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var problem = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal(
            "provisioning_manifest_invalid",
            problem.GetProperty("reasonCode").GetString());
        Assert.NotEmpty(problem.GetProperty("errors").EnumerateArray());
    }

    [Fact]
    public async Task Temporary_token_is_attenuated_and_audited_without_secret_value()
    {
        await using var factory = new ManagementTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        using var client = factory.CreateClient();

        using var response = await client.PostAsJsonAsync(
            "/api/provisioning/token",
            new ProvisioningTokenIssueRequest(60));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var issued = await response.Content
            .ReadFromJsonAsync<ProvisioningTokenIssueResult>();
        Assert.NotNull(issued);
        Assert.False(string.IsNullOrWhiteSpace(issued.AccessToken));
        Assert.Equal("Bearer", issued.TokenType);
        Assert.Equal(["identity.management"], issued.Scopes);
        Assert.Equal(
            [
                ManagementCapabilities.ProvisioningPreview,
                ManagementCapabilities.ProvisioningApply
            ],
            issued.Capabilities);
        Assert.InRange(
            issued.ExpiresAtUtc,
            DateTimeOffset.UtcNow.AddSeconds(45),
            DateTimeOffset.UtcNow.AddSeconds(75));

        using var scope = factory.Services.CreateScope();
        var database = scope.ServiceProvider
            .GetRequiredService<AppDbContext>();
        var audit = Assert.Single(
            await database.ManagementAuditEvents
                .AsNoTracking()
                .Where(entry => entry.ReasonCode ==
                    "provisioning_temporary_token_issued")
                .ToArrayAsync());
        Assert.Equal("succeeded", audit.OperationOutcome);
        Assert.DoesNotContain(
            issued.AccessToken,
            audit.ResourceId ?? string.Empty,
            StringComparison.Ordinal);
    }

    private static MutableManifestRequest EmptyManifest() =>
        new()
        {
            SchemaVersion = IdentityProvisioningManifest.CurrentSchemaVersion
        };

    private sealed class MutableManifestRequest
    {
        public int SchemaVersion { get; set; }

        public object[] Scopes { get; set; } = [];

        public object[] Clients { get; set; } = [];
    }
}
