using System.Net;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.Management.Controllers;
using Sufficit.Identity.Tests.Infrastructure;
using Xunit;

namespace Sufficit.Identity.Tests;

public sealed class ClaimsControllerTests
{
    [Fact]
    public async Task Metadata_exposes_the_canonical_claim_suggestions()
    {
        using var factory = new ManagementTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        using var client = factory.CreateClient();

        using var response = await client.GetAsync("/api/claims/metadata");
        var body = await response.Content.ReadFromJsonAsync<JsonElement>();

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(256, body.GetProperty("typeMaxLength").GetInt32());
        Assert.Equal(4096, body.GetProperty("valueMaxLength").GetInt32());
        Assert.Contains(
            body.GetProperty("suggestedTypes").EnumerateArray(),
            value => value.GetString() == "locale");
    }

    [Fact]
    public async Task List_returns_persisted_custom_claim_assignments()
    {
        using var factory = new ManagementTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        using var client = factory.CreateClient();

        using var response = await client.GetAsync(
            $"/api/claims?search={Uri.EscapeDataString(TestDataSeeder.DefaultDirectiveValue)}");
        var body = await response.Content.ReadFromJsonAsync<JsonElement>();

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(1, body.GetProperty("totalCount").GetInt32());
        var claim = body.GetProperty("items")[0];
        Assert.Equal(
            TestDataSeeder.DirectiveClaimType,
            claim.GetProperty("type").GetString());
        Assert.Equal(
            TestDataSeeder.DefaultDirectiveValue,
            claim.GetProperty("value").GetString());
        Assert.Equal(
            TestDataSeeder.DefaultUsername,
            claim.GetProperty("userName").GetString());
    }

    [Fact]
    public async Task Create_update_and_delete_change_security_stamp_and_redact_audit()
    {
        using var factory = new ManagementTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        using var client = factory.CreateClient();

        string userId;
        string initialStamp;
        await using (var scope = factory.Services.CreateAsyncScope())
        {
            var users = scope.ServiceProvider
                .GetRequiredService<UserManager<ApplicationUser>>();
            var user = await users.FindByNameAsync(
                TestDataSeeder.DefaultUsername)
                ?? throw new InvalidOperationException("Seeded user is missing.");
            userId = user.Id;
            initialStamp = await users.GetSecurityStampAsync(user);
        }

        var secretValue = $"private-value-{Guid.NewGuid():N}";
        using var created = await client.PostAsJsonAsync(
            "/api/claims",
            new CreateClaimRequest
            {
                UserId = userId,
                Type = "urn:tests:department",
                Value = secretValue
            });
        var createdBody = await created.Content.ReadFromJsonAsync<JsonElement>();
        var claimId = createdBody.GetProperty("id").GetInt32();

        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        Assert.Equal(
            "urn:tests:department",
            createdBody.GetProperty("type").GetString());

        string stampAfterCreate;
        await using (var scope = factory.Services.CreateAsyncScope())
        {
            var users = scope.ServiceProvider
                .GetRequiredService<UserManager<ApplicationUser>>();
            var user = await users.FindByIdAsync(userId)
                ?? throw new InvalidOperationException("Seeded user is missing.");
            stampAfterCreate = await users.GetSecurityStampAsync(user);
        }
        Assert.NotEqual(initialStamp, stampAfterCreate);

        var updatedSecretValue = $"updated-private-value-{Guid.NewGuid():N}";
        using var updated = await client.PutAsJsonAsync(
            $"/api/claims/{claimId}",
            new UpdateClaimRequest
            {
                Type = "urn:tests:office",
                Value = updatedSecretValue
            });
        var updatedBody = await updated.Content.ReadFromJsonAsync<JsonElement>();

        Assert.Equal(HttpStatusCode.OK, updated.StatusCode);
        Assert.Equal(
            "urn:tests:office",
            updatedBody.GetProperty("type").GetString());
        Assert.Equal(
            updatedSecretValue,
            updatedBody.GetProperty("value").GetString());

        string stampAfterUpdate;
        await using (var scope = factory.Services.CreateAsyncScope())
        {
            var users = scope.ServiceProvider
                .GetRequiredService<UserManager<ApplicationUser>>();
            var user = await users.FindByIdAsync(userId)
                ?? throw new InvalidOperationException("Seeded user is missing.");
            stampAfterUpdate = await users.GetSecurityStampAsync(user);
        }
        Assert.NotEqual(stampAfterCreate, stampAfterUpdate);

        using var deleted = await client.DeleteAsync($"/api/claims/{claimId}");
        Assert.Equal(HttpStatusCode.NoContent, deleted.StatusCode);

        await using var verificationScope =
            factory.Services.CreateAsyncScope();
        var database = verificationScope.ServiceProvider
            .GetRequiredService<AppDbContext>();
        var events = await database.ManagementAuditEvents
            .Where(entry =>
                entry.ResourceType == "claim"
                && (entry.Capability == "identity.claims.create"
                    || entry.Capability == "identity.claims.update"
                    || entry.Capability == "identity.claims.delete"))
            .OrderBy(entry => entry.Id)
            .ToArrayAsync();

        Assert.Equal(3, events.Length);
        Assert.Equal("identity.claims.create", events[0].Capability);
        Assert.Equal("identity.claims.update", events[1].Capability);
        Assert.Equal("identity.claims.delete", events[2].Capability);
        Assert.All(events, entry =>
        {
            Assert.DoesNotContain(
                secretValue,
                entry.OperatorSubject,
                StringComparison.Ordinal);
            Assert.DoesNotContain(
                secretValue,
                entry.CorrelationId,
                StringComparison.Ordinal);
            Assert.DoesNotContain(
                updatedSecretValue,
                entry.CorrelationId,
                StringComparison.Ordinal);
        });
    }

    [Theory]
    [InlineData("sub")]
    [InlineData("email")]
    [InlineData("role")]
    [InlineData("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier")]
    public async Task Create_rejects_reserved_claim_types(string type)
    {
        using var factory = new ManagementTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        using var client = factory.CreateClient();

        string userId;
        await using (var scope = factory.Services.CreateAsyncScope())
        {
            var users = scope.ServiceProvider
                .GetRequiredService<UserManager<ApplicationUser>>();
            userId = (await users.FindByNameAsync(
                    TestDataSeeder.DefaultUsername)
                ?? throw new InvalidOperationException("Seeded user is missing."))
                .Id;
        }

        using var response = await client.PostAsJsonAsync(
            "/api/claims",
            new CreateClaimRequest
            {
                UserId = userId,
                Type = type,
                Value = "attempted-override"
            });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task Create_rejects_duplicate_assignment()
    {
        using var factory = new ManagementTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        using var client = factory.CreateClient();

        string userId;
        await using (var scope = factory.Services.CreateAsyncScope())
        {
            var users = scope.ServiceProvider
                .GetRequiredService<UserManager<ApplicationUser>>();
            userId = (await users.FindByNameAsync(
                    TestDataSeeder.DefaultUsername)
                ?? throw new InvalidOperationException("Seeded user is missing."))
                .Id;
        }

        using var response = await client.PostAsJsonAsync(
            "/api/claims",
            new CreateClaimRequest
            {
                UserId = userId,
                Type = TestDataSeeder.DirectiveClaimType,
                Value = TestDataSeeder.DefaultDirectiveValue
            });

        Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
    }
}
