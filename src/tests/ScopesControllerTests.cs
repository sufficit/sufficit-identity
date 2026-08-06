using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Abstractions;
using Sufficit.Identity.Management.Controllers;
using Sufficit.Identity.Tests.Infrastructure;
using Xunit;

namespace Sufficit.Identity.Tests;

public sealed class ScopesControllerTests
{
    [Fact]
    public async Task Create_update_and_delete_manage_a_custom_scope()
    {
        using var factory = new ManagementTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        using var client = factory.CreateClient();
        var scopeName = $"orders.read.{Guid.NewGuid():N}";

        using var created = await client.PostAsJsonAsync(
            "/api/scopes",
            new CreateScopeRequest
            {
                Name = scopeName,
                DisplayName = "Read orders",
                Description = "Reads order records.",
                Resources = ["orders-api"]
            });
        var createdBody = await created.Content.ReadFromJsonAsync<JsonElement>();
        var scopeId = createdBody.GetProperty("id").GetString()
            ?? throw new InvalidOperationException("Created scope has no id.");

        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        Assert.Equal(scopeName, createdBody.GetProperty("name").GetString());
        Assert.False(createdBody.GetProperty("isManifestManaged").GetBoolean());

        using var updated = await client.PutAsJsonAsync(
            $"/api/scopes/{Uri.EscapeDataString(scopeId)}",
            new UpdateScopeRequest
            {
                DisplayName = "Orders — read only",
                Description = "Reads orders without mutation.",
                Resources = ["orders-api", "reports-api"]
            });
        var updatedBody = await updated.Content.ReadFromJsonAsync<JsonElement>();

        Assert.Equal(HttpStatusCode.OK, updated.StatusCode);
        Assert.Equal(
            "Orders — read only",
            updatedBody.GetProperty("displayName").GetString());
        Assert.Equal(2, updatedBody.GetProperty("resources").GetArrayLength());

        using var deleted = await client.DeleteAsync(
            $"/api/scopes/{Uri.EscapeDataString(scopeId)}");
        Assert.Equal(HttpStatusCode.NoContent, deleted.StatusCode);

        using var missing = await client.GetAsync(
            $"/api/scopes/{Uri.EscapeDataString(scopeId)}");
        Assert.Equal(HttpStatusCode.NotFound, missing.StatusCode);
    }

    [Fact]
    public async Task Delete_is_blocked_while_clients_use_the_scope()
    {
        using var factory = new ManagementTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        using var client = factory.CreateClient();

        string scopeId;
        await using (var scope = factory.Services.CreateAsyncScope())
        {
            var scopes = scope.ServiceProvider
                .GetRequiredService<IOpenIddictScopeManager>();
            var entity = await scopes.FindByNameAsync(
                TestDataSeeder.ScopeName)
                ?? throw new InvalidOperationException("Seeded scope is missing.");
            scopeId = (string?)await scopes.GetIdAsync(entity)
                ?? throw new InvalidOperationException("Seeded scope has no id.");
        }

        using var response = await client.DeleteAsync(
            $"/api/scopes/{Uri.EscapeDataString(scopeId)}");

        Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
    }

    [Theory]
    [InlineData("openid")]
    [InlineData("offline_access")]
    [InlineData("bad scope")]
    [InlineData("bad\"scope")]
    // H2/M3: API-protection scopes are reserved and must be rejected at the
    // runtime CRUD boundary (declare them via bootstrap/provisioning instead).
    [InlineData("skoruba_identity_admin_api")]
    [InlineData("scim")]
    public async Task Create_rejects_protocol_or_invalid_scope_names(
        string name)
    {
        using var factory = new ManagementTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        using var client = factory.CreateClient();

        using var response = await client.PostAsJsonAsync(
            "/api/scopes",
            new CreateScopeRequest
            {
                Name = name,
                DisplayName = "Invalid scope"
            });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task Manifest_managed_scope_is_visible_but_read_only()
    {
        using var factory = new ManagementTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        using var client = factory.CreateClient();
        var name = $"manifest.{Guid.NewGuid():N}";
        string id;

        await using (var scope = factory.Services.CreateAsyncScope())
        {
            var scopes = scope.ServiceProvider
                .GetRequiredService<IOpenIddictScopeManager>();
            var descriptor = new OpenIddictScopeDescriptor
            {
                Name = name,
                DisplayName = "Manifest scope"
            };
            descriptor.Properties[
                "identity:provisioning-manifest:schema-version"] =
                JsonSerializer.SerializeToElement(1);
            var entity = await scopes.CreateAsync(descriptor);
            id = (string?)await scopes.GetIdAsync(entity)
                ?? throw new InvalidOperationException("Created scope has no id.");
        }

        using var detail = await client.GetAsync(
            $"/api/scopes/{Uri.EscapeDataString(id)}");
        var detailBody = await detail.Content.ReadFromJsonAsync<JsonElement>();
        Assert.True(
            detailBody.GetProperty("isManifestManaged").GetBoolean());

        using var update = await client.PutAsJsonAsync(
            $"/api/scopes/{Uri.EscapeDataString(id)}",
            new UpdateScopeRequest
            {
                DisplayName = "Attempted override"
            });
        using var delete = await client.DeleteAsync(
            $"/api/scopes/{Uri.EscapeDataString(id)}");

        Assert.Equal(HttpStatusCode.Conflict, update.StatusCode);
        Assert.Equal(HttpStatusCode.Conflict, delete.StatusCode);
    }
}
