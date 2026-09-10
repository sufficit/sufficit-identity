using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using System.Security.Claims;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Abstractions;
using Sufficit.Identity.Management.Scopes;
using Sufficit.Identity.Management.Authorization;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Tests.Infrastructure;
using Xunit;

namespace Sufficit.Identity.Tests;

public sealed class AudiencesControllerTests
{
    [Fact]
    public async Task Inventory_groups_resources_case_sensitively_and_includes_unbound_scopes()
    {
        using var factory = new ManagementTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        var first = await SeedAsync(factory, "inventory.first", ["Orders", "orders"]);
        var second = await SeedAsync(factory, "inventory.second", ["Orders"], manifest: true);
        var empty = await SeedAsync(factory, "inventory.empty", []);
        using var client = factory.CreateClient();
        var inventory = await client.GetFromJsonAsync<ManagementAudienceInventory>("/api/audiences");
        Assert.NotNull(inventory);
        Assert.Equal(2, inventory.Audiences.Single(a => a.Name == "Orders").Scopes.Count);
        Assert.Single(inventory.Audiences.Single(a => a.Name == "orders").Scopes);
        Assert.True(inventory.Scopes.Single(s => s.Id == second).IsManifestManaged);
        Assert.Empty(inventory.Scopes.Single(s => s.Id == empty).Resources);
        Assert.Contains(inventory.Scopes, s => s.Id == first);
    }

    [Fact]
    public async Task Binding_preserves_metadata_and_other_resources_and_rejects_stale_edits()
    {
        using var factory = new ManagementTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        var id = await SeedAsync(factory, "binding.test", ["existing"]);
        using var client = factory.CreateClient();
        using var add = await client.PutAsJsonAsync($"/api/audiences/scopes/{id}",
            new UpdateAudienceBindingCommand("new-api", true, ["existing"]));
        Assert.Equal(HttpStatusCode.OK, add.StatusCode);
        var detail = await add.Content.ReadFromJsonAsync<ManagementScopeDetail>();
        Assert.Equal("Display", detail!.DisplayName);
        Assert.Equal("Description", detail.Description);
        Assert.Equal(new[] { "existing", "new-api" }, detail.Resources.Order());
        using var stale = await client.PutAsJsonAsync($"/api/audiences/scopes/{id}",
            new UpdateAudienceBindingCommand("other-api", true, ["existing"]));
        Assert.Equal(HttpStatusCode.Conflict, stale.StatusCode);
        Assert.Contains("audience_bindings_changed", await stale.Content.ReadAsStringAsync());
        using var remove = await client.PutAsJsonAsync($"/api/audiences/scopes/{id}",
            new UpdateAudienceBindingCommand("new-api", false, ["existing", "new-api"]));
        Assert.Equal(HttpStatusCode.OK, remove.StatusCode);
        Assert.Equal(new[] { "existing" }, (await remove.Content.ReadFromJsonAsync<ManagementScopeDetail>())!.Resources);
        await using var auditScope = factory.Services.CreateAsyncScope();
        var database = auditScope.ServiceProvider.GetRequiredService<AppDbContext>();
        Assert.Equal(2, await database.ManagementAuditEvents.CountAsync(a => a.ResourceId == id && a.ReasonCode == "scope_updated"));
    }

    [Fact]
    public async Task Read_capability_does_not_grant_binding_updates_at_the_service_boundary()
    {
        using var factory = ManagementTestFactory.CreateWithRealAuthz();
        await ((IAsyncLifetime)factory).InitializeAsync();
        await using var scope = factory.Services.CreateAsyncScope();
        var service = scope.ServiceProvider.GetRequiredService<IScopeManagementService>();
        var principal = new ClaimsPrincipal(new ClaimsIdentity([
            new Claim(ClaimTypes.NameIdentifier, "audience-reader"),
            new Claim("permission", ManagementCapabilities.ScopesRead)], "test"));
        var context = new ManagementRequestContext(principal, "audience-capability-test");
        Assert.NotNull(await service.ListAudiencesAsync(context));
        await Assert.ThrowsAsync<ManagementAccessException>(() => service.UpdateAudienceBindingAsync(
            "missing", new UpdateAudienceBindingCommand("api", true, []), context));
    }

    [Fact]
    public async Task Manifest_bindings_are_read_only()
    {
        using var factory = new ManagementTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        var id = await SeedAsync(factory, "manifest.binding", ["existing"], manifest: true);
        using var client = factory.CreateClient();
        foreach (var assigned in new[] { true, false })
        {
            using var response = await client.PutAsJsonAsync($"/api/audiences/scopes/{id}",
                new UpdateAudienceBindingCommand("existing", assigned, ["existing"]));
            Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
        }
    }

    [Theory]
    [InlineData("entitlements")]
    [InlineData("directives")]
    [InlineData("profile")]
    public async Task Claims_scopes_cannot_receive_new_audiences(string name)
    {
        using var factory = new ManagementTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        var id = await SeedAsync(factory, name, []);
        using var client = factory.CreateClient();
        using var response = await client.PutAsJsonAsync($"/api/audiences/scopes/{id}",
            new UpdateAudienceBindingCommand("new-api", true, []));
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Theory]
    [InlineData("")]
    [InlineData("bad audience")]
    [InlineData("bad\nname")]
    public async Task Invalid_identifier_does_not_change_scope(string audience)
    {
        using var factory = new ManagementTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        var id = await SeedAsync(factory, "invalid.binding", []);
        using var client = factory.CreateClient();
        using var response = await client.PutAsJsonAsync($"/api/audiences/scopes/{id}",
            new UpdateAudienceBindingCommand(audience, true, []));
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Empty((await client.GetFromJsonAsync<ManagementScopeDetail>($"/api/scopes/{id}"))!.Resources);
    }

    [Fact]
    public async Task Anonymous_cannot_read_or_change_audiences()
    {
        using var factory = ManagementTestFactory.CreateWithRealAuthz();
        await ((IAsyncLifetime)factory).InitializeAsync();
        using var client = factory.CreateClient();
        using var read = await client.GetAsync("/api/audiences");
        using var update = await client.PutAsJsonAsync("/api/audiences/scopes/missing",
            new UpdateAudienceBindingCommand("api", true, []));
        Assert.Contains(read.StatusCode, new[] { HttpStatusCode.Unauthorized, HttpStatusCode.Forbidden });
        Assert.Contains(update.StatusCode, new[] { HttpStatusCode.Unauthorized, HttpStatusCode.Forbidden });
    }

    private static async Task<string> SeedAsync(ManagementTestFactory factory, string name,
        string[] resources, bool manifest = false)
    {
        await using var scope = factory.Services.CreateAsyncScope();
        var manager = scope.ServiceProvider.GetRequiredService<IOpenIddictScopeManager>();
        var descriptor = new OpenIddictScopeDescriptor
        { Name = name, DisplayName = "Display", Description = "Description" };
        descriptor.Resources.UnionWith(resources);
        if (manifest)
            descriptor.Properties["identity:provisioning-manifest:schema-version"] = JsonSerializer.SerializeToElement(1);
        var entity = await manager.CreateAsync(descriptor);
        return (await manager.GetIdAsync(entity))!;
    }
}
