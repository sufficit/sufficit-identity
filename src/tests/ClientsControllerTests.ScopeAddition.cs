using System.Net;
using System.Net.Http.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Abstractions;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Management.Clients;
using Sufficit.Identity.Tests.Infrastructure;
using Xunit;

namespace Sufficit.Identity.Tests;

public sealed partial class ClientsControllerTests
{
    [Fact]
    public async Task Scope_addition_preserves_existing_permissions_and_is_idempotent()
    {
        using var factory = new ManagementTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        using var client = factory.CreateClient();
        await using var setup = factory.Services.CreateAsyncScope();
        var applications = setup.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
        var scopes = setup.ServiceProvider.GetRequiredService<IOpenIddictScopeManager>();
        const string name = "example.reports";
        await scopes.CreateAsync(new OpenIddictScopeDescriptor { Name = name });
        var clientId = $"ExamplePortal-{Guid.NewGuid():N}";
        await applications.CreateAsync(new OpenIddictApplicationDescriptor
        {
            ClientId = clientId,
            ClientType = "public",
            RedirectUris = { new Uri("https://client.example.invalid/signin") },
            Permissions = { "gt:authorization_code", "ept:authorization", "ept:token",
                "ept:pushed_authorization", "rst:code", "scp:identity.management" },
            Requirements = { "ft:pkce" },
        });

        var path = $"/api/clients/{clientId}";
        var before = await client.GetFromJsonAsync<ManagementClientDetail>(path);
        Assert.NotNull(before);
        var scopePath = $"{path}/scopes/{name}";

        using var stale = await client.PutAsJsonAsync(scopePath, new { expectedVersion = "stale" });
        Assert.Equal(HttpStatusCode.Conflict, stale.StatusCode);
        using var reserved = await client.PutAsJsonAsync($"{path}/scopes/scim", new { expectedVersion = before.Version });
        Assert.Equal(HttpStatusCode.BadRequest, reserved.StatusCode);

        using var added = await client.PutAsJsonAsync(scopePath, new { expectedVersion = before.Version });
        Assert.Equal(HttpStatusCode.NoContent, added.StatusCode);
        var after = await client.GetFromJsonAsync<ManagementClientDetail>(path);
        Assert.NotNull(after);
        Assert.Equal(before.Permissions.Append($"scp:{name}").Order(), after.Permissions.Order());
        Assert.Equal(before.Requirements, after.Requirements);
        Assert.Equal(before.RedirectUris, after.RedirectUris);
        Assert.NotEqual(before.Version, after.Version);

        using var replay = await client.PutAsJsonAsync(scopePath, new { expectedVersion = before.Version });
        Assert.Equal(HttpStatusCode.NoContent, replay.StatusCode);
        var database = setup.ServiceProvider.GetRequiredService<AppDbContext>();
        var audit = await database.ManagementAuditEvents.AsNoTracking()
            .SingleAsync(row => row.ResourceId == clientId && row.ReasonCode == "client_scope_added");
        Assert.Contains(name, audit.AfterJson);
    }
}
