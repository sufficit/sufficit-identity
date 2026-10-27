using System.Net;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.Tests.Infrastructure;
using Xunit;
namespace Sufficit.Identity.Tests;
public sealed class EffectiveClaimsControllerTests
{
    [Fact]
    public async Task Current_snapshot_includes_role_claims_and_observes_revocation()
    {
        using var factory = new ManagementTestFactory(); await ((IAsyncLifetime)factory).InitializeAsync();
        using var client = factory.CreateClient(); await using var scope = factory.Services.CreateAsyncScope();
        var users = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        var roles = scope.ServiceProvider.GetRequiredService<RoleManager<ApplicationRole>>();
        var user = await users.FindByNameAsync(TestDataSeeder.DefaultUsername) ?? throw new InvalidOperationException();
        var role = new ApplicationRole { Name = "example-operator-" + Guid.NewGuid().ToString("N") };
        Assert.True((await roles.CreateAsync(role)).Succeeded);
        var grant = new Claim("entitlements", "example.operate:example-tenant");
        Assert.True((await roles.AddClaimAsync(role, grant)).Succeeded);
        Assert.True((await users.AddToRoleAsync(user, role.Name!)).Succeeded);
        var url = "/api/claims/effective?userId=" + Uri.EscapeDataString(user.Id);
        using var response = await client.GetAsync(url); Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.True(response.Headers.CacheControl?.NoStore);
        var body = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal(user.Id, body.GetProperty("subject").GetString());
        Assert.Contains(body.GetProperty("claims").EnumerateArray(), c => c.GetProperty("value").GetString() == grant.Value);
        Assert.True((await roles.RemoveClaimAsync(role, grant)).Succeeded);
        var next = await client.GetFromJsonAsync<JsonElement>(url);
        Assert.DoesNotContain(next.GetProperty("claims").EnumerateArray(), c => c.GetProperty("value").GetString() == grant.Value);
    }
    [Fact]
    public async Task Anonymous_consumer_cannot_select_another_user()
    {
        using var factory = ManagementTestFactory.CreateWithRealAuthz(); await ((IAsyncLifetime)factory).InitializeAsync();
        using var client = factory.CreateClient(); using var response = await client.GetAsync("/api/claims/effective?userId=example-user");
        Assert.True(response.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden);
    }
}
