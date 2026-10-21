using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.Tests.Infrastructure;
using Xunit;

namespace Sufficit.Identity.Tests;

public sealed class CurrentEntitlementsFlowTests
{
    [Fact]
    public async Task Self_query_includes_current_role_grants_and_revokes_without_new_token()
    {
        using var factory = SufficitIdentityTestFactory.CreateIsolated(new Dictionary<string, string?>
        {
            ["Sufficit:Identity:ClaimScopeMap:ServerResolvedEntitlementKeys:0"] = "example.read",
            ["Sufficit:Identity:ClaimScopeMap:ServerResolvedEntitlementKeys:1"] = "example.operate"
        });
        await ((IAsyncLifetime)factory).InitializeAsync();
        var username = "current-grants-" + Guid.NewGuid().ToString("N");
        const string password = "Str0ng!Passw0rd#Example";
        var direct = new Claim("entitlements", "example.read:workspace/alpha");
        var inherited = new Claim("entitlements", "example.operate:resource:beta");
        string userId;
        using (var scope = factory.Services.CreateScope())
        {
            var users = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
            await TestDataSeeder.CreateUserAsync(users, username, password);
            var user = (await users.FindByNameAsync(username))!;
            userId = user.Id;
            Assert.True((await users.AddClaimAsync(user, direct)).Succeeded);
            var roles = scope.ServiceProvider.GetRequiredService<RoleManager<ApplicationRole>>();
            var role = new ApplicationRole { Name = "test-resource-operators" };
            Assert.True((await roles.CreateAsync(role)).Succeeded);
            Assert.True((await roles.AddClaimAsync(role, inherited)).Succeeded);
            Assert.True((await users.AddToRoleAsync(user, role.Name)).Succeeded);
        }
        var client = factory.CreateClient();
        var (status, body) = await client.PostFormAsync("/connect/token", new Dictionary<string, string>
        {
            ["grant_type"] = "password", ["username"] = username, ["password"] = password,
            ["client_id"] = TestDataSeeder.PasswordClientId,
            ["client_secret"] = TestDataSeeder.PasswordClientSecret,
            ["scope"] = "openid roles " + TestDataSeeder.ScopeName
        });
        Assert.Equal(HttpStatusCode.OK, status);
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", body.GetProperty("access_token").GetString());
        var ordinary = await client.GetFromJsonAsync<JsonElement>("/connect/userinfo");
        Assert.False(ordinary.TryGetProperty("authorization", out _));
        Assert.DoesNotContain("example.read", ordinary.GetRawText());
        var first = await client.GetFromJsonAsync<JsonElement>("/connect/userinfo?entitlements=current&userId=another-user");
        Assert.Equal(userId, first.GetProperty("sub").GetString());
        var grants = first.GetProperty("authorization").GetProperty("grants").EnumerateArray().Select(x => x.GetString()).ToArray();
        Assert.Contains(direct.Value, grants);
        Assert.Contains(inherited.Value, grants);
        using (var scope = factory.Services.CreateScope())
        {
            var users = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
            var user = (await users.FindByIdAsync(userId))!;
            Assert.True((await users.RemoveClaimAsync(user, direct)).Succeeded);
            Assert.True((await users.RemoveFromRoleAsync(user, "test-resource-operators")).Succeeded);
        }
        var last = await client.GetFromJsonAsync<JsonElement>("/connect/userinfo?entitlements=current");
        Assert.Empty(last.GetProperty("authorization").GetProperty("grants").EnumerateArray());
        client.DefaultRequestHeaders.Authorization = null;
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.GetAsync("/connect/userinfo?entitlements=current")).StatusCode);
    }

    // 21/10/2026: with server-resolved keys configured, a user holding one of
    // them and an ordinary entitlement failed every sign-in with HTTP 500
    // ("Conflicting destinations for the claim 'entitlements'"): OpenIddict
    // keeps destinations per claim type, and with the directives scope granted
    // the ordinary value went to the access token while the server-resolved
    // one went nowhere.
    [Fact]
    public async Task Mixed_server_resolved_and_ordinary_entitlements_agree_on_destinations()
    {
        using var factory = SufficitIdentityTestFactory.CreateIsolated(new Dictionary<string, string?>
        {
            ["Sufficit:Identity:ClaimScopeMap:ServerResolvedEntitlementKeys:0"] = "example.read",
        });
        await ((IAsyncLifetime)factory).InitializeAsync();
        using var scope = factory.Services.CreateScope();
        var grants = scope.ServiceProvider.GetRequiredService<Sufficit.Identity.STS.Grants.GrantOperations>();

        var identity = new ClaimsIdentity("test");
        identity.AddClaim(new Claim(OpenIddict.Abstractions.OpenIddictConstants.Claims.Subject, "user-1"));
        identity.AddClaim(new Claim("entitlements", "example.read:workspace/alpha"));
        identity.AddClaim(new Claim("entitlements", "example.other:workspace/alpha"));
        OpenIddict.Abstractions.OpenIddictExtensions.SetScopes(identity, "openid", "directives");

        grants.ApplyDestinations(identity);

        // The same check OpenIddict runs while generating the token.
        var destinations = OpenIddict.Abstractions.OpenIddictExtensions.GetDestinations(new ClaimsPrincipal(identity));
        Assert.Contains(OpenIddict.Abstractions.OpenIddictConstants.Destinations.AccessToken, destinations["entitlements"]);
        Assert.DoesNotContain(identity.Claims, claim => claim.Value == "example.read:workspace/alpha");
        Assert.Contains(identity.Claims, claim => claim.Value == "example.other:workspace/alpha");
    }
}
