using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.STS;
using Sufficit.Identity.Tests.Infrastructure;
using Xunit;

namespace Sufficit.Identity.Tests;

[Collection(StsCollection.Name)]
public sealed class ScopeEntitlementProvisionerTests(SufficitIdentityTestFactory factory)
{
    [Fact]
    public async Task An_entitlement_declared_under_the_legacy_name_is_stored_once_as_entitlements()
    {
        // The test scope still declares its grant as "directive", as one
        // production scope did: every approval wrote the grant a second time.
        using var scope = factory.Services.CreateScope();
        var users = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        var user = await TestDataSeeder.CreateUserAsync(users, $"entitled-{Guid.NewGuid():N}", "Str0ng!Passw0rd#Entitled");
        var provisioner = scope.ServiceProvider.GetRequiredService<ScopeEntitlementProvisioner>();

        Assert.True((await provisioner.ProvisionAsync(user, [TestDataSeeder.AiBridgeScopeName])).Succeeded);
        Assert.True((await provisioner.ProvisionAsync(user, [TestDataSeeder.AiBridgeScopeName])).Succeeded);

        var claims = await users.GetClaimsAsync(user);
        Assert.Single(claims, claim => claim.Type == "entitlements" && claim.Value == TestDataSeeder.AiBridgeEntitlementValue);
        Assert.DoesNotContain(claims, claim => claim.Type == "directive");
    }
}
