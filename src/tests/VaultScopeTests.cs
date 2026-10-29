using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.Management;
using Sufficit.Identity.Tests.Infrastructure;
using Xunit;

namespace Sufficit.Identity.Tests;

/// <summary>
/// The shared Vault API accepts the management scope, or the narrow Vault scope only from a system user
/// (a client bound to one). A person's delegated credential carrying the narrow scope stays out.
/// </summary>
public sealed class VaultScopeTests
{
    private const string Management = "identity.management", Vault = "identity.vault";

    private static ClaimsPrincipal Principal(string scope, string? subject, string? clientId)
    {
        var claims = new List<Claim> { new("scope", scope) };
        if (subject is not null) claims.Add(new Claim("sub", subject));
        if (clientId is not null) claims.Add(new Claim("client_id", clientId));
        return new ClaimsPrincipal(new ClaimsIdentity(claims, "test"));
    }

    private static async Task<bool> Allowed(IServiceProvider services, ClaimsPrincipal principal)
    {
        var requirement = new VaultScopeRequirement(Management, Vault);
        var context = new AuthorizationHandlerContext([requirement], principal, null);
        await new VaultScopeHandler(services.GetRequiredService<IServiceScopeFactory>()).HandleAsync(context);
        return context.HasSucceeded;
    }

    [Fact]
    public async Task Narrow_scope_reaches_the_shared_vault_only_as_a_system_user()
    {
        var factory = SufficitIdentityTestFactory.CreateIsolated(new Dictionary<string, string?>());
        await ((IAsyncLifetime)factory).InitializeAsync();
        try
        {
            string systemUser, person;
            await using (var scope = factory.Services.CreateAsyncScope())
            {
                var users = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
                var system = new ApplicationUser { UserName = $"system-{Guid.NewGuid():N}" };
                Assert.True((await users.CreateAsync(system)).Succeeded);
                var human = new ApplicationUser { UserName = $"person-{Guid.NewGuid():N}", Email = $"{Guid.NewGuid():N}@example.com" };
                Assert.True((await users.CreateAsync(human, "Strong-Password-123!")).Succeeded);
                systemUser = system.Id; person = human.Id;
            }

            Assert.True(await Allowed(factory.Services, Principal(Management, person, "management-console")), "management scope keeps working");
            Assert.True(await Allowed(factory.Services, Principal(Vault, systemUser, "background-vault")), "system user with the narrow scope");
            Assert.False(await Allowed(factory.Services, Principal(Vault, person, "agent-executor")), "person's delegated credential stays personal");
            Assert.False(await Allowed(factory.Services, Principal(Vault, systemUser, null)), "no client, no system-user path");
            Assert.False(await Allowed(factory.Services, Principal("openid profile", systemUser, "background-vault")), "other scopes never pass");
        }
        finally
        {
            await ((IAsyncLifetime)factory).DisposeAsync();
        }
    }
}
