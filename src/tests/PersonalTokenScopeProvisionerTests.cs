using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using OpenIddict.Abstractions;
using Sufficit.Identity.STS;
using Sufficit.Identity.Tests.Infrastructure;
using Xunit;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Sufficit.Identity.Tests;

public sealed class PersonalTokenScopeProvisionerTests
{
    [Fact]
    public async Task Provisions_scope_and_only_explicit_client_permission_idempotently()
    {
        await using var factory = new ManagementTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        using var scope = factory.Services.CreateScope();
        var applications = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
        var scopes = scope.ServiceProvider.GetRequiredService<IOpenIddictScopeManager>();
        var allowed = await applications.CreateAsync(new OpenIddictApplicationDescriptor
        {
            ClientId = "personal-token-allowed",
            ClientType = ClientTypes.Public,
            Permissions = { Permissions.Endpoints.Authorization },
        });
        var unrelated = await applications.CreateAsync(new OpenIddictApplicationDescriptor
        {
            ClientId = "personal-token-unrelated",
            ClientType = ClientTypes.Public,
        });
        var options = new SufficitIdentityOptions();
        options.PersonalTokens.ScopeClientIds.Add("personal-token-allowed");
        var provisioner = new PersonalTokenScopeProvisioner(scopes, applications, options,
            NullLogger<PersonalTokenScopeProvisioner>.Instance);

        await provisioner.ProvisionAsync();
        await provisioner.ProvisionAsync();

        Assert.NotNull(await scopes.FindByNameAsync("personal.tokens.manage"));
        Assert.True(await applications.HasPermissionAsync(allowed, Permissions.Prefixes.Scope + "personal.tokens.manage"));
        Assert.True(await applications.HasPermissionAsync(allowed, Permissions.Endpoints.Authorization));
        Assert.False(await applications.HasPermissionAsync(unrelated, Permissions.Prefixes.Scope + "personal.tokens.manage"));
        Assert.False(await applications.HasPermissionAsync(allowed, Permissions.Prefixes.Scope + "identity.management"));
    }
}
