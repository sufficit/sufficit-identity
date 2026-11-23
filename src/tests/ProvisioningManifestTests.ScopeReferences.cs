using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Abstractions;
using Sufficit.Identity.Application.Security;
using Sufficit.Identity.Management.Provisioning;
using Xunit;

namespace Sufficit.Identity.Tests;

public sealed partial class ProvisioningManifestTests
{
    [Fact]
    public async Task Adopt_client_with_referenced_scope_preserves_the_scope()
    {
        var suffix = Guid.NewGuid().ToString("N");
        var scopeName = $"shared.scope.{suffix}";
        var clientId = $"referencing-client-{suffix}";
        using var serviceScope = _factory.Services.CreateScope();
        var applications = serviceScope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
        var scopes = serviceScope.ServiceProvider.GetRequiredService<IOpenIddictScopeManager>();
        var provisioner = new OpenIddictManifestProvisioner(applications, scopes, new TrackingSecretResolver());

        await provisioner.ApplyAsync(new IdentityProvisioningManifest
        {
            ManifestId = "scope-owner",
            Scopes = [new IdentityScopeManifest { Name = scopeName, Resources = ["example-api"] }],
        });
        var fixture = PublicClientManifest(scopeName, clientId, "Adopted client", "Shared");
        var client = fixture.Clients[0];
        var unmanaged = new OpenIddictApplicationDescriptor
        {
            ClientId = clientId,
            DisplayName = client.DisplayName,
            ClientType = client.ClientType,
            ConsentType = client.ConsentType,
        };
        unmanaged.RedirectUris.UnionWith(client.RedirectUris);
        unmanaged.PostLogoutRedirectUris.UnionWith(client.PostLogoutRedirectUris);
        unmanaged.Permissions.UnionWith([
            "gt:authorization_code", "gt:refresh_token", "rst:code",
            "ept:authorization", "ept:token", "ept:end_session",
            "scp:openid", "scp:offline_access", $"scp:{scopeName}",
        ]);
        unmanaged.Requirements.Add("ft:pkce");
        await applications.CreateAsync(unmanaged);

        var manifest = new IdentityProvisioningManifest
        {
            ManifestId = "client-owner",
            ReferencedScopes = [scopeName],
            RolloutMode = ClientDefinitionRolloutMode.Enforce,
            Clients =
            [
                new IdentityClientManifest
                {
                    ClientId = clientId,
                    DisplayName = client.DisplayName,
                    AdoptExisting = true,
                    RequirePkce = true,
                    GrantTypes = client.GrantTypes,
                    ResponseTypes = client.ResponseTypes,
                    RedirectUris = client.RedirectUris,
                    PostLogoutRedirectUris = client.PostLogoutRedirectUris,
                    Scopes = client.Scopes,
                },
            ],
        };

        var inventory = await provisioner.InventoryAsync(manifest);
        Assert.Contains(inventory.Entries, entry =>
            entry.ClientId == clientId && entry.Status == IdentityManifestInventoryStatus.DeclaredUnmanaged);
        var expected = new IdentityManifestChange("client", clientId, IdentityManifestChangeKind.Adopted);
        Assert.Equal(expected, Assert.Single((await provisioner.PreviewAsync(manifest)).Changes));
        Assert.Equal(expected, Assert.Single((await provisioner.ApplyAsync(manifest)).Changes));

        var scope = await scopes.FindByNameAsync(scopeName);
        Assert.NotNull(scope);
        var properties = await scopes.GetPropertiesAsync(scope);
        Assert.Equal("scope-owner", properties["identity:provisioning-manifest:identity"].GetString());
        Assert.Equal("example-api", Assert.Single(await scopes.GetResourcesAsync(scope)));
        Assert.Contains((await provisioner.InventoryAsync(manifest)).Entries, entry =>
            entry.ClientId == clientId && entry.Status == IdentityManifestInventoryStatus.DeclaredCurrent);
    }

    [Fact]
    public async Task Missing_scope_reference_blocks_every_operation_before_writes()
    {
        var suffix = Guid.NewGuid().ToString("N");
        var missing = $"missing.scope.{suffix}";
        var owned = $"owned.scope.{suffix}";
        using var serviceScope = _factory.Services.CreateScope();
        var applications = serviceScope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
        var scopes = serviceScope.ServiceProvider.GetRequiredService<IOpenIddictScopeManager>();
        var provisioner = new OpenIddictManifestProvisioner(applications, scopes, new TrackingSecretResolver());
        var manifest = new IdentityProvisioningManifest
        {
            ManifestId = "scope-reference-test",
            ReferencedScopes = [missing],
            Scopes = [new IdentityScopeManifest { Name = owned }],
        };

        foreach (var execute in new Func<Task>[]
        {
            () => provisioner.InventoryAsync(manifest),
            () => provisioner.PreviewAsync(manifest),
            () => provisioner.ApplyAsync(manifest),
        })
        {
            var error = await Assert.ThrowsAsync<IdentityProvisioningManifestException>(execute);
            Assert.Contains(error.Errors, message => message.Contains(missing, StringComparison.Ordinal));
        }

        Assert.Null(await scopes.FindByNameAsync(owned));
    }

    [Fact]
    public void Manifest_rejects_a_scope_listed_as_both_owned_and_referenced()
    {
        var manifest = new IdentityProvisioningManifest
        {
            ManifestId = "scope-reference-test",
            Scopes = [new IdentityScopeManifest { Name = "shared.scope" }],
            ReferencedScopes = ["shared.scope"],
        };

        Assert.Contains(IdentityProvisioningManifestValidator.Validate(manifest),
            error => error.Contains("overlaps", StringComparison.Ordinal));
    }
}
