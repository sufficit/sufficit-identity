using Sufficit.Identity.Application.Security;
using Sufficit.Identity.Management.Provisioning;
using Xunit;

namespace Sufficit.Identity.Tests;

public sealed class RetiredIdentityScopeTests
{
    [Fact]
    public void Retired_skoruba_scope_is_rejected_from_manifests()
    {
        var errors = IdentityProvisioningManifestValidator.Validate(
            new IdentityProvisioningManifest
            {
                Scopes =
                [
                    new IdentityScopeManifest
                    {
                        Name = RetiredIdentityScopes.SkorubaIdentityAdminApi
                    }
                ],
                Clients =
                [
                    new IdentityClientManifest
                    {
                        ClientId = "legacy-client",
                        Scopes = [RetiredIdentityScopes.SkorubaIdentityAdminApi]
                    }
                ]
            });

        Assert.Contains(errors, error =>
            error.Contains("references retired scope", StringComparison.Ordinal));
        Assert.Contains(errors, error =>
            error.Contains("contains retired scope", StringComparison.Ordinal));
    }

    [Fact]
    public void Retired_scope_is_part_of_the_default_reserved_boundary()
    {
        var policy = new ReservedScopePolicy(
            new[] { "identity.management", "scim" }
                .Concat(RetiredIdentityScopes.Names));

        Assert.True(policy.IsReserved(
            RetiredIdentityScopes.SkorubaIdentityAdminApi));
    }
}
