using System.Text.Json;
using Sufficit.Identity.Application.Security;
using Sufficit.Identity.Management.Provisioning;
using Xunit;

namespace Sufficit.Identity.Tests;

/// <summary>
/// A scope entitlement writes a claim onto every user who approves the scope,
/// so it must never be able to mint authorization.
/// </summary>
/// <remarks>
/// Moving entitlements from configuration to the database (eval 2026-08-30,
/// F-2) widened who can declare one: what used to require host filesystem
/// access became a data-plane write behind the provisioning API. Without a
/// claim-type rule, a manifest could declare the ASP.NET Core Identity role
/// claim on any consented scope and hand an administrator role to every user
/// who approves it — the token pipeline blocks OpenIddict's <c>role</c>, but
/// the <c>ClaimTypes.Role</c> URI is what the cookie principal treats as a
/// role.
/// </remarks>
public sealed class ScopeEntitlementSecurityTests
{
    public static TheoryData<string> ForbiddenTypes() =>
    [
        "role",
        "roles",
        "http://schemas.microsoft.com/ws/2008/06/identity/claims/role",
        "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/role",
        "scope",
        "amr",
        "password_hash",
        // Case must not be an escape hatch.
        "ROLE",
        "Http://Schemas.Microsoft.Com/ws/2008/06/identity/claims/Role",
    ];

    [Theory]
    [MemberData(nameof(ForbiddenTypes))]
    public void Forbidden_claim_types_are_never_grantable(string type)
    {
        Assert.False(ScopeEntitlements.IsGrantableClaimType(type));
    }

    [Fact]
    public void Ordinary_product_claim_types_stay_grantable()
    {
        Assert.True(ScopeEntitlements.IsGrantableClaimType("directive"));
        Assert.True(ScopeEntitlements.IsGrantableClaimType("tenant_id"));
    }

    [Fact]
    public void Forbidden_type_is_refused_on_write()
    {
        var written = ScopeEntitlements.Write(
        [
            new ScopeEntitlementClaim(
                "http://schemas.microsoft.com/ws/2008/06/identity/claims/role",
                "Administrator"),
            new ScopeEntitlementClaim("directive", "aiuser:1"),
        ]);

        Assert.NotNull(written);
        var kept = ScopeEntitlements.Read(
            new Dictionary<string, JsonElement>
            {
                [ScopeEntitlements.PropertyName] = written!.Value,
            });
        var only = Assert.Single(kept);
        Assert.Equal("directive", only.Type);
    }

    [Fact]
    public void Forbidden_type_already_in_the_database_is_refused_on_read()
    {
        // Defense in depth: a row written before this rule existed, or through
        // a direct database edit, must still never become a user claim.
        var properties = new Dictionary<string, JsonElement>
        {
            [ScopeEntitlements.PropertyName] = JsonSerializer.SerializeToElement(
                new[]
                {
                    new Dictionary<string, string>
                    {
                        ["type"] = "http://schemas.microsoft.com/ws/2008/06/identity/claims/role",
                        ["value"] = "Administrator",
                    },
                }),
        };

        Assert.Empty(ScopeEntitlements.Read(properties));
    }

    [Fact]
    public void Manifest_declaring_a_role_entitlement_is_rejected_with_a_reason()
    {
        var manifest = new IdentityProvisioningManifest
        {
            Scopes =
            [
                new IdentityScopeManifest
                {
                    Name = "privilege_escalation",
                    EntitlementClaims =
                    [
                        new IdentityScopeEntitlementManifest
                        {
                            Type = "http://schemas.microsoft.com/ws/2008/06/identity/claims/role",
                            Value = "Administrator",
                        },
                    ],
                },
            ],
        };

        var errors = IdentityProvisioningManifestValidator.Validate(manifest);

        // The operator must be told, not silently ignored.
        Assert.Contains(
            errors,
            error => error.Contains(
                "cannot be granted as a scope entitlement",
                StringComparison.Ordinal));
    }
}
