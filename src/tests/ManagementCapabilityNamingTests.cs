using System.Security.Claims;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Options;
using Sufficit.Identity.Management;
using Sufficit.Identity.Management.Authorization;
using Xunit;

namespace Sufficit.Identity.Tests;

/// <summary>
/// The capability naming rule (2026-10-27): <c>identity.&lt;resource&gt;.&lt;action|qualifier&gt;</c>,
/// optionally one more level, every segment one lowercase word. Retired
/// spellings keep working through <see cref="ManagementCapabilities.Normalize"/>.
/// </summary>
public sealed class ManagementCapabilityNamingTests
{
    public static TheoryData<string, string> Renames => new()
    {
        { "identity.users.reset-mfa", "identity.users.mfa.reset" },
        { "identity.system-users.manage", "identity.users.system" },
        { "identity.trusted-proxies.read", "identity.proxies.read" },
        { "identity.trusted-proxies.manage", "identity.proxies.manage" },
        { "identity.vault.secrets.read", "identity.secrets.read" },
        { "identity.vault.secrets.manage", "identity.secrets.manage" },
        { "identity.vault.secrets.resolve", "identity.secrets.resolve" },
        { "identity.management.tokens.read", "identity.tokens.read" },
        { "identity.management.tokens.issue", "identity.tokens.issue" },
        { "identity.management.tokens.revoke", "identity.tokens.revoke" },
        { "identity.operator-tokens.read", "identity.tokens.read" },
        { "identity.operator-tokens.issue", "identity.tokens.issue" },
        { "identity.operator-tokens.revoke", "identity.tokens.revoke" },
        { "identity.users.reset-password", "identity.users.reset" },
        { "identity.users.resend_confirmation", "identity.users.confirmation" },
    };

    [Theory]
    [MemberData(nameof(Renames))]
    public void Every_legacy_name_normalizes_to_its_new_name(string legacy, string canonical)
    {
        Assert.Equal(canonical, ManagementCapabilities.Normalize(legacy));
        Assert.Contains(canonical, ManagementCapabilities.All);
        Assert.DoesNotContain(legacy, ManagementCapabilities.All);
    }

    [Fact]
    public void Every_legacy_name_is_covered_and_lands_in_the_catalog()
    {
        var tested = Renames.Select(row => (string)row[0]).ToHashSet(StringComparer.Ordinal);
        foreach (var (legacy, canonical) in ManagementCapabilities.LegacyNames)
        {
            Assert.Contains(legacy, tested);
            Assert.Contains(canonical, ManagementCapabilities.All);
        }
    }

    [Fact]
    public void Canonical_names_normalize_to_themselves()
    {
        Assert.All(ManagementCapabilities.All, capability =>
            Assert.Equal(capability, ManagementCapabilities.Normalize(capability)));
    }

    [Fact]
    public void Every_capability_follows_the_naming_rule()
    {
        var rule = new Regex(@"^identity(\.[a-z]+){2,3}$");
        Assert.All(ManagementCapabilities.All, capability =>
            Assert.Matches(rule, capability));
        Assert.Contains("identity.claims.system", ManagementCapabilities.All);
        Assert.Contains("identity.users.system", ManagementCapabilities.All);
    }

    [Theory]
    [MemberData(nameof(Renames))]
    public async Task Legacy_names_in_role_mappings_and_claims_grant_the_canonical_capability(
        string legacy,
        string canonical)
    {
        var options = Options.Create(new ManagementOptions
        {
            Authorization = new ManagementAuthorizationOptions
            {
                RoleCapabilities = new(StringComparer.OrdinalIgnoreCase)
                {
                    ["legacy-role"] = [legacy],
                },
            },
        });
        var resolver = new ScopeAndRoleManagementEntitlementResolver(options);

        var fromRole = await resolver.ResolveAsync(Principal(new Claim(ClaimTypes.Role, "legacy-role")));
        var fromClaim = await resolver.ResolveAsync(Principal(new Claim("permission", legacy)));

        Assert.Equal([canonical], fromRole.Capabilities);
        Assert.Equal([canonical], fromClaim.Capabilities);
    }

    private static ClaimsPrincipal Principal(params Claim[] claims) =>
        new(new ClaimsIdentity(
            [new Claim("sub", "operator-1"), .. claims],
            "test",
            ClaimTypes.Name,
            ClaimTypes.Role));
}
