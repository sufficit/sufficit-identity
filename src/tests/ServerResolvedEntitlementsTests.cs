using System.Security.Claims;
using OpenIddict.Abstractions;
using Sufficit.Identity.STS;
using Xunit;

namespace Sufficit.Identity.Tests;

public sealed class ServerResolvedEntitlementsTests
{
    [Theory]
    [InlineData("entitlements", "example.read")]
    [InlineData("directive", "example.operate")]
    public void Current_permissions_never_reach_tokens_even_when_scope_is_granted(string type, string key)
    {
        var identity = new ClaimsIdentity([new Claim(type, key + ":workspace/alpha")]);
        identity.SetScopes("openid", "entitlements", "directives");
        var options = new ClaimScopeMapOptions { ServerResolvedEntitlementKeys = new(StringComparer.Ordinal) { key } };
        var policy = new ApplicationClaimDestinationPolicy(options);
        Assert.Empty(policy.GetDestinations(identity.FindFirst(type)!, true));
    }

    [Fact]
    public void Resolve_preserves_opaque_values_without_business_validation()
    {
        var keys = new HashSet<string>(StringComparer.Ordinal) { "example.read", "example.operate" };
        var grants = ServerResolvedEntitlements.Resolve([
            new("entitlements", "example.read:workspace/alpha"),
            new("directive", "example.read:workspace/alpha"),
            new("entitlements", "example.operate:resource:beta"),
            new("entitlements", "example.read"),
            new("entitlements", "example.read:00000000-0000-0000-0000-000000000000"),
            new("entitlements", "example.read:Case Sensitive Value"),
            new("entitlements", "example.read.child:alpha"),
            new("entitlements", "example.read:invalid\nvalue"),
            new("role", "example.read:alpha")], keys);
        Assert.Equal(5, grants.Length);
        Assert.Contains("example.read:workspace/alpha", grants);
        Assert.Contains("example.operate:resource:beta", grants);
        Assert.Contains("example.read", grants);
        Assert.Contains("example.read:00000000-0000-0000-0000-000000000000", grants);
        Assert.Contains("example.read:Case Sensitive Value", grants);
    }

    [Fact]
    public void Default_configuration_contains_no_business_keys_or_implicit_token_exclusion()
    {
        var options = new ClaimScopeMapOptions();
        Assert.Empty(options.ServerResolvedEntitlementKeys);
        var identity = new ClaimsIdentity([new Claim("entitlements", "example.read:alpha")]);
        identity.SetScopes("directives");
        Assert.NotEmpty(new ApplicationClaimDestinationPolicy(options).GetDestinations(identity.FindFirst("entitlements")!, true));
    }
}
