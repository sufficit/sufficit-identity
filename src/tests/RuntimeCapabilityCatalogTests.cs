using OpenIddict.Abstractions;
using Sufficit.Identity.Management;
using Sufficit.Identity.STS;
using Xunit;

namespace Sufficit.Identity.Tests;

public sealed class RuntimeCapabilityCatalogTests
{
    [Fact]
    public void Catalog_projects_enabled_protocol_features_without_business_roles()
    {
        var options = new SufficitIdentityOptions
        {
            Dpop = new() { Enabled = true },
            Jar = new() { Enabled = true },
            Mtls = new() { Enabled = true },
            Fapi2 = new() { Enabled = true, ClientIds = ["fapi-client"] },
            Mcp = new()
            {
                Resources = ["https://mcp.example.test"],
                ProtectedResourceMetadataEnabled = true,
            },
        };

        var catalog = new SufficitIdentityRuntimeCapabilityCatalog(options);

        Assert.True(catalog.Current.SupportsGrant(
            OpenIddictConstants.GrantTypes.AuthorizationCode));
        Assert.True(catalog.Current.SupportsGrant(
            OpenIddictConstants.GrantTypes.DeviceCode));
        Assert.True(catalog.Current.SupportsFeature(
            ManagementRuntimeCapabilities.DeviceAuthorization));
        Assert.True(catalog.Current.SupportsFeature(
            ManagementRuntimeCapabilities.Dpop));
        Assert.True(catalog.Current.SupportsFeature(
            ManagementRuntimeCapabilities.Jar));
        Assert.True(catalog.Current.SupportsFeature(
            ManagementRuntimeCapabilities.Mtls));
        Assert.True(catalog.Current.SupportsFeature(
            ManagementRuntimeCapabilities.Fapi2));
        Assert.True(catalog.Current.SupportsFeature(
            ManagementRuntimeCapabilities.Mcp));
        Assert.Equal(["https://mcp.example.test"],
            catalog.Current.RegisteredResources);
    }

    [Fact]
    public void Catalog_does_not_advertise_disabled_legacy_or_dynamic_features()
    {
        var catalog = new SufficitIdentityRuntimeCapabilityCatalog(
            new SufficitIdentityOptions());

        Assert.False(catalog.Current.SupportsGrant(
            OpenIddictConstants.GrantTypes.Password));
        Assert.False(catalog.Current.SupportsGrant("none"));
        Assert.False(catalog.Current.SupportsFeature(
            ManagementRuntimeCapabilities.DynamicClientRegistration));
        Assert.False(catalog.Current.SupportsFeature(
            ManagementRuntimeCapabilities.Dpop));
        Assert.False(catalog.Current.SupportsFeature(
            ManagementRuntimeCapabilities.Ciba));
    }
}
