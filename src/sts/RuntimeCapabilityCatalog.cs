using OpenIddict.Abstractions;
using Sufficit.Identity.Management;

namespace Sufficit.Identity.STS;

/// <summary>
/// Projects the protocol switches of the running STS into the management
/// contract. Keeping this adapter in STS prevents the generic management
/// module from importing host-specific configuration types.
/// </summary>
internal sealed class SufficitIdentityRuntimeCapabilityCatalog
    : IIdentityRuntimeCapabilityCatalog
{
    public SufficitIdentityRuntimeCapabilityCatalog(
        SufficitIdentityOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        var grants = new HashSet<string>(StringComparer.Ordinal)
        {
            OpenIddictConstants.GrantTypes.AuthorizationCode,
            OpenIddictConstants.GrantTypes.ClientCredentials,
            OpenIddictConstants.GrantTypes.DeviceCode,
            OpenIddictConstants.GrantTypes.RefreshToken,
            OpenIddictConstants.GrantTypes.TokenExchange,
        };

        if (options.LegacyGrants.Password)
        {
            grants.Add(OpenIddictConstants.GrantTypes.Password);
        }

        if (options.LegacyGrants.None)
        {
            grants.Add("none");
        }

        var features = new HashSet<string>(StringComparer.Ordinal)
        {
            ManagementRuntimeCapabilities.DeviceAuthorization,
            ManagementRuntimeCapabilities.Par,
        };

        features.UnionWith(Features.ProtocolFeatureCatalog.RuntimeCapabilities(options));

        if (options.Mcp.ProtectedResourceMetadataEnabled)
        {
            features.Add(ManagementRuntimeCapabilities.Mcp);
        }

        Current = new(
            grants,
            features,
            options.Pkce.RequireForAllClients,
            options.Par.RequireForAllClients,
            options.Mcp.Resources
                .Where(resource => !string.IsNullOrWhiteSpace(resource))
                .Select(resource => resource.Trim())
                .Distinct(StringComparer.Ordinal)
                .ToArray());
    }

    public IdentityRuntimeCapabilitySnapshot Current { get; }
}
