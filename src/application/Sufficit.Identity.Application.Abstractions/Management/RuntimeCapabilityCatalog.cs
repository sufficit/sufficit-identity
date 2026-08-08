namespace Sufficit.Identity.Management;

/// <summary>
/// Names used by the management configurator when it describes capabilities
/// exposed by the running authorization server. These are protocol facts, not
/// business roles, and are intentionally kept in the shared contract assembly.
/// </summary>
public static class ManagementRuntimeCapabilities
{
    public const string AuthorizationCode = "authorization_code";
    public const string ClientCredentials = "client_credentials";
    public const string DeviceCode = "urn:ietf:params:oauth:grant-type:device_code";
    public const string RefreshToken = "refresh_token";
    public const string TokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange";
    public const string Password = "password";
    public const string None = "none";

    public const string Par = "par";
    public const string Jar = "jar";
    public const string Jarm = "jarm";
    public const string Dpop = "dpop";
    public const string Mtls = "mtls";
    public const string Fapi2 = "fapi2";
    public const string Ciba = "ciba";
    public const string DeviceAuthorization = "device_authorization";
    public const string DynamicClientRegistration = "dynamic_client_registration";
    public const string Mcp = "mcp";
}

/// <summary>
/// Immutable projection of the protocol features enabled by the current
/// hosting process. The management UI consumes this instead of maintaining a
/// second list of guessed grants and optional features.
/// </summary>
public sealed record IdentityRuntimeCapabilitySnapshot(
    IReadOnlySet<string> GrantTypes,
    IReadOnlySet<string> Features,
    bool RequirePkce,
    bool RequirePar,
    IReadOnlyList<string> RegisteredResources)
{
    public bool SupportsGrant(string grantType) =>
        GrantTypes.Contains(grantType);

    public bool SupportsFeature(string feature) =>
        Features.Contains(feature);
}

public interface IIdentityRuntimeCapabilityCatalog
{
    IdentityRuntimeCapabilitySnapshot Current { get; }
}

/// <summary>
/// Safe fallback for hosts that expose the management module without the STS
/// module. It advertises no optional protocol capability, so the UI fails
/// closed instead of offering a flow the host cannot process.
/// </summary>
public sealed class DisabledIdentityRuntimeCapabilityCatalog
    : IIdentityRuntimeCapabilityCatalog
{
    public IdentityRuntimeCapabilitySnapshot Current { get; } =
        new(
            new HashSet<string>(StringComparer.Ordinal),
            new HashSet<string>(StringComparer.Ordinal),
            RequirePkce: false,
            RequirePar: false,
            []);
}
