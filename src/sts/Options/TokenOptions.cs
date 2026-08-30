using Sufficit.Identity.Application.Security;

namespace Sufficit.Identity.STS;

/// <summary>
/// Token lifetimes. Null values fall back to the OpenIddict defaults
/// (access: 1 hour, identity: 20 minutes).
/// </summary>
public sealed class TokenLifetimeOptions
{
    /// <summary>
    /// Access token lifetime, in minutes. Null = OpenIddict default (60).
    /// </summary>
    public int? AccessTokenLifetimeMinutes { get; init; }

    /// <summary>
    /// Identity (id_token) lifetime, in minutes. Null = OpenIddict default (20).
    /// </summary>
    public int? IdentityTokenLifetimeMinutes { get; init; }

    /// <summary>
    /// Refresh token lifetime, in days. Rotation itself is always on
    /// (single-use refresh tokens); this only bounds how long an unused
    /// refresh token stays redeemable.
    /// FAPI 2.0 NOTE: the 14-day default targets general-purpose deployments.
    /// For FAPI 2.0 / financial-grade profiles, deploy a materially shorter
    /// lifetime (e.g. 1 day or less) in configuration — ecosystem guidance
    /// favors short-lived, rotated refresh tokens for high-assurance clients.
    /// </summary>
    public double RefreshTokenLifetimeDays { get; init; } = 14;

    /// <summary>
    /// Client-specific values consumed only by the explicit
    /// <c>--reconcile-client-token-lifetimes</c> maintenance command. Normal
    /// server startup never reapplies this map, so the management database
    /// remains the source of truth after reconciliation.
    /// </summary>
    public Dictionary<string, ClientTokenLifetimeOverrideOptions> ClientOverrides
    { get; init; } = new(StringComparer.Ordinal);

    /// <summary>
    /// Compatibility fallback when no per-resource or per-client rule exists.
    /// <c>true</c> preserves the historical opaque reference-token behavior;
    /// <c>false</c> uses self-contained JWT access tokens. New migrations
    /// should use the maps below instead of flipping every client at once.
    /// </summary>
    public bool UseReferenceAccessTokens { get; init; } = true;

    /// <summary>
    /// Exact OAuth client_id to access-token format. Resource rules take
    /// precedence when a token has a mapped audience.
    /// </summary>
    public Dictionary<string, AccessTokenStorageMode> AccessTokenFormatsByClient
    { get; init; } = new(StringComparer.Ordinal);

    /// <summary>
    /// Exact resource/audience to format. All mapped resources in one token
    /// must agree; conflicting formats fail issuance closed.
    /// </summary>
    public Dictionary<string, AccessTokenStorageMode> AccessTokenFormatsByResource
    { get; init; } = new(StringComparer.Ordinal);
}
/// <summary>Optional token lifetime values for one registered client.</summary>
public sealed class ClientTokenLifetimeOverrideOptions
{
    public int? AccessTokenLifetimeMinutes { get; init; }
    public int? IdentityTokenLifetimeMinutes { get; init; }
    public int? RefreshTokenLifetimeDays { get; init; }
}
public enum AccessTokenStorageMode
{
    Reference,
    Jwt,
}
