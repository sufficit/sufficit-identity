namespace Sufficit.Identity.STS;

/// <summary>
/// Identity Assertion JWT Authorization Grant (ID-JAG,
/// draft-ietf-oauth-identity-assertion-authz-grant) in both roles: issuing
/// grants to other authorization servers, and redeeming grants issued by a
/// trusted identity provider. Both roles are disabled by default.
/// </summary>
public sealed class IdentityAssertionOptions
{
    /// <summary>IdP role: token exchange with requested_token_type id-jag.</summary>
    public IdentityAssertionIssuanceOptions Issuance { get; init; } = new();

    /// <summary>Resource authorization server role: the jwt-bearer grant.</summary>
    public IdentityAssertionRedemptionOptions Redemption { get; init; } = new();
}

public sealed class IdentityAssertionIssuanceOptions
{
    public bool Enabled { get; init; }

    /// <summary>Grant lifetime in seconds. Clamped to 60..3600.</summary>
    public int LifetimeSeconds { get; init; } = 300;

    /// <summary>
    /// Includes the user's confirmed email, which the draft recommends for
    /// subject resolution at the resource authorization server.
    /// </summary>
    public bool IncludeEmail { get; init; } = true;

    /// <summary>
    /// Authorization servers in other trust domains that may receive a grant.
    /// A request naming any other audience is rejected.
    /// </summary>
    public List<IdentityAssertionAudience> Audiences { get; init; } = [];
}

public sealed class IdentityAssertionAudience
{
    /// <summary>Issuer identifier of the resource authorization server; the <c>aud</c> claim.</summary>
    public string Issuer { get; init; } = string.Empty;

    /// <summary>Additional audience values that resolve to <see cref="Issuer"/>.</summary>
    public string[] Aliases { get; init; } = [];

    /// <summary>Local clients allowed to request a grant for this audience. Empty allows any client holding the token-exchange permission.</summary>
    public string[] AllowedClientIds { get; init; } = [];

    /// <summary>
    /// Maps a local client_id to the client_id it is registered under at the
    /// resource authorization server. Unmapped clients keep their own id.
    /// </summary>
    public Dictionary<string, string> ClientIdMap { get; init; } = new(StringComparer.Ordinal);

    /// <summary>Scopes that may be granted. Empty passes the requested scopes through.</summary>
    public string[] AllowedScopes { get; init; } = [];

    /// <summary>Resources that may be granted. Empty passes the requested resources through.</summary>
    public string[] AllowedResources { get; init; } = [];
}

public sealed class IdentityAssertionRedemptionOptions
{
    public bool Enabled { get; init; }

    /// <summary>Longest accepted grant lifetime (exp - iat) in seconds.</summary>
    public int MaxAssertionLifetimeSeconds { get; init; } = 600;

    /// <summary>Identity providers whose grants are accepted.</summary>
    public List<IdentityAssertionTrustedIssuer> TrustedIssuers { get; init; } = [];
}

public sealed class IdentityAssertionTrustedIssuer
{
    /// <summary>Issuer identifier; must match the grant's <c>iss</c> exactly.</summary>
    public string Issuer { get; init; } = string.Empty;

    /// <summary>
    /// JWKS location. When absent, <c>jwks_uri</c> is read from the issuer's
    /// OpenID Connect discovery document.
    /// </summary>
    public string? JwksUri { get; init; }

    /// <summary>
    /// External login provider name whose provider key equals the grant's
    /// <c>sub</c>. Subjects resolve only through an existing external login;
    /// email is never used, so an issuer cannot claim an arbitrary local account.
    /// </summary>
    public string LoginProvider { get; init; } = string.Empty;

    /// <summary>Local clients allowed to redeem grants from this issuer. Empty allows any confidential client holding the jwt-bearer grant permission.</summary>
    public string[] AllowedClientIds { get; init; } = [];

    /// <summary>Scopes this issuer may grant. Empty accepts the grant's scopes, still limited by the client's scope permissions.</summary>
    public string[] AllowedScopes { get; init; } = [];
}
