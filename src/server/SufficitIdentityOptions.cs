namespace Sufficit.Identity.Server;

/// <summary>
/// Root configuration for the Sufficit Identity STS.
/// Bound from the <c>Sufficit:Identity</c> configuration section.
/// </summary>
public sealed class SufficitIdentityOptions
{
    /// <summary>
    /// Issuer URI advertised in discovery documents and JWT tokens.
    /// Default: the host the request arrived on. Set explicitly in production.
    /// </summary>
    public string? Issuer { get; init; }

    /// <summary>
    /// Database connection string key (under ConnectionStrings) used by the
    /// unified <see cref="Sufficit.Identity.Core.Data.AppDbContext"/>.
    /// </summary>
    public string ConnectionStringName { get; init; } = "DefaultConnection";

    /// <summary>
    /// Optional management API configuration. When <see cref="ManagementOptions.Enabled"/>
    /// is true, the host should also call <c>AddSufficitIdentityManagement</c>.
    /// </summary>
    public ManagementOptions Management { get; init; } = new();

    /// <summary>
    /// Production X.509 certificate configuration for OpenIddict token
    /// signing/encryption. See <see cref="CertificatesOptions"/>.
    /// </summary>
    public CertificatesOptions Certificates { get; init; } = new();

    /// <summary>
    /// Feature flags for legacy OAuth 2.0 grant types slated for removal
    /// under OAuth 2.1. See <see cref="LegacyGrantsOptions"/>.
    /// </summary>
    public LegacyGrantsOptions LegacyGrants { get; init; } = new();

    /// <summary>
    /// Rate limiting applied by the host to the token endpoint.
    /// See <see cref="RateLimitOptions"/>.
    /// </summary>
    public RateLimitOptions RateLimit { get; init; } = new();

    /// <summary>
    /// Token lifetimes. See <see cref="TokenLifetimeOptions"/>.
    /// </summary>
    public TokenLifetimeOptions Tokens { get; init; } = new();

    /// <summary>
    /// Account lockout policy applied to password verification.
    /// See <see cref="LockoutOptions"/>.
    /// </summary>
    public LockoutOptions Lockout { get; init; } = new();

    /// <summary>
    /// HSTS policy applied by the host outside Development.
    /// See <see cref="HstsOptions"/>.
    /// </summary>
    public HstsOptions Hsts { get; init; } = new();
}

/// <summary>
/// Rate limiting applied by the STS host to <c>POST /connect/token</c>
/// (fixed window per client IP, no queueing). Complements — never replaces —
/// the account lockout policy: rate limiting throttles a single source,
/// lockout protects a single account from distributed attempts.
/// </summary>
public sealed class RateLimitOptions
{
    /// <summary>
    /// Master switch. Disable only when an upstream gateway already
    /// throttles the token endpoint.
    /// </summary>
    public bool Enabled { get; init; } = true;

    /// <summary>
    /// Requests allowed per window, per client IP.
    /// </summary>
    public int PermitLimit { get; init; } = 30;

    /// <summary>
    /// Fixed window length, in seconds. Also returned as <c>Retry-After</c>
    /// on 429 responses.
    /// </summary>
    public int WindowSeconds { get; init; } = 60;
}

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
    /// </summary>
    public double RefreshTokenLifetimeDays { get; init; } = 14;

    /// <summary>
    /// Access token format switch (P0 #5 / eval #B2). <c>true</c> (default —
    /// the CURRENT, pre-existing behavior, preserved so this flag is a no-op
    /// until someone deliberately changes it) makes
    /// <c>server.UseReferenceAccessTokens()</c> apply: access tokens are
    /// opaque reference tokens, validated only via
    /// <c>/connect/introspect</c>. <c>false</c> switches to self-contained
    /// JWT access tokens, validated locally by any resource server holding
    /// the signing public key (no introspection round-trip).
    ///
    /// This setting is GLOBAL — OpenIddict does not support a per-client
    /// token format natively — while the legacy client inventory
    /// (docs/migration/PLAN.md in git HEAD) records that only ONE of the 26
    /// legacy clients (<c>sufficit-endpoints</c>) actually relied on
    /// reference tokens; the rest expect a JWT they can validate locally.
    /// Flipping this to <c>false</c> is therefore a real migration-contract
    /// decision, not a drop-in security hardening: JWTs are self-contained
    /// (faster, no introspection dependency/availability coupling, but
    /// un-revocable before expiry and visible to anyone holding the token)
    /// vs. reference+introspection (instantly revocable, opaque to the
    /// client, but every validation is a network round-trip to this STS and
    /// every RS must be coded against /connect/introspect). Do NOT flip
    /// this without coordinating with every resource server (RS) team first
    /// — this file only surfaces the decision as explicit and reversible
    /// config; it does not make the call for you.
    /// </summary>
    public bool UseReferenceAccessTokens { get; init; } = true;
}

/// <summary>
/// Account lockout policy enforced by ASP.NET Core Identity during password
/// verification (interactive login and the password grant alike).
/// </summary>
public sealed class LockoutOptions
{
    /// <summary>
    /// Consecutive failed attempts before the account is locked.
    /// </summary>
    public int MaxFailedAttempts { get; init; } = 5;

    /// <summary>
    /// How long the account stays locked, in minutes.
    /// </summary>
    public double DurationMinutes { get; init; } = 5;
}

/// <summary>
/// HSTS policy applied by the host outside Development.
/// </summary>
public sealed class HstsOptions
{
    /// <summary>
    /// <c>max-age</c> advertised to browsers, in days.
    /// </summary>
    public int MaxAgeDays { get; init; } = 365;

    /// <summary>
    /// Extends the policy to all subdomains.
    /// </summary>
    public bool IncludeSubDomains { get; init; } = true;

    /// <summary>
    /// Opts into browser preload lists. Only meaningful together with
    /// <see cref="IncludeSubDomains"/> and a max-age of at least one year.
    /// </summary>
    public bool Preload { get; init; } = true;
}

/// <summary>
/// Production X.509 certificate configuration used by OpenIddict to sign and
/// encrypt tokens. When left unset, the server falls back to ephemeral
/// development certificates, but ONLY while <c>ASPNETCORE_ENVIRONMENT</c> is
/// <c>Development</c>; outside that environment, startup fails fast instead
/// of silently issuing tokens signed with a throwaway key.
/// </summary>
public sealed class CertificatesOptions
{
    /// <summary>
    /// Filesystem path to the PFX file used to sign tokens (JWT signing key).
    /// Required in production.
    /// </summary>
    public string? SigningPath { get; init; }

    /// <summary>
    /// Password protecting the signing PFX file referenced by <see cref="SigningPath"/>.
    /// </summary>
    public string? SigningPassword { get; init; }

    /// <summary>
    /// Filesystem path to the PFX file used to encrypt tokens (JWE encryption key).
    /// Required in production.
    /// </summary>
    public string? EncryptionPath { get; init; }

    /// <summary>
    /// Password protecting the encryption PFX file referenced by <see cref="EncryptionPath"/>.
    /// </summary>
    public string? EncryptionPassword { get; init; }
}

/// <summary>
/// Feature flags for legacy OAuth 2.0 grant types that OAuth 2.1 removes
/// (Resource Owner Password Credentials and the "none" grant/response type).
/// Both default to <c>true</c> to preserve compatibility with clients that
/// have not yet migrated to authorization_code + PKCE; they exist so the
/// future cutover ("Onda E") can disable each grant per-environment without
/// a code change.
/// </summary>
public sealed class LegacyGrantsOptions
{
    /// <summary>
    /// Enables the Resource Owner Password Credentials grant
    /// (<c>grant_type=password</c>). Removed by OAuth 2.1.
    /// </summary>
    public bool Password { get; init; } = true;

    /// <summary>
    /// Enables the "none" grant/response type. Removed by OAuth 2.1.
    /// </summary>
    public bool None { get; init; } = true;
}

/// <summary>
/// Management API configuration (opt-in).
/// </summary>
public sealed class ManagementOptions
{
    public bool Enabled { get; init; } = false;

    /// <summary>
    /// Route prefix for the management REST endpoints.
    /// </summary>
    public string RoutePrefix { get; init; } = "api";

    /// <summary>
    /// If true, the management endpoints require an access token carrying the
    /// <c>sufficit_identity_admin_api</c> scope (or another configured scope).
    /// </summary>
    public bool RequireAuthorization { get; init; } = true;

    /// <summary>
    /// Required authorization policy/scope. Defaults to the legacy
    /// <c>skoruba_identity_admin_api</c> scope name to remain compatible with
    /// existing admin clients during migration.
    /// </summary>
    public string RequiredScope { get; init; } = "skoruba_identity_admin_api";
}
