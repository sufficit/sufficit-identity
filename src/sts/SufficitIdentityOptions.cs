using Sufficit.Identity.Application.Security;

namespace Sufficit.Identity.STS;

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
    /// Canonical externally reachable base URL used in account emails and
    /// resource metadata. When absent, <see cref="Issuer"/> is used.
    /// </summary>
    public string? PublicUrl { get; init; }

    /// <summary>
    /// Controls whether request-derived public URLs are observed or rejected.
    /// Enforce is the secure default; Audit is migration-only and reported by
    /// the production posture check when no canonical origin is configured.
    /// </summary>
    public PublicOriginPolicyOptions PublicOrigin { get; init; } = new();

    /// <summary>
    /// Database connection string key (under ConnectionStrings) used by the
    /// unified <see cref="Sufficit.Identity.Core.Data.AppDbContext"/>.
    /// </summary>
    public string ConnectionStringName { get; init; } = "DefaultConnection";

    /// <summary>
    /// Database provisioning/migration policy. See <see cref="DatabaseOptions"/>.
    /// </summary>
    public DatabaseOptions Database { get; init; } = new();

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
    /// Compatibility flags for OAuth 2.0 grant types outside the current OAuth
    /// 2.1 draft baseline. See <see cref="LegacyGrantsOptions"/>.
    /// </summary>
    public LegacyGrantsOptions LegacyGrants { get; init; } = new();

    /// <summary>
    /// Proof Key for Code Exchange policy. See <see cref="PkceOptions"/>.
    /// </summary>
    public PkceOptions Pkce { get; init; } = new();

    /// <summary>
    /// Pushed Authorization Request (RFC 9126) policy. See
    /// <see cref="ParOptions"/>.
    /// </summary>
    public ParOptions Par { get; init; } = new();

    /// <summary>
    /// Rate limiting applied by the host to the token endpoint.
    /// See <see cref="RateLimitOptions"/>.
    /// </summary>
    public RateLimitOptions RateLimit { get; init; } = new();

    public UserSessionStoreOptions UserSessions { get; init; } = new();

    /// <summary>
    /// Distributed-cache policy for multi-replica deployments. See
    /// <see cref="DistributedCacheOptions"/>.
    /// </summary>
    public DistributedCacheOptions DistributedCache { get; init; } = new();

    /// <summary>
    /// Deployment shape used to derive the minimum proxy, cache and issuer
    /// contract.  The default preserves the single-process compatibility
    /// posture; clustered deployments must opt in explicitly.
    /// </summary>
    public DeploymentTopology DeploymentTopology { get; init; } =
        DeploymentTopology.SingleReplica;

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

    /// <summary>
    /// Cross-origin policy for browser clients hosted separately from the STS.
    /// Origins must be explicitly configured; the generic Identity service
    /// never permits wildcard origins for authenticated API calls.
    /// </summary>
    public CorsOptions Cors { get; init; } = new();

    /// <summary>
    /// Network boundary for HTTP calls initiated by the STS. Private or
    /// clear-text destinations remain supported through explicit host
    /// allowlists so internal integrations can be rolled forward safely.
    /// </summary>
    public OutboundHttpSecurityOptions OutboundHttp { get; init; } = new();

    /// <summary>
    /// Content Security Policy applied by the host to HTML responses (login,
    /// consent, device and logout pages served by the embedded public UI). See
    /// <see cref="CspOptions"/>.
    /// </summary>
    public CspOptions Csp { get; init; } = new();

    /// <summary>
    /// Provider-neutral CAPTCHA/human-verification policy for public account
    /// flows that create users or send email.
    /// </summary>
    public HumanVerificationOptions HumanVerification { get; init; } = new();

    /// <summary>
    /// Password complexity policy applied on user creation and password
    /// change/reset. See <see cref="PasswordPolicyOptions"/>.
    /// </summary>
    public PasswordPolicyOptions Password { get; init; } = new();

    /// <summary>
    /// Sign-in policy (e.g. whether a confirmed email is required to sign in).
    /// See <see cref="SignInPolicyOptions"/>.
    /// </summary>
    public SignInPolicyOptions SignIn { get; init; } = new();

    /// <summary>
    /// Authenticator-app two-factor settings. See <see cref="TwoFactorOptions"/>.
    /// </summary>
    public TwoFactorOptions TwoFactor { get; init; } = new();

    /// <summary>
    /// Consolidated production security-posture policy (the fail-closed
    /// go-live check). See <see cref="SecurityPostureOptions"/>.
    /// </summary>
    public SecurityPostureOptions Security { get; init; } = new();

    /// <summary>
    /// WebAuthn/passkey resource limits and relying-party configuration.
    /// See <see cref="AccountPasskeyOptions"/>.
    /// </summary>
    public AccountPasskeyOptions Passkeys { get; init; } = new();

    /// <summary>
    /// Step-up and revocation policy applied around credential mutations.
    /// Audit mode is the rolling-upgrade default and does not reject an
    /// existing production session while operators measure its age.
    /// </summary>
    public CredentialMutationSecurityOptions CredentialMutations { get; init; } = new();

    /// <summary>
    /// Optional claim-type → required-scope map that gates which custom
    /// persisted claims reach the access and identity tokens. The map is
    /// application configuration; the STS does not assign domain meaning to
    /// either side. See <see cref="ClaimScopeMapOptions"/>.
    /// </summary>
    public ClaimScopeMapOptions ClaimScopeMap { get; init; } = new();

    /// <summary>
    /// Compatibility rollout policy for personal access-token issuance.
    /// Observe mode computes and records the strict decision while preserving
    /// existing callers; Enforce applies the attenuated decision.
    /// </summary>
    public PersonalTokenIssuanceOptions PersonalTokens { get; init; } = new();

    /// <summary>
    /// Mutual TLS (mTLS) client authentication and sender-constrained tokens
    /// (RFC 8705). See <see cref="MtlsOptions"/>.
    /// </summary>
    public MtlsOptions Mtls { get; init; } = new();

    /// <summary>
    /// OIDC Back-Channel Logout 1.0 — federated logout distribution to RPs.
    /// See <see cref="BackchannelLogoutOptions"/>.
    /// </summary>
    public BackchannelLogoutOptions BackchannelLogout { get; init; } = new();

    /// <summary>
    /// OIDC Front-Channel Logout 1.0 — browser-mediated RP logout.
    /// See <see cref="FrontchannelLogoutOptions"/>.
    /// </summary>
    public FrontchannelLogoutOptions FrontchannelLogout { get; init; } = new();

    /// <summary>
    /// DPoP (RFC 9449) — sender-constrained access tokens. See
    /// <see cref="DpopOptions"/>.
    /// </summary>
    public DpopOptions Dpop { get; init; } = new();

    /// <summary>
    /// Opt-in FAPI 2.0 Security Profile enforcement for an explicit client
    /// allowlist. See <see cref="Fapi2Options"/>.
    /// </summary>
    public Fapi2Options Fapi2 { get; init; } = new();

    /// <summary>
    /// JWT Secured Authorization Response Mode (JARM). JARM is independent
    /// from FAPI 2.0 and remains opt-in. See <see cref="JarmOptions"/>.
    /// </summary>
    public JarmOptions Jarm { get; init; } = new();

    /// <summary>
    /// JWT-Secured Authorization Requests (JAR, RFC 9101). When enabled, the
    /// STS accepts signed <c>request</c> parameters at the authorization and
    /// PAR endpoints, validates their signature against the client's registered
    /// keys, and merges the signed claims into the authorization request. See
    /// <see cref="JarOptions"/>.
    /// </summary>
    public JarOptions Jar { get; init; } = new();

    /// <summary>
    /// OpenID Shared Signals Framework / CAEP transmitter settings. See
    /// <see cref="SharedSignalsOptions"/>.
    /// </summary>
    public SharedSignalsOptions SharedSignals { get; init; } = new();

    /// <summary>
    /// CIBA (OpenID Connect Client-Initiated Backchannel Authentication Core 1.0) —
    /// decoupled authentication where the consumption device is NOT the
    /// authentication device. See <see cref="CibaOptions"/>.
    /// </summary>
    public CibaOptions Ciba { get; init; } = new();

    /// <summary>
    /// MCP / agent-AI resource-server configuration. See
    /// <see cref="McpOptions"/>.
    /// </summary>
    public McpOptions Mcp { get; init; } = new();
}

/// <summary>
/// Database schema provisioning/migration policy.
/// </summary>
/// <remarks>
/// <para>
/// <b>Dev/test</b> always runs <c>Database.MigrateAsync()</c> at startup (so
/// pending EF migrations are applied and the Up/Down paths are exercised
/// end-to-end, not just <c>EnsureCreated</c> which ignores migrations).
/// </para>
/// <para>
/// <b>Production</b> applies pending EF migrations at startup ONLY when
/// <see cref="AutoMigrate"/> is <c>true</c> (default <c>false</c> — the
/// conservative choice for the legacy shared Duende/Skoruba database, which
/// predates the EF model and was migrated into). Because applying migrations
/// to the wrong database is destructive, <see cref="AllowedDatabaseNames"/>
/// acts as a guard: when non-empty, the actual database name (parsed from the
/// connection string) MUST be in that allow-list or the process refuses to
/// start. This stops a misconfigured connection string from ever pointing the
/// migrator at the production database by accident.
/// </para>
/// </remarks>
public sealed class DatabaseOptions
{
    /// <summary>
    /// Transport contract for the database connection. Compatibility keeps
    /// existing rolling deployments unchanged; production can select
    /// <c>RequireVerifiedTls</c> or the explicit <c>PrivateSocket</c>
    /// exception after its CA/socket is provisioned.
    /// </summary>
    public DatabaseTransportMode TransportMode { get; init; } =
        DatabaseTransportMode.Compatibility;

    /// <summary>
    /// When <c>true</c> outside Development, the host applies pending EF Core
    /// migrations on startup via <c>Database.MigrateAsync()</c>. Default
    /// <c>false</c>: production keeps provisioning schema from the checked-in
    /// canonical SQL (<c>docs/migration/sql/*</c>) until an operator
    /// deliberately opts in. Flip to <c>true</c> only after confirming the
    /// schema is aligned and <see cref="AllowedDatabaseNames"/> is set.
    /// </summary>
    public bool AutoMigrate { get; init; } = false;

    /// <summary>
    /// Allow-list of database names the automatic migrator is permitted to
    /// touch. When non-empty (recommended in production), the database name
    /// parsed from the active connection string MUST appear here or startup
    /// fails fast — a guard against pointing the migrator at the wrong
    /// (e.g. production) database. Empty (the default) disables the guard
    /// and trusts the connection string unconditionally; acceptable in
    /// Development.
    /// </summary>
    public string[] AllowedDatabaseNames { get; init; } = [];

    /// <summary>
    /// Connection-pool limits and timeouts applied by the STS before the
    /// provider is configured. See <see cref="DatabaseConnectionPoolOptions"/>.
    /// </summary>
    public DatabaseConnectionPoolOptions ConnectionPool { get; init; } = new();

    /// <summary>
    /// In-process database watchdog policy. See
    /// <see cref="DatabaseWatchdogOptions"/>.
    /// </summary>
    public DatabaseWatchdogOptions Watchdog { get; init; } = new();
}

public enum DatabaseTransportMode
{
    Compatibility,
    RequireVerifiedTls,
    PrivateSocket,
}

/// <summary>
/// Safe defaults for the current MySQL/MariaDB connection provider. Every
/// value is explicit so deployments do not inherit driver-default drift.
/// </summary>
public sealed class DatabaseConnectionPoolOptions
{
    public int MaximumSize { get; init; } = 50;

    public int MinimumSize { get; init; } = 0;

    public int ConnectionTimeoutSeconds { get; init; } = 15;

    public int CommandTimeoutSeconds { get; init; } = 30;

    public int ConnectionLifetimeSeconds { get; init; } = 180;

    public int ConnectionIdleTimeoutSeconds { get; init; } = 180;

    public bool ResetOnCheckout { get; init; } = true;

    /// <summary>
    /// Non-secret pool label emitted by MySqlConnector metrics and server
    /// connection attributes.
    /// </summary>
    public string ApplicationName { get; init; } = "Sufficit.Identity";
}

/// <summary>
/// Detects the state in which the process remains alive but cannot obtain a
/// usable database connection. After sustained failures it asks the host to
/// stop with a failure exit code so systemd or the container orchestrator can
/// rebuild the process and its pools.
/// </summary>
public sealed class DatabaseWatchdogOptions
{
    public bool Enabled { get; init; } = true;

    public int StartupDelaySeconds { get; init; } = 60;

    public int ProbeIntervalSeconds { get; init; } = 30;

    public int ProbeTimeoutSeconds { get; init; } = 10;

    public int ConsecutiveFailuresBeforeRestart { get; init; } = 3;
}

/// <summary>
/// Authenticator-app two-factor settings used by the account-management
/// application service.
/// </summary>
public sealed class TwoFactorOptions
{
    /// <summary>
    /// Issuer displayed by authenticator applications.
    /// </summary>
    public string AuthenticatorIssuer { get; init; } = "Sufficit Identity";

    /// <summary>
    /// One-time recovery codes generated after activation or regeneration.
    /// Values outside 1..20 are clamped by the runtime.
    /// </summary>
    public int RecoveryCodeCount { get; init; } = 10;
}

/// <summary>
/// Provider-neutral account passkey settings. The STS adapter maps these
/// values to the concrete WebAuthn implementation used at runtime.
/// </summary>
public sealed class AccountPasskeyOptions
{
    /// <summary>
    /// Optional WebAuthn relying-party identifier. When absent, ASP.NET
    /// Identity derives it from the validated request host.
    /// </summary>
    public string? RelyingPartyId { get; init; }

    /// <summary>
    /// Maximum passkeys that one account may retain.
    /// </summary>
    public int MaximumCredentialsPerAccount { get; init; } = 10;

    /// <summary>
    /// Maximum display-name length accepted from the account UI.
    /// </summary>
    public int MaximumNameLength { get; init; } = 100;

    /// <summary>
    /// Maximum UTF-8 size accepted for a serialized WebAuthn credential.
    /// </summary>
    public int MaximumCredentialPayloadBytes { get; init; } = 131_072;
}

/// <summary>
/// Rate limiting applied by the STS host to credential and OAuth/OIDC protocol
/// endpoints (fixed windows per client IP, no queueing). Complements — never
/// replaces — the account lockout policy: rate limiting throttles a single
/// source, lockout protects a single account from distributed attempts.
/// </summary>
public sealed class RateLimitOptions
{
    /// <summary>
    /// Master switch. Disable only when an upstream gateway already
    /// throttles the same credential and protocol endpoints.
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

    /// <summary>
    /// Pushed authorization requests allowed per window and source IP. PAR
    /// has an independent bucket so a failing token-refresh loop cannot block
    /// a new interactive login. Keeping the same conservative default as the
    /// credential bucket preserves the existing anti-abuse strength.
    /// </summary>
    public int PushedAuthorizationPermitLimit { get; init; } = 30;

    public int PushedAuthorizationWindowSeconds { get; init; } = 60;

    /// <summary>
    /// Anonymous lookups allowed per client/IP for
    /// <c>GET /connect/device/info</c>. This bucket is independent from
    /// credential POSTs so enumeration cannot consume the login/token bucket.
    /// </summary>
    public int DeviceInformationPermitLimit { get; init; } = 12;

    public int DeviceInformationWindowSeconds { get; init; } = 60;

    /// <summary>
    /// When <c>true</c> AND <c>TrustedProxies</c> is empty outside Development,
    /// the STS fails to start (instead of only logging a warning). Without
    /// trusted proxies, every request's <c>RemoteIpAddress</c> is the proxy's
    /// IP, so the rate limiter partitions ALL traffic into one shared bucket —
    /// a single attacker (or even normal load) triggers self-inflicted 429s
    /// for everyone. Default <c>false</c> (warning only); flip to <c>true</c>
    /// in production so a missing <c>TrustedProxies</c> cannot silently turn
    /// the rate limiter into a self-DoS (item 5.1 [L4]).
    /// </summary>
    public bool FailOnUntrustedProxy { get; init; } = false;
}

public sealed class UserSessionStoreOptions
{
    /// <summary>
    /// Shared-cache lifetime for protected server-side cookie tickets. Short
    /// enough to bound stale outage behavior; explicit revocation invalidates
    /// the entry immediately.
    /// </summary>
    public int CacheLifetimeSeconds { get; init; } = 60;

    /// <summary>Minimum interval between durable activity updates.</summary>
    public int ActivityUpdateIntervalSeconds { get; init; } = 300;
}

/// <summary>
/// Distributed-cache policy for multi-replica deployments. Several security-
/// critical stores (DPoP replay cache + nonce store, CIBA pending requests,
/// front-channel logout context, passkey ceremony tickets) depend on
/// <c>IDistributedCache</c>. The default registration is
/// <c>AddDistributedMemoryCache</c> (single-node, in-process) — correct for a
/// single replica, but in a multi-replica deployment each replica has its own
/// isolated cache, so DPoP replay detection, CIBA cross-replica polling and
/// nonce challenges silently break. This option lets an operator make the
/// requirement explicit so the process fails fast instead of running with a
/// degraded security posture.
/// </summary>
public sealed class DistributedCacheOptions
{
    /// <summary>
    /// When <c>true</c> outside Development, the STS fails to start if the
    /// registered <c>IDistributedCache</c> is the in-memory fallback
    /// (<c>MemoryDistributedCache</c>), because that backend is not shared
    /// across replicas. Default <c>false</c> (warning only) — flip to
    /// <c>true</c> before deploying more than one replica so a missing Redis
    /// (or other shared cache) cannot silently disable DPoP replay protection
    /// and CIBA cross-replica flows.
    /// </summary>
    public bool RequireShared { get; init; } = false;
}

/// <summary>
/// Supported hosting shapes for security-sensitive state and forwarded
/// headers.  This is deliberately an enum so configuration cannot silently
/// invent a fourth topology with incompatible assumptions.
/// </summary>
public enum DeploymentTopology
{
    SingleReplica,
    Clustered,
    BehindTrustedProxy,
    ClusteredBehindTrustedProxy,
}

/// <summary>
/// Startup contract for the selected deployment topology.
/// </summary>
public static class DeploymentTopologyPolicy
{
    public static void Validate(
        SufficitIdentityOptions options,
        int trustedProxyCount,
        bool isDevelopment)
    {
        ArgumentNullException.ThrowIfNull(options);

        var clustered = options.DeploymentTopology is
            DeploymentTopology.Clustered or
            DeploymentTopology.ClusteredBehindTrustedProxy;
        var behindProxy = options.DeploymentTopology is
            DeploymentTopology.BehindTrustedProxy or
            DeploymentTopology.ClusteredBehindTrustedProxy;

        if (clustered && !options.DistributedCache.RequireShared)
        {
            throw new InvalidOperationException(
                $"Sufficit:Identity:DeploymentTopology={options.DeploymentTopology} " +
                "requires Sufficit:Identity:DistributedCache:RequireShared=true " +
                "because DPoP, CIBA, logout and passkey state must be shared.");
        }

        if (behindProxy)
        {
            if (!isDevelopment && trustedProxyCount == 0)
            {
                throw new InvalidOperationException(
                    $"Sufficit:Identity:DeploymentTopology={options.DeploymentTopology} " +
                    "requires at least one configured Sufficit:Identity:TrustedProxies entry.");
            }

            if (!options.RateLimit.FailOnUntrustedProxy)
            {
                throw new InvalidOperationException(
                    $"Sufficit:Identity:DeploymentTopology={options.DeploymentTopology} " +
                    "requires RateLimit:FailOnUntrustedProxy=true so a missing proxy " +
                    "trust boundary cannot degrade into a shared rate-limit bucket.");
            }

            if (!Uri.TryCreate(options.Issuer, UriKind.Absolute, out var issuer) ||
                issuer.Scheme != Uri.UriSchemeHttps)
            {
                throw new InvalidOperationException(
                    $"Sufficit:Identity:DeploymentTopology={options.DeploymentTopology} " +
                    "requires an explicit HTTPS Sufficit:Identity:Issuer.");
            }
        }

        if (clustered && !Uri.TryCreate(options.Issuer, UriKind.Absolute, out _))
        {
            throw new InvalidOperationException(
                $"Sufficit:Identity:DeploymentTopology={options.DeploymentTopology} " +
                "requires an explicit absolute Sufficit:Identity:Issuer for stable " +
                "cross-replica discovery and token validation.");
        }
    }
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
    /// FAPI 2.0 NOTE: the 14-day default targets general-purpose deployments.
    /// For FAPI 2.0 / financial-grade profiles, deploy a materially shorter
    /// lifetime (e.g. 1 day or less) in configuration — ecosystem guidance
    /// favors short-lived, rotated refresh tokens for high-assurance clients.
    /// </summary>
    public double RefreshTokenLifetimeDays { get; init; } = 14;

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

public enum AccessTokenStorageMode
{
    Reference,
    Jwt,
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
/// Explicit CORS policy for browser-based resource clients.
/// </summary>
public sealed class CorsOptions
{
    /// <summary>
    /// Enables the policy middleware. Defaults to <c>false</c> so an
    /// unconfigured public Identity deployment does not accidentally expose
    /// cross-origin APIs.
    /// </summary>
    public bool Enabled { get; init; }

    /// <summary>
    /// Exact origins allowed to call the API, including scheme and port.
    /// Wildcards and trailing paths are rejected when the policy is built.
    /// </summary>
    public List<string> AllowedOrigins { get; init; } = [];

    /// <summary>
    /// Allows browser credential mode for clients that intentionally use
    /// cookies. Bearer-only clients should leave this disabled.
    /// </summary>
    public bool AllowCredentials { get; init; }
}

/// <summary>
/// Content Security Policy (CSP) baseline for the STS's interactive HTML
/// pages (login, consent, device verification, logout), served by the sibling
/// embedded <c>Sufficit.Identity.UI</c> Blazor Server project. XSS on those pages is
/// the highest-impact client-side risk in an IdP (forged consent / stolen
/// session), and CSP is the containment layer that was missing (eval M1).
/// </summary>
/// <remarks>
/// <b>Rollout model (report-only first).</b> The policy ships
/// <see cref="ReportOnly"/>=<c>true</c> so it does NOT block anything until an
/// operator has calibrated it against the real UI (exercising login, consent,
/// device and logout end-to-end), collected the violation reports, tightened
/// the directives — ideally removing <c>'unsafe-inline'</c> from
/// <c>style-src</c> via nonces/hashes — and then flipped <see cref="ReportOnly"/>
/// to <c>false</c>. Shipping in enforce mode without that calibration would
/// break the UI for end users.
///
/// <para><b>Cross-repo note.</b> The actual calibration is an operational step
/// performed in the UI repo (the STS host emits the header; the UI renders the
/// pages). It cannot be exercised by the STS integration tests, which do not
/// load the embedded UI (see <c>SufficitIdentityTestFactory</c>). The tests here
/// assert that the header is emitted with the configured policy; they do not
/// validate the policy against the real rendered DOM.</para>
/// </remarks>
/// <summary>
/// Policy for the consolidated production posture check
/// (<c>ProductionPostureCheck</c>). The check gathers permissive
/// rollout-friendly defaults (CSP report-only, management Observe modes and a
/// non-shared DPoP replay cache) that are
/// easy to ship to production unnoticed.
/// </summary>
public sealed class SecurityPostureOptions
{
    /// <summary>
    /// Retained only so older configuration files continue to bind. The host
    /// now always fails closed outside Development; false is logged and ignored.
    /// </summary>
    [Obsolete("The production posture check always fails closed outside Development. Use bounded per-finding acknowledgements.")]
    public bool FailClosedOnInsecureDefaults { get; init; } = true;

    /// <summary>
    /// Temporary bridge for the old CSP/Management acknowledgement booleans.
    /// Disabled by default. When explicitly enabled, old booleans are honored
    /// with a deprecation warning while deployments migrate to
    /// <see cref="Acknowledgements"/>.
    /// </summary>
    public bool AllowLegacyBooleanAcknowledgements { get; init; }

    /// <summary>
    /// Bounded exceptions keyed by stable production posture finding ID. Owner,
    /// reason and a future expiry are all required; stale or expired entries
    /// are themselves startup findings.
    /// </summary>
    public Dictionary<string, ProductionPostureAcknowledgement> Acknowledgements
    { get; init; } = new(StringComparer.Ordinal);
}

public sealed class CspOptions
{
    /// <summary>
    /// Master switch for CSP emission. Default <c>true</c>. Disable only if an
    /// upstream gateway already injects a CSP.
    /// </summary>
    public bool Enabled { get; init; } = true;

    /// <summary>
    /// When <c>true</c> (default), emits <c>Content-Security-Policy-Report-Only</c>
    /// — violations are reported but NOT blocked, so a misconfigured policy
    /// cannot break the UI. Flip to <c>false</c> only after calibrating the
    /// policy against the real UI pages (see the class-level remarks).
    /// </summary>
    public bool ReportOnly { get; init; } = true;

    /// <summary>
    /// Acknowledges that running CSP in <see cref="ReportOnly"/> mode in
    /// production is a deliberate choice (e.g. during policy calibration). When
    /// false (default), the production posture check treats report-only CSP as
    /// an unresolved permissive default and — if fail-closed is on — blocks
    /// startup. Set true only if you knowingly want report-only in production.
    /// </summary>
    public bool AcknowledgeReportOnly { get; init; }

    /// <summary>
    /// The policy string. The default is tuned for a Blazor Server UI hosted
    /// same-origin with the STS: <c>connect-src</c> allows the SignalR WebSocket
    /// circuit; <c>style-src</c> allows <c>'unsafe-inline'</c> (Blazor/Bootstrap
    /// commonly require it — the calibration step should aim to remove it via
    /// nonces/hashes); <c>img-src</c> admits the same-origin UI and the
    /// Sufficit avatar endpoint used by authenticated shells;
    /// <c>frame-ancestors 'none'</c> reinforces
    /// <c>X-Frame-Options: DENY</c>. Adjust per environment as needed.
    /// </summary>
    public string Policy { get; init; } =
        "default-src 'self'; " +
        "script-src 'self'; " +
        "style-src 'self' 'unsafe-inline'; " +
        "img-src 'self' data:; " +
        // 'self' covers the same-origin SignalR WebSocket upgrade — no need
        // for broad wss:/ws: wildcards that would allow XSS exfil to any host.
        "connect-src 'self'; " +
        "frame-ancestors 'none'; " +
        "base-uri 'self'; " +
        "form-action 'self'";

    /// <summary>
    /// Optional <c>report-uri</c> (or <c>report-to</c>) endpoint appended to
    /// the policy so a violation collector can receive reports during the
    /// report-only calibration phase. Null/empty = no <c>report-uri</c>
    /// directive emitted.
    /// </summary>
    public string? ReportUri { get; init; }
}

/// <summary>
/// Password complexity policy enforced by ASP.NET Core Identity on user
/// creation and password change/reset (eval M2). The defaults raise the bar
/// above the ASP.NET Core defaults (<c>RequiredLength=6</c>) toward the 2026
/// baseline (NIST 800-63B: favor length over composition rules, but require a
/// minimum of 8 — this policy defaults to 12). Existing users are NOT forced
/// to change their password on login: ASP.NET Core Identity applies password
/// rules only at creation/change time, never retroactively.
/// </summary>
public sealed class PasswordPolicyOptions
{
    /// <summary>Minimum password length. Default 12 (NIST 800-63B floor is 8).</summary>
    public int RequiredLength { get; init; } = 12;

    /// <summary>Require at least one digit ('0'-'9'). Default true.</summary>
    public bool RequireDigit { get; init; } = true;

    /// <summary>Require at least one lowercase letter ('a'-'z'). Default true.</summary>
    public bool RequireLowercase { get; init; } = true;

    /// <summary>Require at least one uppercase letter ('A'-'Z'). Default true.</summary>
    public bool RequireUppercase { get; init; } = true;

    /// <summary>Require at least one non-alphanumeric character. Default true.</summary>
    public bool RequireNonAlphanumeric { get; init; } = true;

    /// <summary>Minimum number of distinct characters. Default 4.</summary>
    public int RequiredUniqueChars { get; init; } = 4;

    /// <summary>
    /// OPT-IN hook for a breached-password validator (HaveIBeenPwned k-anonymity
    /// range API, or a local top-N blocklist). Default <c>false</c>: the flag
    /// exists to surface the decision as explicit config, but NO validator is
    /// wired up by default in this pass — implementing the validator itself
    /// (HIBP range call with network/mock, or a local list) is tracked as a
    /// separate hardening item, since a network-dependent validator needs
    /// careful handling of latency/availability and a local list is of limited
    /// value. Flip to <c>true</c> only after the validator is implemented and
    /// its latency/availability characteristics are validated for the target
    /// environment.
    /// </summary>
    public bool RejectBreached { get; init; } = false;
}

/// <summary>
/// Sign-in policy applied by ASP.NET Core Identity's
/// <see cref="Microsoft.AspNetCore.Identity.SignInManager{TUser}.CanSignInAsync"/>
/// — which every grant in <c>AuthorizationController</c> consults. See
/// <see cref="SignInPolicyOptions"/>.
/// </summary>
public sealed class SignInPolicyOptions
{
    /// <summary>
    /// When <c>true</c> (default — secure-by-default, eval M3), a user cannot
    /// sign in until they have proven possession of their email. Combined with
    /// the public self-registration surface (gated separately in the embedded UI
    /// repo via <c>Sufficit:Identity:Register:Enabled</c>), this closes the
    /// "register with someone else's email and use the account" hole. Every
    /// grant in <c>AuthorizationController</c> collapses the unconfirmed-email
    /// case into the same generic <c>invalid_grant</c> as a wrong password, so
    /// this does NOT introduce user enumeration.
    /// </summary>
    /// <remarks>
    /// <b>External-login dependency.</b> Accounts created via an external
    /// provider (Google/GitHub/Facebook) by the runtime's
    /// <c>AspNetCoreIdentityExternalSignInService</c> are only marked
    /// <c>EmailConfirmed=true</c>
    /// when the provider asserts <c>email_verified</c>. The STS wires that
    /// <c>ClaimAction</c> for Google (<c>ServiceCollectionExtensions.
    /// AddExternalProviders</c>) but NOT yet for Facebook/GitHub. Flipping this
    /// to <c>true</c> in production therefore REQUIRES first ensuring every
    /// configured external provider emits (and the UI consumes) the
    /// <c>email_verified</c> claim — otherwise provider users get locked out.
    /// See <c>docs/runbooks/RUNBOOK-CONFIRMED-EMAIL.md</c> for the production
    /// rollout steps, including the legacy-user migration query.
    /// </remarks>
    public bool RequireConfirmedEmail { get; init; } = true;
}

/// <summary>
/// Config-driven claim-type → required-scope allowlist that closes the residual
/// over-disclosure gap (eval #10 / plan item 2.5 [M5]). When a claim type is
/// present in <see cref="ClaimToScope"/>, that claim reaches the access and
/// identity tokens ONLY if the subject was granted the mapped scope. Claim
/// types NOT in the map keep the pre-existing behavior while
/// <see cref="ClaimScopeMapOptions.IncludeUnmappedClaimsInAccessTokens"/> is
/// true. The default map protects the authorization directive claim.
/// </summary>
/// <remarks>
/// <b>Rollout model.</b> Add entries one resource server at a time: first
/// confirm every RS that consumes a claim requests the mapped scope, THEN add
/// the claim-to-scope entry. Adding an entry before the RS requests the scope
/// silently strips the claim from that RS's tokens. Mapped scopes and claims
/// are registered automatically by the STS when this option is configured.
/// </remarks>
public sealed class ClaimScopeMapOptions
{
    /// <summary>
    /// Map of claim type → scope name. When a token is being built, a claim
    /// whose type matches a key here is included in the access token ONLY if
    /// the subject's granted scopes contain the mapped value. Mapped keys and
    /// values are also advertised as custom claims/scopes in discovery.
    /// </summary>
    /// <remarks>
    /// <b>Default (finding #4 fix).</b> The Sufficit authorization directive
    /// claim (<c>directive</c>) is gated behind the <c>directives</c> scope so
    /// a client requesting only <c>openid</c> does not receive the user's full
    /// authorization directive set. An operator can add more entries or clear
    /// this map to revert to the pre-fix behavior (all claims to all tokens).
    /// </remarks>
    public Dictionary<string, string> ClaimToScope { get; init; } = new(StringComparer.Ordinal)
    {
        ["directive"] = "directives",
    };

    /// <summary>
    /// Compatibility bridge for persisted claim types that are not yet mapped.
    /// Keep true while resource servers are inventoried, then set false to make
    /// <see cref="ClaimToScope"/> a strict allowlist without removing claims
    /// from existing tokens during the rollout.
    /// </summary>
    public bool IncludeUnmappedClaimsInAccessTokens { get; init; } = true;

    /// <summary>
    /// Persisted claim types that are never eligible for token release when
    /// unmapped, including while the general compatibility bridge is active.
    /// Values are claim names only; claim values are never logged.
    /// </summary>
    public HashSet<string> DeniedUnmappedClaimTypes { get; init; } = new(StringComparer.Ordinal)
    {
        "security_stamp",
        "concurrency_stamp",
        "password_hash",
        "authenticator_key",
        "recovery_codes",
    };
}

public enum SecurityPolicyEnforcementMode
{
    Observe,
    Enforce,
}

/// <summary>
/// Least-privilege policy for issuing personal access tokens. Enforce is the
/// secure default; Observe remains available only as an explicit, posture-
/// checked migration mode.
/// </summary>
public sealed class PersonalTokenIssuanceOptions
{
    public SecurityPolicyEnforcementMode Mode { get; init; } =
        SecurityPolicyEnforcementMode.Enforce;

    public string RequiredScope { get; init; } = "personal_tokens.manage";

    public bool RequireRecentAuthentication { get; init; } = true;

    public int MaximumAuthenticationAgeMinutes { get; init; } = 15;

    public int MaximumLifetimeDays { get; init; } = 90;

    public bool RequireSenderConstraint { get; init; }

    public HashSet<string> EligibleClientIds { get; init; } = new(StringComparer.Ordinal);
}

/// <summary>
/// Mutual TLS (mTLS) client authentication and sender-constrained access
/// tokens (RFC 8705). mTLS is a prerequisite of FAPI 2.0 and a stronger
/// alternative to client secrets for confidential clients: the client
/// authenticates with an X.509 certificate at the TLS layer against
/// MTLS-aliased endpoint paths (e.g. <c>/connect/token</c> served under a
/// distinct path that requires a client certificate).
/// </summary>
/// <remarks>
/// <b>Opt-in (default <see cref="Enabled"/>=<c>false</c>).</b> mTLS requires
/// the HOST (Kestrel/nginx) to be configured to request and validate client
/// certificates at the TLS handshake — that is deployment configuration, not
/// something this option alone can enable. When <see cref="Enabled"/> is true,
/// the STS registers the MTLS endpoint aliases (so clients can target them)
/// and advertises <c>tls_client_certificate_bound_access_tokens=true</c> in
/// discovery. See <c>src/server/Program.cs</c> and the appsettings template
/// for the host-side configuration required.
/// <para><b>private_key_jwt</b> (RFC 7523) is enabled by OpenIddict
/// unconditionally and is NOT gated here — it is available regardless of this
/// flag. mTLS and private_key_jwt together cover the "strong client auth"
/// requirement of FAPI 2.0.</para>
/// </remarks>
public sealed class MtlsOptions
{
    /// <summary>
    /// When <c>true</c>, the STS registers MTLS endpoint aliases and advertises
    /// mTLS sender-constrained token support in discovery. Default
    /// <c>false</c> — the host must be configured for client certificates first
    /// (otherwise the MTLS-aliased paths would 404 at the TLS layer).
    /// </summary>
    public bool Enabled { get; init; } = false;

    /// <summary>
    /// Explicit statement of where client-certificate validation occurs.
    /// Enabling mTLS with Unattested is rejected during startup.
    /// </summary>
    public MtlsDeploymentMode DeploymentMode { get; init; } =
        MtlsDeploymentMode.Unattested;

    /// <summary>
    /// SHA-256 certificate thumbprints allowed for each OAuth client. Multiple
    /// entries permit bounded rollover overlap.
    /// </summary>
    public Dictionary<string, HashSet<string>> ClientCertificateThumbprints { get; init; } =
        new(StringComparer.Ordinal);

    /// <summary>
    /// Builds the platform X.509 chain in addition to the explicit client pin.
    /// Keep enabled in production; private PKI roots must be installed in the
    /// host trust store.
    /// </summary>
    public bool RequireValidCertificateChain { get; init; } = true;

    /// <summary>
    /// Certificate-revocation strategy used while building the platform chain.
    /// The secure default performs online CRL/OCSP retrieval.
    /// </summary>
    public MtlsCertificateRevocationMode RevocationMode { get; init; } =
        MtlsCertificateRevocationMode.Online;

    /// <summary>
    /// Controls whether an unavailable CRL/OCSP responder is denied. The
    /// default is fail-closed; the compatibility mode never permits an
    /// explicitly revoked, expired, untrusted or wrongly pinned certificate.
    /// </summary>
    public MtlsRevocationFailureMode RevocationFailureMode { get; init; } =
        MtlsRevocationFailureMode.FailClosed;

    /// <summary>Maximum platform chain URL retrieval time.</summary>
    public int RevocationTimeoutSeconds { get; init; } = 3;

    /// <summary>
    /// Header carrying the URL-encoded PEM or base64 DER certificate in
    /// TrustedProxy mode. It is removed before downstream middleware runs.
    /// </summary>
    public string ForwardedCertificateHeader { get; init; } =
        "X-Sufficit-Client-Certificate";

    /// <summary>
    /// CIDRs authorized specifically to assert the forwarded client
    /// certificate. This list is deliberately separate from general
    /// X-Forwarded-* proxy trust.
    /// </summary>
    public HashSet<string> TrustedProxyNetworks { get; init; } =
        new(StringComparer.Ordinal);
}

public enum MtlsDeploymentMode
{
    Unattested,
    DirectTls,
    TrustedProxy,
}

public enum MtlsCertificateRevocationMode
{
    NoCheck,
    Online,
    Offline,
}

public enum MtlsRevocationFailureMode
{
    FailClosed,
    AllowWhenUnavailable,
}

/// <summary>
/// OIDC Back-Channel Logout 1.0 — distribution of a signed <c>logout_token</c>
/// to every RP with an active session when a user signs out (item 3.2 [L1]).
/// OpenIddict 7.6 only CONSUMES logout_tokens; it does NOT generate them, so
/// the STS hand-builds the JWT (<c>Logout.LogoutTokenGenerator</c>) and fans it
/// out (<c>Logout.BackchannelLogoutDistributor</c>). The discovery handler
/// advertises <c>backchannel_logout_supported=true</c> only when this is
/// enabled, so clients know the STS will notify them on logout.
/// </summary>
/// <remarks>
/// The capability is enabled by default. It remains a no-op for clients that
/// do not register a <c>backchannel_logout_uri</c>.
/// </remarks>
public sealed class BackchannelLogoutOptions
{
    /// <summary>
    /// Master switch. When <c>true</c>, the STS distributes a
    /// <c>logout_token</c> to every RP with an active authorization on user
    /// sign-out, and advertises <c>backchannel_logout_supported=true</c> in
    /// discovery. Default <c>true</c>.
    /// </summary>
    public bool Enabled { get; init; } = true;
}

/// <summary>
/// OIDC Front-Channel Logout 1.0 — renders each RP's registered
/// <c>frontchannel_logout_uri</c> in an iframe after local sign-out.
/// </summary>
/// <remarks>
/// The capability is enabled by default. The OP issues a cryptographically
/// random <c>sid</c> in its session cookie and ID Tokens, allowing RPs to
/// request session-specific logout.
/// </remarks>
public sealed class FrontchannelLogoutOptions
{
    /// <summary>
    /// Master switch. When <c>true</c>, the OP prepares a one-time iframe page
    /// for registered RP logout URIs and advertises front-channel support.
    /// Default <c>true</c>.
    /// </summary>
    public bool Enabled { get; init; } = true;
}

/// <summary>
/// DPoP (RFC 9449) — sender-constrains access tokens to a client-provided key,
/// neutralizing token theft/replay without requiring mTLS. A client sends a
/// short-lived signed <c>DPoP</c> proof header with each token request; the STS
/// validates it and embeds the proof key's thumbprint (<c>cnf.jkt</c>) in the
/// issued access token, so resource servers can reject the token when a later
/// request does not present a matching proof (item 3.1).
/// </summary>
/// <remarks>
/// <b>Implemented from scratch</b> — OpenIddict 7.6 has no DPoP support
/// (verified: zero "dpop" strings in any assembly). The proof validator
/// (<c>Dpop.DpopProofValidator</c>) and the <c>cnf</c> attachment live in the
/// STS controller, not in OpenIddict handlers, to stay portable for a future
/// move off OpenIddict. Opt-in by default: when disabled, the STS behaves
/// exactly as before (pure bearer tokens).
/// <para>
/// When <see cref="Enabled"/> is true but <see cref="RequireForAllClients"/> is
/// false (the default), DPoP is ACCEPTED-but-not-required: clients that send a
/// valid proof get a sender-constrained token; clients that don't get a plain
/// bearer token (backward compatible). Flip <see cref="RequireForAllClients"/>
/// to reject bearer entirely — only do this once every client is DPoP-capable.
/// </para>
/// </remarks>
public sealed class DpopOptions
{
    /// <summary>
    /// Master switch. When <c>true</c>, the STS validates the <c>DPoP</c>
    /// header on token requests and sender-constrains tokens whose requests
    /// carried a valid proof. Default <c>false</c>.
    /// </summary>
    public bool Enabled { get; init; } = false;

    /// <summary>
    /// When <c>true</c>, a valid DPoP proof is REQUIRED on every token request
    /// — requests without one (or with an invalid one) are rejected. Default
    /// <c>false</c> (accept-but-don't-require) so legacy bearer clients keep
    /// working during a gradual rollout. Flip only after confirming every
    /// client sends DPoP proofs.
    /// </summary>
    public bool RequireForAllClients { get; init; } = false;

    /// <summary>
    /// When <c>true</c>, the AS enforces the DPoP nonce dance (RFC 9449 §8):
    /// a proof without a valid <c>nonce</c> claim is rejected with HTTP 400
    /// <c>use_dpop_nonce</c> and a <c>DPoP-Nonce</c> response header; the
    /// client retries carrying that nonce. RECOMMENDED by the RFC (bounds
    /// pre-computation attacks) but not required. Default <c>false</c> — flip
    /// to harden once clients implement the retry. Ignored when
    /// <see cref="Enabled"/> is false.
    /// </summary>
    public bool RequireNonce { get; init; } = false;
}

/// <summary>
/// A deliberately opt-in FAPI 2.0 Security Profile boundary. Enabling this
/// option does not by itself assert certification: it activates the protocol
/// controls the STS can enforce and leaves conformance claims to the official
/// OpenID Foundation test suite and deployment-level TLS evidence.
/// </summary>
public sealed class Fapi2Options
{
    /// <summary>Master switch. Default <c>false</c>.</summary>
    public bool Enabled { get; init; } = false;

    /// <summary>
    /// Confidential client identifiers governed by the profile. Keeping an
    /// explicit allowlist prevents a FAPI rollout from breaking legacy OAuth
    /// clients sharing the same issuer.
    /// </summary>
    public HashSet<string> ClientIds { get; init; } = new(StringComparer.Ordinal);

    /// <summary>
    /// Sender-constraining mechanism required for profiled clients. DPoP is
    /// the default; mTLS requires the TLS terminator to validate certificates.
    /// </summary>
    public Fapi2SenderConstraint SenderConstraint { get; init; } =
        Fapi2SenderConstraint.Dpop;

    /// <summary>
    /// Lifetime of authorization codes in seconds. FAPI 2.0 caps this at 60;
    /// values outside 1..60 are rejected during startup.
    /// </summary>
    public int AuthorizationCodeLifetimeSeconds { get; init; } = 60;

    /// <summary>
    /// Lifetime of PAR request URIs in seconds. FAPI 2.0 requires a value
    /// below 600; values outside 1..599 are rejected during startup.
    /// </summary>
    public int PushedAuthorizationRequestLifetimeSeconds { get; init; } = 300;
}

public enum Fapi2SenderConstraint
{
    Dpop,
    Mtls,
}

/// <summary>
/// JWT Secured Authorization Response Mode (JARM) configuration. The STS
/// signs the complete authorization response and returns it in a single
/// <c>response</c> parameter. This capability is independent of FAPI 2.0.
/// </summary>
public sealed class JarmOptions
{
    /// <summary>Master switch. Default <c>false</c>.</summary>
    public bool Enabled { get; init; } = false;

    /// <summary>
    /// Signed response lifetime in seconds. Kept short to bound replay;
    /// values outside 1..600 are rejected during startup.
    /// </summary>
    public int LifetimeSeconds { get; init; } = 120;

    /// <summary>
    /// JARM encryption (JWE) configuration. When set, authorization responses
    /// are signed AND encrypted (signed-then-encrypted, the FAPI 2.0 Advancing
    /// Profile shape). When null (default), responses remain signed-only.
    /// </summary>
    public JarmEncryptionOptions Encryption { get; init; } = new();
}

/// <summary>
/// JWE encryption settings for JARM responses. The STS can encrypt the signed
/// JWT response to an RSA or EC public key registered in each client's JWKS.
/// The receiver decrypts with its matching private key. Encryption is an
/// optional JARM confidentiality mode; FAPI 2.0 does not require it for the
/// authorization code response.
/// </summary>
public sealed class JarmEncryptionOptions
{
    /// <summary>
    /// Master switch for JWE encryption. When false (default), JARM responses
    /// are signed-only even when <see cref="JarmOptions.Enabled"/> is true.
    /// </summary>
    public bool Enabled { get; init; } = false;

    /// <summary>
    /// Deprecated and ignored. Recipient keys must come from client metadata.
    /// </summary>
    public string? Path { get; init; }

    /// <summary>
    /// Deprecated and ignored with <see cref="Path"/>.
    /// </summary>
    public string? Password { get; init; }

    /// <summary>
    /// JWE <c>alg</c> (key management) algorithm for RSA recipient keys.
    /// Defaults to <c>RSA-OAEP-256</c> (RSA-OAEP with SHA-256). The legacy
    /// <c>RSA-OAEP</c> (SHA-1) is discouraged. Ignored for EC recipient keys, which use
    /// <see cref="EcKeyManagementAlgorithm"/>.
    /// </summary>
    public string KeyManagementAlgorithm { get; init; } = "RSA-OAEP-256";

    /// <summary>
    /// JWE <c>alg</c> (key management) algorithm for EC recipient keys.
    /// Defaults to <c>ECDH-ES+A256KW</c>. Used when a FAPI/OIDC client
    /// registers an elliptic-curve (rather than RSA) encryption key in its
    /// JWKS.
    /// </summary>
    public string EcKeyManagementAlgorithm { get; init; } = "ECDH-ES+A256KW";

    /// <summary>
    /// JWE <c>enc</c> (content encryption) algorithm. Defaults to
    /// <c>A256CBC-HS512</c> (the value compatible with RSA key transport in
    /// Microsoft IdentityModel — <c>A256GCM</c> requires symmetric keywrap).
    /// </summary>
    public string ContentEncryptionAlgorithm { get; init; } = "A256CBC-HS512";
}

/// <summary>
/// JWT-Secured Authorization Request (JAR, RFC 9101) options. When enabled,
/// the STS accepts a signed <c>request</c> parameter (a JWT whose payload
/// carries the authorization request parameters) and validates it against the
/// client's registered signing keys before merging its claims.
/// </summary>
/// <remarks>
/// <b>Opt-in (default <see cref="Enabled"/>=<c>false</c>).</b> JAR is
/// independent of FAPI 2.0 but is a prerequisite of the FAPI 2.0 Security
/// Profile for clients that need signed authorization requests (as an
/// alternative or complement to PAR — a request object can be pushed via PAR).
/// </remarks>
public sealed class JarOptions
{
    /// <summary>
    /// Master switch. When <c>true</c>, the authorization and PAR endpoints
    /// accept a signed <c>request</c> parameter. Default <c>false</c>.
    /// </summary>
    public bool Enabled { get; init; } = false;

    /// <summary>
    /// Signing algorithms accepted in request objects. Defaults to the FAPI
    /// 2.0 baseline (<c>PS256</c>, <c>ES256</c>). A request object signed with
    /// any other algorithm is rejected.
    /// </summary>
    public HashSet<string> AllowedSigningAlgorithms { get; init; } = new(StringComparer.Ordinal)
    {
        "PS256",
        "ES256",
    };

    /// <summary>
    /// Maximum lifetime of a request object, in seconds. A request object
    /// without an <c>exp</c> claim is rejected; one older than this (counted
    /// from its <c>iat</c>, or <c>nbf</c> when present) is rejected. Default
    /// 120 (2 minutes). RFC 9101 recommends a short lifetime.
    /// </summary>
    public int MaxLifetimeSeconds { get; init; } = 120;

    /// <summary>Required RFC 9101 request-object media type.</summary>
    public string RequiredTokenType { get; init; } = "oauth-authz-req+jwt";

    /// <summary>Maximum remote JWKS response size. Responses are streamed and
    /// rejected once this bound is crossed.</summary>
    public int RemoteJwksMaxBytes { get; init; } = 65_536;

    /// <summary>Per-request timeout for a registered remote JWKS URI.</summary>
    public int RemoteJwksTimeoutSeconds { get; init; } = 3;

    /// <summary>Fresh-cache lifetime for remote key sets.</summary>
    public int RemoteJwksCacheSeconds { get; init; } = 300;

    /// <summary>Additional bounded interval during which an already-known kid
    /// may be used if the remote endpoint is temporarily unavailable.</summary>
    public int RemoteJwksStaleSeconds { get; init; } = 900;

    /// <summary>Maximum number of registered JWKS URIs retained in process.</summary>
    public int RemoteJwksMaxCacheEntries { get; init; } = 256;
}

/// <summary>
/// OpenID Shared Signals Framework 1.0 transmitter configuration. The first
/// production slice supports discovery plus RFC 8935 push delivery of signed
/// CAEP SETs to statically provisioned receivers. The optional dynamic stream
/// management API is intentionally not advertised.
/// </summary>
public sealed class SharedSignalsOptions
{
    /// <summary>Master switch. Default <c>false</c>.</summary>
    public bool Enabled { get; init; } = false;

    /// <summary>
    /// Statically provisioned push receivers. Secrets belong in environment
    /// variables or an external secret store, never committed appsettings.
    /// </summary>
    public List<SharedSignalsReceiverOptions> Receivers { get; init; } = new();

    /// <summary>
    /// Opt-in dynamic stream management API (RFC 8933). When true, exposes
    /// <c>/ssf/streams</c> for creating/reading/deleting streams and
    /// advertises <c>configuration_endpoint</c> in discovery. Default false —
    /// the REST surface is administrative and should be enabled deliberately.
    /// </summary>
    public bool StreamManagementEnabled { get; init; } = false;

    /// <summary>
    /// OAuth scope required to call the stream-management and poll endpoints.
    /// Default <c>ssf_transmitter</c>. The scope must exist as an OpenIddict
    /// scope (create it via the management API or provisioning manifest).
    /// </summary>
    public string RequiredScope { get; init; } = "ssf_transmitter";

    /// <summary>
    /// Requires <c>subject</c> to be supplied explicitly when a stream is
    /// created, instead of defaulting to <c>ALL</c> (every subject in the
    /// deployment). Default <c>false</c> for compatibility: existing receivers
    /// legitimately rely on the <c>ALL</c> default, so tightening it is a
    /// breaking change an operator opts into. When false, an omitted subject
    /// still defaults to <c>ALL</c> but is logged at Warning.
    /// </summary>
    public bool RequireExplicitSubject { get; init; } = false;
}

public sealed class SharedSignalsReceiverOptions
{
    /// <summary>Stable operator-facing receiver identifier.</summary>
    public string Id { get; init; } = string.Empty;

    /// <summary>SET audience expected by this receiver.</summary>
    public string Audience { get; init; } = string.Empty;

    /// <summary>HTTPS RFC 8935 push endpoint.</summary>
    public string Endpoint { get; init; } = string.Empty;

    /// <summary>
    /// Optional value placed in the HTTP Authorization header, for example
    /// <c>Bearer ...</c>. Configure from a secret source.
    /// </summary>
    public string? Authorization { get; init; }
}

/// <summary>
/// CIBA (OpenID Connect Client-Initiated Backchannel Authentication Core 1.0).
/// Enables decoupled authentication: a client initiates auth on a consumption
/// device (kiosk, call-center, AI agent) and the end user approves on a
/// SEPARATE authentication device. The client polls the token endpoint with an
/// <c>auth_req_id</c> until the user approves (or denies, or it expires).
/// </summary>
/// <remarks>
/// <b>Implemented from scratch</b> — OpenIddict 7.6 has no CIBA support.
/// Pending requests are held by <c>ICibaPendingRequestStore</c> (an in-memory
/// implementation is shipped for the current single-instance deployment).
/// The store boundary includes an atomic approved-request consumption method;
/// multi-replica deployments must provide a shared implementation before
/// enabling CIBA. The completion channel binds approval to the requested
/// subject and the poll path emits the RFC error contract.
/// <para>
/// Opt-in (default <see cref="Enabled"/>=<c>false</c>). Enabling registers the
/// <c>/bc-authorize</c> initiation endpoint, the completion endpoint, and the
/// CIBA grant-type branch in <c>/connect/token</c>; discovery advertises
/// <c>backchannel_token_delivery_modes_supported=["poll"]</c> and
/// <c>grant_types_supported</c> includes the CIBA grant.
/// </para>
/// </remarks>
public sealed class CibaOptions
{
    /// <summary>
    /// Master switch. Default <c>false</c>.
    /// </summary>
    public bool Enabled { get; init; } = false;

    /// <summary>
    /// How long an unapproved <c>auth_req_id</c> stays valid (seconds).
    /// Default 600 (10 min) — CIBA Core 1.0 <c>expires_in</c>.
    /// </summary>
    public int ExpiresInSeconds { get; init; } = 600;

    /// <summary>
    /// Minimum seconds the client MUST wait between polls. CIBA Core 1.0
    /// <c>interval</c>. If the client polls faster, the AS returns
    /// <c>slow_down</c>. Default 5.
    /// </summary>
    public int PollIntervalSeconds { get; init; } = 5;

    /// <summary>
    /// Observe records clients that would fail the explicit CIBA entitlement
    /// without interrupting them. Enforce rejects those requests.
    /// </summary>
    public SecurityPolicyEnforcementMode ClientPolicyMode { get; init; } =
        SecurityPolicyEnforcementMode.Enforce;

    public bool RequireConfidentialClient { get; init; } = true;

    public string RequiredGrantPermission { get; init; } =
        "gt:urn:openid:params:grant-type:ciba";

    public HashSet<string> AllowedClientIds { get; init; } = new(StringComparer.Ordinal);
}

/// <summary>
/// MCP (Model Context Protocol) / agent-AI resource-server configuration
/// (Onda 4). Configures the STS to serve as the authorization server for MCP
/// servers and other agent resource servers: RFC 8707 resource indicators
/// (audience binding), RFC 9728 protected-resource metadata, and (opt-in)
/// RFC 7591 Dynamic Client Registration.
/// </summary>
public sealed class McpOptions
{
    /// <summary>
    /// Resource/audience URIs the STS recognizes as valid <c>resource</c>
    /// indicator targets (RFC 8707, item 4.2). These are registered with
    /// OpenIddict so <c>resource</c> parameters are accepted (without this,
    /// OpenIddict rejects unknown resources with <c>invalid_target</c>). A
    /// client must ALSO be granted the matching <c>oi_rprm</c> permission
    /// (<c>Permissions.Prefixes.Resource + uri</c>) to request one. Each entry
    /// typically points to an MCP server (e.g.
    /// <c>https://mcp.example.com</c>). Empty by default.
    /// </summary>
    public List<string> Resources { get; init; } = new();

    /// <summary>
    /// When <c>true</c>, exposes the RFC 9728
    /// <c>/.well-known/oauth-protected-resource</c> metadata document pointing
    /// resource servers (MCP) to this STS as their authorization server.
    /// Default <c>true</c>: serving the metadata is cheap and harmless (it only
    /// advertises the AS location; actual resource servers decide whether to
    /// trust it). Disable only if the STS is never an MCP/agent AS.
    /// </summary>
    public bool ProtectedResourceMetadataEnabled { get; init; } = true;

    /// <summary>
    /// Dynamic Client Registration (RFC 7591) — opt-in (default <c>false</c>).
    /// When enabled, exposes <c>/connect/register</c> for clients (including
    /// MCP clients) to self-register. Gated: requires an initial access token
    /// by default (see <see cref="DcrRequireInitialAccessToken"/>). DCR is a
    /// high-risk surface if open; enable deliberately.
    /// </summary>
    public DcrOptions Dcr { get; init; } = new();
}

/// <summary>
/// Dynamic Client Registration (RFC 7591) options — item 4.3.
/// </summary>
public sealed class DcrOptions
{
    /// <summary>
    /// Master switch for the <c>/connect/register</c> endpoint. Default
    /// <c>false</c> (secure-by-default — DCR is an open-registration surface).
    /// </summary>
    public bool Enabled { get; init; } = false;

    /// <summary>
    /// When <c>true</c>, the <c>/connect/register</c> endpoint requires a
    /// valid initial access token (bearer) in the Authorization header. Default
    /// <c>true</c> — without it, anyone can register a client. The token is
    /// validated against <see cref="InitialAccessToken"/>; leave that empty to
    /// disable the endpoint entirely (Enabled must be true AND a token
    /// configured for DCR to actually accept requests).
    /// </summary>
    public bool RequireInitialAccessToken { get; init; } = true;

    /// <summary>
    /// The static initial access token accepted by <c>/connect/register</c>
    /// when <see cref="RequireInitialAccessToken"/> is true. Configure via User
    /// Secrets / env var in real environments — NEVER commit a real value.
    /// Empty = endpoint rejects all requests (even when Enabled).
    /// </summary>
    public string InitialAccessToken { get; init; } = "";

    /// <summary>
    /// Required expiry for the bootstrap credential when DCR is enabled.
    /// Provision a new credential/expiry for each registration ceremony.
    /// </summary>
    public DateTimeOffset? InitialAccessTokenExpiresAtUtc { get; init; }

    public bool InitialAccessTokenSingleUse { get; init; } = true;

    /// <summary>
    /// Deprecated migration adapters. Secure registrations use server-issued
    /// identifiers and one-time plaintext secrets.
    /// </summary>
    public bool AllowCallerSuppliedClientIds { get; init; } = true;

    public bool AllowCallerSuppliedSecrets { get; init; } = true;

    /// <summary>
    /// Grant types that a dynamically registered client may request. Defaults
    /// to the interactive OAuth 2.1 grants; privileged and legacy grants must
    /// be enabled deliberately.
    /// </summary>
    public HashSet<string> AllowedGrantTypes { get; init; } = new(StringComparer.Ordinal)
    {
        OpenIddict.Abstractions.OpenIddictConstants.GrantTypes.AuthorizationCode,
        OpenIddict.Abstractions.OpenIddictConstants.GrantTypes.RefreshToken,
    };

    /// <summary>
    /// Scopes that a dynamically registered client may request. Custom API or
    /// administrative scopes must be explicitly added by the operator.
    /// </summary>
    public HashSet<string> AllowedScopes { get; init; } = new(StringComparer.Ordinal)
    {
        OpenIddict.Abstractions.OpenIddictConstants.Scopes.OpenId,
        OpenIddict.Abstractions.OpenIddictConstants.Scopes.Profile,
        OpenIddict.Abstractions.OpenIddictConstants.Scopes.Email,
        OpenIddict.Abstractions.OpenIddictConstants.Scopes.OfflineAccess,
    };
}

/// <summary>
/// OAuth 2.1-aligned PKCE policy for authorization-code clients.
/// </summary>
public sealed class PkceOptions
{
    /// <summary>
    /// Require PKCE for every authorization-code request. Disable only during
    /// a controlled migration of confidential legacy clients.
    /// </summary>
    public bool RequireForAllClients { get; init; } = true;

    /// <summary>
    /// Permit the legacy <c>plain</c> challenge method. Disabled by default;
    /// clients must use <c>S256</c>.
    /// </summary>
    public bool AllowPlainCodeChallengeMethod { get; init; } = false;
}

/// <summary>
/// Pushed Authorization Request (PAR, RFC 9126) policy. The PAR endpoint
/// (<c>connect/par</c>) is always registered; these options control whether
/// PAR is *required* of all clients (defense in depth — protects
/// authorization requests from URL/tamper exposure) and the lifetime of the
/// resulting <c>request_uri</c> outside the FAPI 2.0 boundary.
/// </summary>
/// <remarks>
/// Per-client PAR requirement is enforced by OpenIddict's own
/// <c>Requirements.Features.PushedAuthorizationRequests</c> flag on the
/// application. Setting <see cref="RequireForAllClients"/> to true is the
/// global equivalent and supersedes the per-client flag for every client.
/// </remarks>
public sealed class ParOptions
{
    /// <summary>
    /// Require PAR for every authorization request. Default <c>false</c> to
    /// preserve backward compatibility with existing non-PAR clients; flip to
    /// <c>true</c> only once every client has been migrated to push its
    /// authorization request. When true, the <c>request_uri</c> parameter is
    /// the only way to start an authorization flow.
    /// </summary>
    public bool RequireForAllClients { get; init; } = false;

    /// <summary>
    /// Lifetime of a pushed <c>request_uri</c>, in seconds, for non-FAPI
    /// clients. Null (default) = OpenIddict's built-in default (60s). FAPI 2.0
    /// clients are governed separately by
    /// <see cref="Fapi2Options.PushedAuthorizationRequestLifetimeSeconds"/>
    /// (which must be &lt; 600s per the profile). Values here must be 1..599
    /// to match the RFC 9126 range.
    /// </summary>
    public int? RequestUriLifetimeSeconds { get; init; } = null;
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
    /// When enabled, active signing and encryption credentials must be
    /// different certificates. Disabled initially as a rollout gate.
    /// </summary>
    public bool RequirePurposeSeparation { get; init; } = false;

    /// <summary>
    /// Warn (or fail) when a configured certificate has less remaining
    /// lifetime than this rollout window.
    /// </summary>
    public int MinimumRemainingLifetimeDays { get; init; } = 30;

    /// <summary>
    /// When true, the expiry window is enforced at startup. False preserves
    /// availability while operators first deploy expiry telemetry.
    /// </summary>
    public bool FailOnExpiringCertificate { get; init; } = false;

    /// <summary>
    /// Filesystem path to the PFX file used to sign tokens (JWT signing key).
    /// Required in production.
    /// </summary>
    public string? SigningPath { get; init; }

    /// <summary>
    /// Ordered active/retiring signing certificates. The first unique entry is
    /// active; subsequent certificates remain published during overlap.
    /// </summary>
    public string[] SigningPaths { get; init; } = [];

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
    /// Ordered active/retiring encryption certificates. The first unique entry
    /// is active; subsequent certificates remain available during overlap.
    /// </summary>
    public string[] EncryptionPaths { get; init; } = [];

    /// <summary>
    /// Password protecting the encryption PFX file referenced by <see cref="EncryptionPath"/>.
    /// </summary>
    public string? EncryptionPassword { get; init; }
}

/// <summary>
/// Feature flags for legacy OAuth 2.0 grant types outside the current OAuth 2.1
/// draft baseline (Resource Owner Password Credentials and the "none"
/// grant/response type). OAuth 2.1 is still a draft, so Identity keeps these
/// compatibility switches instead of assuming that every consumer can migrate
/// immediately. Both default to <c>false</c> — secure-by-default
/// (EVALUATION-2026-07-21 §5 P0 #8). Environments that still need these grants
/// must opt-in explicitly via
/// <c>Sufficit:Identity:LegacyGrants:Password=true</c> and/or
/// <c>None=true</c> in the per-environment
/// <c>appsettings.&lt;env&gt;.json</c>, with telemetry and a migration/removal
/// decision recorded per client.
/// </summary>
public sealed class LegacyGrantsOptions
{
    /// <summary>
    /// Enables the Resource Owner Password Credentials grant
    /// (<c>grant_type=password</c>). It is outside the current OAuth 2.1 draft
    /// baseline, but remains available for existing consumers that still need
    /// compatibility. Default <c>false</c> — opt-in per environment only when
    /// a legacy client requires it, with telemetry and a migration decision.
    /// </summary>
    public bool Password { get; init; } = false;

    /// <summary>
    /// Enables the "none" grant/response type (implicit access_token without
    /// PKCE). It is outside the current OAuth 2.1 draft baseline, but remains
    /// available for existing consumers during migration. Default
    /// <c>false</c> — opt-in per environment only while migrating legacy
    /// WebForms/old-SwaggerUI clients to authorization_code + PKCE.
    /// </summary>
    public bool None { get; init; } = false;
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
    /// <c>identity.management</c> scope (or another configured scope).
    /// </summary>
    public bool RequireAuthorization { get; init; } = true;

    /// <summary>
    /// Required authorization policy/scope. Defaults to
    /// <c>identity.management</c>.
    /// </summary>
    public string RequiredScope { get; init; } = "identity.management";
}
