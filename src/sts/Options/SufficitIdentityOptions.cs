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
    /// Controls publication of the OpenAPI document and Swagger UI.
    /// See <see cref="SwaggerOptions"/>.
    /// </summary>
    public SwaggerOptions Swagger { get; init; } = new();

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
    /// Persisted claims granted when a user approves an application scope.
    /// Grants are idempotent and become visible in the token being approved.
    /// </summary>
    public ScopeEntitlementOptions ScopeEntitlements { get; init; } = new();

    /// <summary>
    /// Additional product scopes this deployment serves, registered with
    /// OpenIddict and advertised in the protected-resource metadata alongside
    /// the standard OIDC scopes.
    /// </summary>
    /// <remarks>
    /// Empty by default (eval 2026-08-30, F-2): product scope names are
    /// deployment configuration, not built-ins of a vendor-neutral STS. The
    /// scopes implied by <see cref="ScopeEntitlements"/> are registered
    /// automatically, so a scope only needs to be listed here when it grants no
    /// entitlement claim of its own. Declare under
    /// <c>Sufficit:Identity:ApplicationScopes</c>.
    /// </remarks>
    public string[] ApplicationScopes { get; init; } = [];

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
