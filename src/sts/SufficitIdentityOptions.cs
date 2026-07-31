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

    /// <summary>
    /// Content Security Policy applied by the host to HTML responses (login,
    /// consent, device and logout pages served by the sibling UI). See
    /// <see cref="CspOptions"/>.
    /// </summary>
    public CspOptions Csp { get; init; } = new();

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
    /// WebAuthn/passkey resource limits and relying-party configuration.
    /// See <see cref="AccountPasskeyOptions"/>.
    /// </summary>
    public AccountPasskeyOptions Passkeys { get; init; } = new();

    /// <summary>
    /// Optional claim-type → required-scope map that gates which custom
    /// persisted claims (e.g. <c>directive</c>) reach the access token. See
    /// <see cref="ClaimScopeMapOptions"/>.
    /// </summary>
    public ClaimScopeMapOptions ClaimScopeMap { get; init; } = new();

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
    /// DPoP (RFC 9449) — sender-constrained access tokens. See
    /// <see cref="DpopOptions"/>.
    /// </summary>
    public DpopOptions Dpop { get; init; } = new();

    /// <summary>
    /// CIBA (Client-Initiated Backchannel Authentication, RFC 9126) —
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
/// Content Security Policy (CSP) baseline for the STS's interactive HTML
/// pages (login, consent, device verification, logout), served by the sibling
/// <c>sufficit-identity-ui</c> Blazor Server project. XSS on those pages is
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
/// load the sibling UI (see <c>SufficitIdentityTestFactory</c>). The tests here
/// assert that the header is emitted with the configured policy; they do not
/// validate the policy against the real rendered DOM.</para>
/// </remarks>
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
    /// The policy string. The default is tuned for a Blazor Server UI hosted
    /// same-origin with the STS: <c>connect-src</c> allows the SignalR WebSocket
    /// circuit; <c>style-src</c> allows <c>'unsafe-inline'</c> (Blazor/Bootstrap
    /// commonly require it — the calibration step should aim to remove it via
    /// nonces/hashes); <c>frame-ancestors 'none'</c> reinforces
    /// <c>X-Frame-Options: DENY</c>. Adjust per environment as needed.
    /// </summary>
    public string Policy { get; init; } =
        "default-src 'self'; " +
        "script-src 'self'; " +
        "style-src 'self' 'unsafe-inline'; " +
        "img-src 'self' data:; " +
        "connect-src 'self' wss: ws:; " +
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
    /// the public self-registration surface (gated separately in the sibling UI
    /// repo via <c>Sufficit:Identity:Register:Enabled</c>), this closes the
    /// "register with someone else's email and use the account" hole. Every
    /// grant in <c>AuthorizationController</c> collapses the unconfirmed-email
    /// case into the same generic <c>invalid_grant</c> as a wrong password, so
    /// this does NOT introduce user enumeration.
    /// </summary>
    /// <remarks>
    /// <b>Cross-repo dependency (external login).</b> Accounts created via an
    /// external provider (Google/GitHub/Facebook) in the sibling UI repo's
    /// <c>ExternalLoginController</c> are only marked <c>EmailConfirmed=true</c>
    /// when the provider asserts <c>email_verified</c>. The STS wires that
    /// <c>ClaimAction</c> for Google (<c>ServiceCollectionExtensions.
    /// AddExternalProviders</c>) but NOT yet for Facebook/GitHub. Flipping this
    /// to <c>true</c> in production therefore REQUIRES first ensuring every
    /// configured external provider emits (and the UI consumes) the
    /// <c>email_verified</c> claim — otherwise provider users get locked out.
    /// See <c>docs/runbook-require-confirmed-email.md</c> for the production
    /// rollout steps, including the legacy-user migration query.
    /// </remarks>
    public bool RequireConfirmedEmail { get; init; } = true;
}

/// <summary>
/// Config-driven claim-type → required-scope allowlist that closes the residual
/// over-disclosure gap (eval #10 / plan item 2.5 [M5]). When a claim type is
/// present in <see cref="ClaimToScope"/>, that claim reaches the access token
/// ONLY if the subject was granted the mapped scope. Claim types NOT in the map
/// keep the pre-existing behavior (routed to the access token unconditionally),
/// so the map ships EMPTY by default — behavior is byte-identical to before
/// until an operator deliberately adds an entry.
/// </summary>
/// <remarks>
/// <b>Rollout model.</b> Add entries one resource server at a time: first
/// confirm every RS that consumes a claim (e.g. <c>directive</c>) requests the
/// mapped scope (e.g. <c>directives</c>), THEN add <c>"directive":"directives"</c>
/// to the map. Adding an entry before the RS requests the scope silently strips
/// the claim from that RS's tokens. The relevant scopes (<c>directives</c>,
/// <c>policies</c>) are already registered in <c>RegisterScopes</c>.
/// </remarks>
public sealed class ClaimScopeMapOptions
{
    /// <summary>
    /// Map of claim type → scope name. When the access token is being built, a
    /// claim whose type matches a key here is included ONLY if the subject's
    /// granted scopes contain the value. Example:
    /// <code>{ "directive": "directives", "policies": "policies" }</code>.
    /// Default empty (retrocompatible — no behavior change).
    /// </summary>
    public Dictionary<string, string> ClaimToScope { get; init; } = new(StringComparer.Ordinal);
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
/// <b>Opt-in (default <see cref="Enabled"/>=<c>false</c>).</b> Back-channel
/// logout only does something useful once RPs register a
/// <c>backchannel_logout_uri</c> on their client. Until then it is a no-op, so
/// it is left off by default to avoid advertising a capability the deployment
/// may not be consuming yet.
/// </remarks>
public sealed class BackchannelLogoutOptions
{
    /// <summary>
    /// Master switch. When <c>true</c>, the STS distributes a
    /// <c>logout_token</c> to every RP with an active authorization on user
    /// sign-out, and advertises <c>backchannel_logout_supported=true</c> in
    /// discovery. Default <c>false</c>.
    /// </summary>
    public bool Enabled { get; init; } = false;
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
/// CIBA (Client-Initiated Backchannel Authentication, RFC 9126 — item 3.5).
/// Enables decoupled authentication: a client initiates auth on a consumption
/// device (kiosk, call-center, AI agent) and the end user approves on a
/// SEPARATE authentication device. The client polls the token endpoint with an
/// <c>auth_req_id</c> until the user approves (or denies, or it expires).
/// </summary>
/// <remarks>
/// <b>Implemented from scratch</b> — OpenIddict 7.6 has no CIBA support
/// (verified: zero "ciba"/"bc-authorize"/"auth_req_id" strings in any
/// assembly). The pending <c>auth_req_id</c> is stored as an OpenIddict token
/// (via <c>IOpenIddictTokenManager</c>, the same primitive the device flow
/// uses), and the poll loop reuses the device-code grant's
/// <c>authorization_pending</c>/<c>SignIn</c> pattern. The completion channel
/// (<c>CibaController.Complete</c>) attaches a principal to the pending
/// <c>auth_req_id</c> exactly as <c>DeviceController.Verify</c> does for a
/// device_code. Portable: depends only on OpenIddict's public manager
/// interfaces, not on internals.
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
    /// Default 600 (10 min) — RFC 9126 §2.2 <c>expires_in</c>.
    /// </summary>
    public int ExpiresInSeconds { get; init; } = 600;

    /// <summary>
    /// Minimum seconds the client MUST wait between polls. RFC 9126 §2.2
    /// <c>interval</c>. If the client polls faster, the AS returns
    /// <c>slow_down</c>. Default 5.
    /// </summary>
    public int PollIntervalSeconds { get; init; } = 5;
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
    /// <c>https://mcp.sufficit.com.br</c>). Empty by default.
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
/// Both default to <c>false</c> — secure-by-default (EVALUATION-2026-07-21 §5
/// P0 #8). Environments that still need these grants during the migration
/// must opt-in explicitly via <c>Sufficit:Identity:LegacyGrants:Password=true</c>
/// and/or <c>None=true</c> in the per-environment <c>appsettings.&lt;env&gt;.json</c>.
/// This forces conscious opt-in instead of ship-a-insecure.
/// </summary>
public sealed class LegacyGrantsOptions
{
    /// <summary>
    /// Enables the Resource Owner Password Credentials grant
    /// (<c>grant_type=password</c>). Removed by OAuth 2.1. Default
    /// <c>false</c> — opt-in per environment if a legacy client still
    /// requires it (with telemetry and a removal date).
    /// </summary>
    public bool Password { get; init; } = false;

    /// <summary>
    /// Enables the "none" grant/response type (implicit access_token without
    /// PKCE). Removed by OAuth 2.1. Default <c>false</c> — opt-in per
    /// environment only while migrating legacy WebForms/old-SwaggerUI clients
    /// to authorization_code + PKCE.
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
