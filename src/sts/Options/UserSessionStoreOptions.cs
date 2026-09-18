using Sufficit.Identity.Application.Security;

namespace Sufficit.Identity.STS;

public sealed class UserSessionStoreOptions
{
    /// <summary>
    /// Lifetime of an interactive Identity session. Persistent browser cookies
    /// use this value directly; session cookies remain browser-scoped but their
    /// server-side ticket cannot outlive this boundary.
    /// </summary>
    public int AuthenticationLifetimeDays { get; init; } = 30;

    /// <summary>
    /// Lifetime of the trusted-device cookie created when the user chooses to
    /// remember MFA on this device.
    /// </summary>
    public int RememberedMfaLifetimeDays { get; init; } = 30;

    /// <summary>
    /// Renews active authentication and trusted-device cookies after half of
    /// their lifetime has elapsed, without extending abandoned sessions.
    /// </summary>
    public bool SlidingExpiration { get; init; } = true;

    /// <summary>
    /// Shared-cache lifetime for protected server-side cookie tickets. Short
    /// enough to bound stale outage behavior; explicit revocation invalidates
    /// the entry immediately.
    /// </summary>
    public int CacheLifetimeSeconds { get; init; } = 60;

    /// <summary>
    /// Maximum time an optional shared-cache operation may delay an
    /// interactive browser-session request. The durable database remains the
    /// source of truth, so reads fall back to it and writes keep the persisted
    /// session when this timeout expires.
    /// </summary>
    public int CacheOperationTimeoutMilliseconds { get; init; } = 250;

    /// <summary>Minimum interval between durable activity updates.</summary>
    public int ActivityUpdateIntervalSeconds { get; init; } = 300;

    /// <summary>
    /// Maximum age of the cookie principal before it is rebuilt from the
    /// store and the server-side ticket renewed. The security stamp is still
    /// checked on every request, and any change to the user row forces an
    /// earlier refresh. Zero rebuilds on every request. Clamped to 0..3600.
    /// </summary>
    public int PrincipalRefreshIntervalSeconds { get; init; } = 300;

    /// <summary>
    /// How long a session may be trusted without reading the user's security
    /// stamp again, when a change notification channel is connected.
    /// </summary>
    /// <remarks>
    /// Zero — the default — keeps the stamp read on every request, which is
    /// what the server has always done. A positive value only takes effect
    /// while <c>IUserSecurityChangePublisher</c> reports a connected channel,
    /// so a node that cannot hear about a revocation on another node never
    /// skips the read. The value bounds how long a lost notification can keep
    /// a revoked session alive on one node. Clamped to 0..300.
    /// </remarks>
    public int ValidityCacheSeconds { get; init; } = 0;
}
