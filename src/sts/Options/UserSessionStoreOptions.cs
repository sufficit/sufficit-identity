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
}
