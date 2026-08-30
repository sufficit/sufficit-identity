using Sufficit.Identity.Application.Security;

namespace Sufficit.Identity.STS;

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
    /// Requests allowed per window and source IP on the administrative
    /// surfaces (management API and SCIM), which were previously unthrottled
    /// altogether.
    /// </summary>
    /// <remarks>
    /// Deliberately generous. These endpoints are not consumed by the
    /// management UI — that is Blazor Server and calls its services through DI
    /// — so the traffic here is automation: provisioning scripts, migration
    /// tools, SCIM synchronisation. A script creating two hundred clients one
    /// call at a time is doing exactly what it should, and throttling it would
    /// be a bug, not a defence. The purpose of this bucket is to bound a
    /// runaway loop, not to pace legitimate bulk work.
    /// </remarks>
    public int AdministrativePermitLimit { get; init; } = 600;

    public int AdministrativeWindowSeconds { get; init; } = 60;

    /// <summary>
    /// Whole-collection operations (provisioning manifest apply/preview/
    /// inventory, revoking every session of a user) allowed per window and
    /// source IP.
    /// </summary>
    /// <remarks>
    /// A separate, smaller bucket: one of these requests can rewrite every
    /// client and scope a manifest declares, so the meaningful limit is on how
    /// often that is attempted rather than on request volume. Keeping it apart
    /// from <see cref="AdministrativePermitLimit"/> is what lets both coexist
    /// — a provisioning run cannot exhaust the budget for ordinary calls, and
    /// a chatty tool cannot block a manifest apply.
    /// </remarks>
    public int AdministrativeBulkPermitLimit { get; init; } = 30;

    public int AdministrativeBulkWindowSeconds { get; init; } = 60;

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
