using Sufficit.Identity.Application.Security;

namespace Sufficit.Identity.STS;

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
