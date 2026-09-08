using Sufficit.Identity.Application.Security;

namespace Sufficit.Identity.STS;

/// <summary>
/// Least-privilege policy for issuing personal access tokens. Enforce is the
/// secure default; Observe remains available only as an explicit, posture-
/// checked migration mode.
/// </summary>
public sealed class PersonalTokenIssuanceOptions
{
    public SecurityPolicyEnforcementMode Mode { get; init; } =
        SecurityPolicyEnforcementMode.Enforce;

    public string RequiredScope { get; init; } = "personal.tokens.manage";

    /// <summary>Clients explicitly authorized to request the self-service scope.
    /// Startup provisions their scope permission, without granting administrator roles.
    /// Empty by default; deployments select their trusted clients.</summary>
    public HashSet<string> ScopeClientIds { get; init; } = new(StringComparer.Ordinal);

    /// <summary>
    /// Requires MFA evidence in the caller's <c>amr</c> claim before issuing
    /// a new personal token. Personal tokens are durable credentials, so a
    /// recent password-only authentication is not sufficient.
    /// </summary>
    public bool RequireMfa { get; init; } = true;

    public bool RequireRecentAuthentication { get; init; } = true;

    public int MaximumAuthenticationAgeMinutes { get; init; } = 15;

    public int MaximumLifetimeDays { get; init; } = 90;

    public bool RequireSenderConstraint { get; init; }

    public HashSet<string> EligibleClientIds { get; init; } = new(StringComparer.Ordinal);
}
