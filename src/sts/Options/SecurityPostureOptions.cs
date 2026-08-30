using Sufficit.Identity.Application.Security;

namespace Sufficit.Identity.STS;

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
public enum SecurityPolicyEnforcementMode
{
    Observe,
    Enforce,
}
