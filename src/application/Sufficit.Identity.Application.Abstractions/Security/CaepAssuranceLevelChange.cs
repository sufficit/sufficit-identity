namespace Sufficit.Identity.Application.Security;

/// <summary>
/// The authentication assurance level (AAL) of a session, used by the CAEP
/// <c>assurance-level-change</c> event (CAEP 1.0 §3.3.4). The enum values map
/// to CAEP <c>level</c>/<c>loa</c> strings via <see cref="Sufficit.Identity.STS.SharedSignals.CaepEventGenerator"/>.
/// </summary>
public enum CaepAssuranceLevel
{
    /// <summary>
    /// Single-factor (e.g. password-only) authentication. Maps to CAEP
    /// <c>level=normal</c> / <c>loa=loa1</c>.
    /// </summary>
    Loa1,

    /// <summary>
    /// Two-factor authentication (password + OTP). Maps to
    /// <c>level=loa2</c>.
    /// </summary>
    Loa2,

    /// <summary>
    /// High-assurance two-factor (password + hardware key). Maps to
    /// <c>level=loa3</c>.
    /// </summary>
    Loa3,

    /// <summary>
    /// Phishing-resistant authentication (WebAuthn/passkey, FIDO2).
    /// Maps to <c>level=phishing-resistant</c>.
    /// </summary>
    PhishingResistant,
}

/// <summary>
/// Payload of a CAEP <c>assurance-level-change</c> event. Carries the new and
/// (when known) previous assurance level of the session.
/// </summary>
public sealed record CaepAssuranceLevelChange(
    CaepAssuranceLevel CurrentLevel,
    CaepAssuranceLevel? PreviousLevel = null)
{
    /// <summary>
    /// Optional explicit LOA (level of assurance) value for the new state.
    /// When null, the transmitter derives a sensible LOA from
    /// <see cref="CurrentLevel"/>.
    /// </summary>
    public CaepAssuranceLevel? CurrentLoa { get; init; }

    /// <summary>
    /// Optional explicit LOA value for the previous state.
    /// </summary>
    public CaepAssuranceLevel? PreviousLoa { get; init; }
}
