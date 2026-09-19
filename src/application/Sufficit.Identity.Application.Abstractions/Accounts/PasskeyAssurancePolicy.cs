namespace Sufficit.Identity.Application.Accounts;

/// <summary>
/// What a completed WebAuthn assertion actually proved.
/// </summary>
/// <param name="UserPresent">
/// The authenticator reported a user gesture (WebAuthn UP flag). Always true
/// for a ceremony the browser completed.
/// </param>
/// <param name="UserVerified">
/// The authenticator reported that it verified the user itself — a PIN, a
/// fingerprint, a face (WebAuthn UV flag). This is the difference between
/// "someone holding the key" and "the account owner".
/// </param>
public readonly record struct PasskeyAssertionEvidence(
    bool UserPresent,
    bool UserVerified);

/// <summary>
/// Decides what a passkey ceremony is allowed to claim.
/// </summary>
/// <remarks>
/// A passkey is phishing-resistant by construction, which is a property of the
/// protocol. Whether it is a <em>second factor</em> is a property of the
/// ceremony: an authenticator that only checked that somebody touched it has
/// proven possession and nothing else. Asserting <c>amr=mfa</c> on the strength
/// of possession alone tells every downstream policy that a second factor was
/// presented when none was, which is exactly the claim step-up enforcement
/// trusts.
/// </remarks>
public interface IPasskeyAssurancePolicy
{
    /// <summary>
    /// The WebAuthn <c>userVerification</c> value to request, so the ceremony
    /// is asked to produce the evidence this policy wants to rely on.
    /// </summary>
    string UserVerificationRequirement { get; }

    /// <summary>
    /// Whether an assertion without user verification is refused outright.
    /// </summary>
    bool RequireUserVerification { get; }

    /// <summary>
    /// Reads what the authenticator reported from a serialized WebAuthn
    /// credential. Returns <see langword="null"/> when the payload cannot be
    /// read at all — the caller decides what an unreadable assertion means.
    /// </summary>
    PasskeyAssertionEvidence? Read(string credentialJson);

    /// <summary>
    /// The authentication methods a ceremony with this evidence may claim.
    /// </summary>
    IReadOnlyCollection<string> AuthenticationMethods(
        PasskeyAssertionEvidence evidence);
}
