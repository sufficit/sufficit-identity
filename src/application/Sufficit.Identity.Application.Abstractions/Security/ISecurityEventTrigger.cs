namespace Sufficit.Identity.Application.Security;

/// <summary>
/// The kind of credential a <see cref="CaepCredentialChange"/> event refers to.
/// Values align with the <c>credential_type</c> vocabulary defined by CAEP
/// (OpenID Continuous Access Evaluation Profile 1.0), §3.3.1.
/// </summary>
public enum CaepCredentialType
{
    /// <summary>
    /// A long-term shared secret known to the user and the credential
    /// service provider (a password). Maps to the CAEP <c>password</c> value.
    /// </summary>
    Password,

    /// <summary>
    /// A one-time-password second factor (TOTP authenticator app). Maps to
    /// the CAEP <c>otp</c> value.
    /// </summary>
    Otp,

    /// <summary>
    /// A federated (social/enterprise IdP) credential. Maps to the CAEP
    /// <c>federated</c> value; the provider is carried in
    /// <see cref="CaepCredentialChange.FederatedType"/>.
    /// </summary>
    Federated,

    /// <summary>
    /// A phishing-resistant public-key credential (WebAuthn / FIDO2 passkey).
    /// Maps to the CAEP <c>passkey</c> value.
    /// </summary>
    Passkey,

    /// <summary>
    /// A privilege/authorization grant (role, claim or scope assignment) that
    /// affects what the subject can do. Not a CAEP-defined credential_type;
    /// emitted under the CAEP <c>credential-change</c> event with a Sufficit
    /// local value so downstream receivers can react to privilege changes.
    /// </summary>
    Privilege,
}

/// <summary>
/// The change operation a credential/device event describes. Mirrors the CAEP
/// <c>change_type</c> vocabulary (create / update / delete).
/// </summary>
public enum CaepChangeOperation
{
    Created,
    Updated,
    Deleted,
}

/// <summary>
/// Payload of a CAEP <c>credential-change</c> event. Captured at the
/// credential-mutation call site and translated by the SSF transmitter into a
/// signed SET.
/// </summary>
public sealed record CaepCredentialChange(
    CaepCredentialType CredentialType,
    CaepChangeOperation Operation,
    string? FederatedType = null)
{
    /// <summary>
    /// The federated provider identifier (e.g. <c>Google</c>, <c>GitHub</c>)
    /// when <see cref="CredentialType"/> is <see cref="CaepCredentialType.Federated"/>; otherwise null.
    /// </summary>
    public string? FederatedType { get; init; } = FederatedType;
}

/// <summary>
/// Payload of a CAEP <c>device-change</c> event, used for WebAuthn
/// credentials that bind a physical device to the account.
/// </summary>
public sealed record CaepDeviceChange(
    CaepChangeOperation Operation,
    string? CredentialId = null,
    string? Description = null);

/// <summary>
/// Provider-neutral hook through which the account, management and SCIM
/// surfaces notify the SSF/CAEP transmitter that a security-relevant
/// credential or device change just occurred.
/// </summary>
/// <remarks>
/// Implementations MUST be safe to call from inside a request pipeline and
/// MUST NOT throw on delivery failure — security event delivery is best-effort
/// by design and must never undo an already-completed business operation
/// (mirrors the back-channel logout distribution contract). The null
/// implementation (used when SSF is disabled) is a pure no-op.
/// <para>
/// The <paramref name="sessionId"/> argument is the OIDC <c>sid</c> when the
/// change happened in the context of an authenticated session (self-service
/// flows); administrative / provisioning flows pass null and the emitted SET
/// carries an <c>iss_sub</c> subject identifier only.
/// </para>
/// </remarks>
public interface ISecurityEventTrigger
{
    /// <summary>
    /// Notify receivers that a credential (password, OTP/MFA factor, passkey,
    /// federated identity or privilege) was created, updated or deleted.
    /// </summary>
    Task CredentialChangedAsync(
        string subject,
        string? sessionId,
        CaepCredentialChange change,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Notify receivers that a device-bound credential (passkey) was added to
    /// or removed from the account.
    /// </summary>
    Task DeviceChangedAsync(
        string subject,
        string? sessionId,
        CaepDeviceChange change,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Notify receivers that the authentication assurance level (AAL) of the
    /// subject's session just changed (CAEP <c>assurance-level-change</c>).
    /// Typical trigger: a step-up from password-only (Loa1) to 2FA (Loa2) or
    /// phishing-resistant passkey sign-in.
    /// </summary>
    Task AssuranceLevelChangedAsync(
        string subject,
        string? sessionId,
        CaepAssuranceLevelChange change,
        CancellationToken cancellationToken = default);
}
