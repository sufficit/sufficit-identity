namespace Sufficit.Identity.STS;

/// <summary>
/// Policy for external identity providers that are allowed to bootstrap local
/// accounts (<c>Sufficit:Identity:ExternalIdentities</c>).
/// </summary>
/// <remarks>
/// No provider is named in code. Which providers exist, and which of them a
/// deployment is willing to believe about email ownership, is configuration —
/// the same binary serves a deployment federating consumer providers and one
/// federating a corporate IdP it operates itself.
/// </remarks>
public sealed class ExternalIdentityOptions
{
    /// <summary>
    /// Require proof of control over the email address before an external
    /// identity may create and bind a local account.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Default <see langword="true"/>, and it should stay that way. Turning it
    /// off restores account pre-hijacking: an attacker who registers the
    /// victim's address at a provider that does not verify addresses gets a
    /// local account bound to their external identity, and keeps that binding
    /// after the victim proves the address through registration recovery or a
    /// confirmation resend.
    /// </para>
    /// <para>
    /// A provider that asserts <c>email_verified</c> satisfies this without any
    /// extra round trip; the verification step only engages when nothing proves
    /// the address.
    /// </para>
    /// </remarks>
    public bool RequireVerifiedEmail { get; init; } = true;

    /// <summary>
    /// Authentication scheme names whose email assertions are trusted even when
    /// the provider emits no <c>email_verified</c> claim.
    /// </summary>
    /// <remarks>
    /// This is an explicit operator decision about a specific provider, not a
    /// blanket switch: a deployment whose IdP verifies addresses out of band but
    /// does not map the claim can list it here and keep the protection for every
    /// other provider. Empty by default.
    /// </remarks>
    public HashSet<string> TrustedEmailProviders { get; init; } =
        new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Authentication scheme names that may authenticate an already-linked
    /// account but may never bootstrap a new one.
    /// </summary>
    public HashSet<string> RegistrationDeniedProviders { get; init; } =
        new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// How long a pending external link stays redeemable, in minutes.
    /// </summary>
    /// <remarks>
    /// Short by design. The ticket authorizes creating an account bound to an
    /// external identity, so its window is the window in which a leaked message
    /// is useful. Clamped to 5..1440 when read.
    /// </remarks>
    public int VerificationLifetimeMinutes { get; init; } = 30;
}
