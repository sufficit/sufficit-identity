using System.Security.Claims;

namespace Sufficit.Identity.Application.Security;

/// <summary>
/// The one reading of what an <c>amr</c> claim proves, and of whether that
/// proof was produced now or remembered from a previous ceremony.
/// </summary>
/// <remarks>
/// A trusted-device cookie lets a user skip the second factor on a browser
/// that already completed one, and the sign-in projects <c>amr=mfa</c> from it
/// so the operator is not challenged again on every Management page
/// (<c>9957d6d</c>, 2026-08-14 — a deliberate product decision).
///
/// Minting a credential is different from using a session. A token outlives
/// the browser that asked for it, so the second factor behind it must have
/// happened, not have been remembered from up to thirty days ago. Callers that
/// issue a token ask for <see cref="HasFreshMfaEvidence"/>; everything else
/// asks for <see cref="HasMfaEvidence"/>.
/// </remarks>
public static class MfaEvidencePolicy
{
    /// <summary>
    /// Marks a principal whose second factor came from a remembered device
    /// rather than from a ceremony in this sign-in.
    /// </summary>
    public const string RememberedSecondFactorClaimType = "identity:mfa_remembered";

    public const string AuthenticationMethodClaimType = "amr";

    private static readonly HashSet<string> PasswordComplementMethods = new(StringComparer.Ordinal)
    {
        "otp", "hwk", "sms", "vcm", "fpt", "eye", "voice", "retina",
    };

    /// <summary>
    /// Requires an explicit MFA assertion or password plus a recognized
    /// possession/biometric method. A method alone (including hwk or otp)
    /// does not prove multiple factors; duplicate possession methods do not
    /// constitute two factors either. Other combinations require explicit mfa.
    /// </summary>
    public static bool HasMfaEvidence(ClaimsPrincipal principal)
    {
        ArgumentNullException.ThrowIfNull(principal);
        var methods = principal.FindAll(AuthenticationMethodClaimType)
            .SelectMany(Split)
            .ToHashSet(StringComparer.Ordinal);
        return methods.Contains("mfa")
            || (methods.Contains("pwd") && methods.Overlaps(PasswordComplementMethods));
    }

    /// <summary>
    /// The second factor was presented in this sign-in, not carried over by a
    /// trusted-device cookie.
    /// </summary>
    public static bool HasFreshMfaEvidence(ClaimsPrincipal principal) =>
        HasMfaEvidence(principal) && !IsSecondFactorRemembered(principal);

    public static bool IsSecondFactorRemembered(ClaimsPrincipal principal)
    {
        ArgumentNullException.ThrowIfNull(principal);
        return principal.FindAll(RememberedSecondFactorClaimType)
            .Any(claim => string.Equals(claim.Value, "true", StringComparison.Ordinal));
    }

    private static IEnumerable<string> Split(Claim claim) =>
        claim.Value.Split(
            ' ',
            StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
}
