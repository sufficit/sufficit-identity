using System.Security.Claims;

namespace Sufficit.Identity.STS.Security;

/// <summary>
/// Centralizes the interpretation of the OIDC <c>amr</c> claim for sensitive
/// STS operations. Claims may arrive either as multiple values or as one
/// space-delimited value after token validation.
/// </summary>
internal static class MfaEvidence
{
    private static readonly HashSet<string> MfaMethods = new(StringComparer.Ordinal)
    {
        "mfa", "otp", "hwk", "sms", "vcm", "fpt", "eye", "voice", "retina"
    };

    public static bool HasMfaEvidence(ClaimsPrincipal principal) =>
        principal.FindAll("amr")
            .SelectMany(claim => claim.Value.Split(
                ' ',
                StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            .Any(MfaMethods.Contains);
}
