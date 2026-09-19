using System.Security.Claims;

namespace Sufficit.Identity.STS.Security;

/// <summary>
/// Centralizes the interpretation of the OIDC <c>amr</c> claim for sensitive
/// STS operations. Claims may arrive either as multiple values or as one
/// space-delimited value after token validation.
/// </summary>
/// <remarks>
/// The method list and the reading of <c>amr</c> now live in
/// <see cref="Sufficit.Identity.Application.Security.MfaEvidencePolicy"/>, so
/// the STS and Management cannot drift into two answers. This stays as the
/// STS-local name its callers already use.
/// </remarks>
internal static class MfaEvidence
{
    public static bool HasMfaEvidence(ClaimsPrincipal principal) =>
        Sufficit.Identity.Application.Security.MfaEvidencePolicy
            .HasMfaEvidence(principal);
}
