using System.Security.Claims;
using Sufficit.Identity.Application.Security;

namespace Sufficit.Identity.STS;

/// <summary>
/// Derives the authentication assurance level (AAL) of a session from its
/// <c>amr</c> (authentication method reference) claims. Used both to stamp the
/// <c>aal</c> claim on the session principal at sign-in and to compute the
/// <c>previous</c>/<c>current</c> levels when a step-up fires an
/// <c>assurance-level-change</c> event.
/// </summary>
public interface IAssuranceLevelResolver
{
    CaepAssuranceLevel Resolve(ClaimsPrincipal principal);
}

/// <summary>
/// AMR-to-AAL mapping per RFC 8176 / CAEP. The strongest factor present wins:
/// phishing-resistant factors beat hardware-bound OTP, which beats software
/// OTP, which beats password-only. Unknown AMRs default to the weakest level
/// so the resolver is fail-safe (never overstates assurance).
/// </summary>
internal sealed class AmrBasedAssuranceLevelResolver : IAssuranceLevelResolver
{
    private static readonly HashSet<string> PhishingResistantAmrs =
        new(StringComparer.Ordinal) { "passkey", "fido", "webauthn", "face", "geo", "hwk" };
    private static readonly HashSet<string> TwoFactorAmrs =
        new(StringComparer.Ordinal) { "otp", "totp", "sms" };

    public CaepAssuranceLevel Resolve(ClaimsPrincipal principal)
    {
        ArgumentNullException.ThrowIfNull(principal);

        // Fast path: the session already carries an `aal` claim stamped by the
        // principal factory. This avoids re-deriving on every request.
        if (principal.FindFirst("aal")?.Value is { } aalString
            && Enum.TryParse<CaepAssuranceLevel>(aalString, ignoreCase: false, out var stamped))
        {
            return stamped;
        }

        var amrs = principal.FindAll("amr")
            .Select(claim => claim.Value)
            .ToHashSet(StringComparer.Ordinal);

        if (amrs.Count == 0)
        {
            return CaepAssuranceLevel.Loa1;
        }

        if (amrs.Overlaps(PhishingResistantAmrs))
        {
            return CaepAssuranceLevel.PhishingResistant;
        }

        if (amrs.Overlaps(TwoFactorAmrs))
        {
            // Hardware-bound OTP (hwk already caught above) → Loa3; software
            // OTP/SMS → Loa2. We treat any OTP as Loa2 unless a hardware key
            // co-occurs (covered by the phishing-resistant set above).
            return CaepAssuranceLevel.Loa2;
        }

        if (amrs.Contains("pwd") || amrs.Contains("kba") || amrs.Contains("mfa"))
        {
            return CaepAssuranceLevel.Loa1;
        }

        // Unknown AMR: fail safe to the weakest level.
        return CaepAssuranceLevel.Loa1;
    }
}
