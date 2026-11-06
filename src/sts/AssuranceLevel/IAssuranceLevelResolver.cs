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
/// Provider assurance mapping: MFA evidence is required above Loa1. The
/// strongest level additionally requires a WebAuthn-family method; hardware
/// possession, biometrics or geolocation alone do not establish that level.
/// This is a local policy, not a mapping specified by RFC 8176.
/// </summary>
internal sealed class AmrBasedAssuranceLevelResolver : IAssuranceLevelResolver
{
    private static readonly HashSet<string> WebAuthnMethods =
        new(StringComparer.Ordinal) { "passkey", "fido", "webauthn" };

    public CaepAssuranceLevel Resolve(ClaimsPrincipal principal)
    {
        ArgumentNullException.ThrowIfNull(principal);
        var methods = principal.FindAll("amr")
            .SelectMany(claim => claim.Value.Split(' ',
                StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            .ToHashSet(StringComparer.Ordinal);
        var derived = !MfaEvidencePolicy.HasMfaEvidence(principal)
            ? CaepAssuranceLevel.Loa1
            : methods.Overlaps(WebAuthnMethods)
                ? CaepAssuranceLevel.PhishingResistant
                : CaepAssuranceLevel.Loa2;

        // Preserve a conservative historical stamp, but never let a stale or
        // numeric/undefined value promote the current authentication evidence.
        if (Enum.TryParse<CaepAssuranceLevel>(principal.FindFirst("aal")?.Value,
                ignoreCase: false, out var stamped)
            && Enum.IsDefined(stamped) && stamped < derived)
            return stamped;
        return derived;
    }
}
