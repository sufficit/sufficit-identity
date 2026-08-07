using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Sufficit.Identity.STS.Consent;

internal enum AuthorizationConsentRequirement
{
    None,
    Interactive,
    ExistingAuthorization,
}

/// <summary>
/// Produces the authorization endpoint's consent requirement from persisted
/// client metadata. Unknown legacy values deliberately require interaction:
/// they remain usable while never becoming an implicit authorization grant.
/// </summary>
internal static class AuthorizationConsentPolicy
{
    public static AuthorizationConsentRequirement Evaluate(
        string? consentType,
        bool hasExistingAuthorization,
        bool forcesReconsent)
        => consentType switch
        {
            ConsentTypes.Implicit => AuthorizationConsentRequirement.None,
            ConsentTypes.Explicit =>
                !hasExistingAuthorization || forcesReconsent
                    ? AuthorizationConsentRequirement.Interactive
                    : AuthorizationConsentRequirement.None,
            ConsentTypes.Systematic => AuthorizationConsentRequirement.Interactive,
            ConsentTypes.External =>
                hasExistingAuthorization
                    ? AuthorizationConsentRequirement.None
                    : AuthorizationConsentRequirement.ExistingAuthorization,
            _ => AuthorizationConsentRequirement.Interactive,
        };
}
