using System.Globalization;
using System.Security.Claims;
using OpenIddict.Abstractions;
using Sufficit.Identity.Application.Security;

namespace Sufficit.Identity.STS;

/// <summary>
/// Evaluates the OIDC max_age and prompt=login contracts against the time at
/// which the user actually authenticated. Token issue/refresh time is
/// intentionally ignored.
/// </summary>
internal static class AuthorizationReauthenticationPolicy
{
    private static readonly TimeSpan FutureClockTolerance = TimeSpan.FromMinutes(1);

    /// <summary>
    /// The strongest level the request asks for, ignoring values this server
    /// does not recognise.
    /// </summary>
    private static CaepAssuranceLevel? RequestedAssuranceLevel(
        OpenIddictRequest request,
        IAuthenticationContextClassMapper authenticationContextClasses)
    {
        if (string.IsNullOrWhiteSpace(request.AcrValues))
        {
            return null;
        }

        CaepAssuranceLevel? strongest = null;
        foreach (var value in request.AcrValues.Split(
            ' ',
            StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (authenticationContextClasses.Parse(value) is { } level
                && (strongest is null || level > strongest))
            {
                strongest = level;
            }
        }

        return strongest;
    }

    /// <summary>
    /// What the session has. Missing or unreadable is the floor, which is what
    /// an unauthenticated principal would also be.
    /// </summary>
    private static CaepAssuranceLevel CurrentAssuranceLevel(
        ClaimsPrincipal principal) =>
        Enum.TryParse<CaepAssuranceLevel>(
            principal.FindFirst(
                OidcSessionClaimsPrincipalFactory.AssuranceLevelClaimType)?.Value,
            ignoreCase: false,
            out var level)
            ? level
            : CaepAssuranceLevel.Loa1;

    public static bool IsRequired(
        OpenIddictRequest request,
        ClaimsPrincipal principal,
        DateTimeOffset now,
        IAuthenticationContextClassMapper authenticationContextClasses)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(principal);
        ArgumentNullException.ThrowIfNull(authenticationContextClasses);

        // acr_values asks for an assurance level (OIDC Core 3.1.2.1). It is a
        // voluntary request, so an unrecognised value is ignored and a level
        // the ceremony cannot reach is not an error — the attempt is made once
        // and the token then tells the truth about what happened. The receipt
        // is what bounds it to one attempt.
        if (RequestedAssuranceLevel(request, authenticationContextClasses)
                is { } requested
            && CurrentAssuranceLevel(principal) < requested)
        {
            return true;
        }

        // A second factor carried by a trusted-device cookie does not mint
        // tokens (owner's decision, 2026-09-20). The ceremony runs here,
        // before the token exists, rather than leaving the relying party to
        // discover an insufficient one: an app that checks amr and redirects
        // without prompt=login would otherwise get the same session and the
        // same token forever. The ceremony signs the remembered cookie out and
        // asks for the factor, so the session that returns is fresh and the
        // next pass through here does nothing.
        if (MfaEvidencePolicy.IsSecondFactorRemembered(principal))
        {
            return true;
        }

        // prompt=login requires the OP to reauthenticate the end user however
        // recent the session is (OIDC Core 3.1.2.1); the conformance suite
        // checks it by comparing auth_time across two authorizations
        // (oidcc-prompt-login). Like max_age=0, the ceremony that satisfies it
        // is recognized by the controller through the authentication receipt.
        if (request.HasPromptValue(OpenIddictConstants.PromptValues.Login))
        {
            return true;
        }

        if (request.MaxAge is not { } maximumAgeSeconds)
        {
            return false;
        }

        // Every new max_age=0 request needs a ceremony, even in the same second.
        // Its authenticated continuation is checked separately by the controller.
        if (maximumAgeSeconds == 0) return true;

        var value = principal.FindFirst(
            AuthenticationContextProjector.AuthenticationTimeClaimType)?.Value;
        if (!long.TryParse(
                value,
                NumberStyles.Integer,
                CultureInfo.InvariantCulture,
                out var unixSeconds))
        {
            return true;
        }

        try
        {
            var authenticatedAt = DateTimeOffset.FromUnixTimeSeconds(unixSeconds);
            if (authenticatedAt > now + FutureClockTolerance)
            {
                return true;
            }

            var maximumAge = TimeSpan.FromSeconds(
                Math.Max(0, maximumAgeSeconds));
            return now - authenticatedAt > maximumAge;
        }
        catch (ArgumentOutOfRangeException)
        {
            return true;
        }
        catch (OverflowException)
        {
            return true;
        }
    }
}
