using System.Globalization;
using System.Security.Claims;
using OpenIddict.Abstractions;

namespace Sufficit.Identity.STS;

/// <summary>
/// Evaluates the OIDC max_age and prompt=login contracts against the time at
/// which the user actually authenticated. Token issue/refresh time is
/// intentionally ignored.
/// </summary>
internal static class AuthorizationReauthenticationPolicy
{
    private static readonly TimeSpan FutureClockTolerance = TimeSpan.FromMinutes(1);

    public static bool IsRequired(
        OpenIddictRequest request,
        ClaimsPrincipal principal,
        DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(principal);

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
