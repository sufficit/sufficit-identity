using System.Globalization;
using System.Security.Claims;
using OpenIddict.Abstractions;

namespace Sufficit.Identity.STS;

/// <summary>
/// Evaluates the OIDC max_age contract against the time at which the user
/// actually authenticated. Token issue/refresh time is intentionally ignored.
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

        if (request.MaxAge is not { } maximumAgeSeconds)
        {
            return false;
        }

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
