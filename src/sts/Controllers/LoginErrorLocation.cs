using System.Globalization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.WebUtilities;

namespace Sufficit.Identity.STS.Controllers;

/// <summary>
/// Builds the redirect back to the login page after a failed sign-in.
/// The error travels in the query string, so a reload, the back button or a
/// stale tab would replay it without context. Each failure is therefore
/// stamped with a per-browser attempt number and the server time it happened
/// at, which the login page shows next to the message so the person can tell
/// whether it belongs to the attempt they just made.
/// </summary>
internal static class LoginErrorLocation
{
    internal const string AttemptCookieName = ".Sufficit.Identity.LoginAttempts";

    public static string Build(
        HttpContext httpContext,
        string error,
        string returnUrl,
        string? loginHint = null)
    {
        var attempt = NextAttempt(httpContext);
        return QueryHelpers.AddQueryString(
            "/account/login",
            new Dictionary<string, string?>
            {
                ["error"] = error,
                ["attempt"] = attempt.ToString(CultureInfo.InvariantCulture),
                ["at"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds()
                    .ToString(CultureInfo.InvariantCulture),
                ["returnUrl"] = returnUrl,
                ["login_hint"] = loginHint,
            });
    }

    /// <summary>Forgets the failure count once the person gets in.</summary>
    public static void Reset(HttpContext httpContext)
    {
        if (httpContext.Request.Cookies.ContainsKey(AttemptCookieName))
            httpContext.Response.Cookies.Delete(AttemptCookieName, CookieOptions(httpContext));
    }

    private static int NextAttempt(HttpContext httpContext)
    {
        var previous = httpContext.Request.Cookies.TryGetValue(
                AttemptCookieName,
                out var raw)
            && int.TryParse(
                raw,
                NumberStyles.None,
                CultureInfo.InvariantCulture,
                out var parsed)
            && parsed is > 0 and < 10_000
                ? parsed
                : 0;
        var attempt = previous + 1;
        httpContext.Response.Cookies.Append(
            AttemptCookieName,
            attempt.ToString(CultureInfo.InvariantCulture),
            CookieOptions(httpContext));
        return attempt;
    }

    // Session cookie: the count only has to outlive the redirect chain of the
    // current sign-in, never the browser session. Lax so the external
    // provider's top-level callback still carries it.
    private static CookieOptions CookieOptions(HttpContext httpContext) => new()
    {
        HttpOnly = true,
        Secure = httpContext.Request.IsHttps,
        SameSite = SameSiteMode.Lax,
        Path = "/",
        IsEssential = true,
    };
}
