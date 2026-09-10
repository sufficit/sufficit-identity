using System.Globalization;
using Microsoft.AspNetCore.Http.HttpResults;
using Sufficit.Identity.STS.ErrorPages;
using Sufficit.Identity.UI.Components;

namespace Sufficit.Identity.Server;

/// <summary>Registered only with embedded public UI; headless hosts retain JSON errors.</summary>
internal sealed class BrowserRateLimitErrors
{
    internal static bool IsHtmlNavigation(HttpRequest request)
    {
        if (!HttpMethods.IsGet(request.Method) && !HttpMethods.IsPost(request.Method)) return false;
        // Exact interactive routes only. A browser calling a protocol or passkey API
        // still receives JSON, even if it sends navigation headers.
        string[] routes = ["/connect/device", "/connect/authorize", "/connect/endsession",
            "/connect/ciba/complete", "/account/login", "/account/login/password",
            "/account/login/2fa", "/account/login/recoverycode", "/account/forgotpassword",
            "/account/resetpassword", "/account/register", "/account/externallogincallback"];
        return routes.Any(path => request.Path.Equals(path, StringComparison.OrdinalIgnoreCase))
            && BrowserNavigationRequest.PrefersHtmlDocument(request);
    }

    internal async Task WriteAsync(HttpContext context, int retryAfterSeconds)
    {
        var previousCulture = CultureInfo.CurrentCulture;
        var previousUiCulture = CultureInfo.CurrentUICulture;
        try
        {
            var culture = ResolveCulture(context.Request);
            CultureInfo.CurrentCulture = CultureInfo.CurrentUICulture = culture;
            context.Response.Headers.ContentLanguage = culture.Name;
            context.Response.Headers["Referrer-Policy"] = "no-referrer";
            // No request URI, error description, token or return URL is reflected.
            await new RazorComponentResult<AuthorizationError>(new { RetryAfterSeconds = retryAfterSeconds })
            {
                StatusCode = StatusCodes.Status429TooManyRequests,
                PreventStreamingRendering = true
            }.ExecuteAsync(context);
        }
        finally
        {
            CultureInfo.CurrentCulture = previousCulture;
            CultureInfo.CurrentUICulture = previousUiCulture;
        }
    }

    private static CultureInfo ResolveCulture(HttpRequest request)
    {
        try
        {
            var languages = request.GetTypedHeaders().AcceptLanguage;
            if (languages is not null)
                foreach (var language in languages.Where(value => (value.Quality ?? 1) > 0)
                             .OrderByDescending(value => value.Quality ?? 1))
                {
                    var name = language.Value.ToString();
                    if (name.Equals("en", StringComparison.OrdinalIgnoreCase)
                        || name.StartsWith("en-", StringComparison.OrdinalIgnoreCase))
                        return CultureInfo.GetCultureInfo("en-US");
                    if (name.Equals("pt", StringComparison.OrdinalIgnoreCase)
                        || name.StartsWith("pt-", StringComparison.OrdinalIgnoreCase))
                        return CultureInfo.GetCultureInfo("pt-BR");
                }
        }
        catch (FormatException) { /* Malformed preferences use the default language. */ }
        return CultureInfo.GetCultureInfo("pt-BR");
    }
}
