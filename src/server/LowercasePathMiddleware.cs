using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;

namespace Sufficit.Identity.Server;

/// <summary>
/// Canonicalizes the request path to lowercase and issues a permanent
/// redirect when the incoming path contains any uppercase letter.
///
/// Behavior:
///  * Only the URL <c>path</c> is lowercased. The query string, fragment,
///    and every header are forwarded untouched (query string values keep
///    their original case).
///  * The redirect preserves the HTTP method via <c>308 Permanent Redirect</c>
///    so POST/PUT/DELETE bodies survive the redirect. Browsers and well-behaved
///    OAuth/OIDC clients honor 308.
///  * Static asset paths (<c>_framework/*</c>, <c>_content/*</c>, files with
///    a file extension) are skipped — they are already lowercase by convention
///    and an extra round-trip would slow down the dev experience.
///  * Endpoints advertised by OpenIddict (<c>/connect/*</c>,
///    <c>/.well-known/*</c>) are <b>accepted</b> case-insensitively but still
///    redirected to the canonical lowercase form, so the URL the user/client
///    sees is always the same. OpenIddict itself stores URIs in lowercase,
///    so the canonical form always matches the discovery document.
/// </summary>
public sealed class LowercasePathMiddleware
{
    private readonly RequestDelegate _next;

    public LowercasePathMiddleware(RequestDelegate next) => _next = next;

    public async Task InvokeAsync(HttpContext context)
    {
        var path = context.Request.Path.Value;

        // No path or already lowercase → nothing to do.
        if (string.IsNullOrEmpty(path) || path == "/" || !NeedsLowercasing(path))
        {
            await _next(context);
            return;
        }

        // Skip static assets to avoid an extra round-trip per asset.
        // _framework/* and _content/* are Blazor/JS assets already lowercase.
        if (IsStaticAsset(path))
        {
            await _next(context);
            return;
        }

        var lower = path.ToLowerInvariant();

        // Rebuild the URL preserving the original query string untouched.
        // Request.QueryString already contains the leading '?' (or is empty).
        var location = lower + context.Request.QueryString.Value;

        // 308 Permanent Redirect preserves method and body (unlike 301/302
        // which may downgrade POST to GET in some clients). RFC 7538.
        context.Response.StatusCode = StatusCodes.Status308PermanentRedirect;
        context.Response.Headers.Location = location;
        await context.Response.CompleteAsync();
    }

    /// <summary>
    /// Returns <c>true</c> if the path contains at least one uppercase
    /// ASCII letter (A-Z). Non-ASCII characters and digits are ignored.
    /// </summary>
    private static bool NeedsLowercasing(string path)
    {
        foreach (var c in path)
        {
            if ((uint)c - 'A' <= 'Z' - 'A')
                return true;
        }
        return false;
    }

    /// <summary>
    /// Returns <c>true</c> for requests that should bypass the redirect
    /// (Blazor framework assets, content assets, files with extensions).
    /// </summary>
    private static bool IsStaticAsset(string path)
    {
        if (path.StartsWith("/_framework/", StringComparison.Ordinal)) return true;
        if (path.StartsWith("/_content/", StringComparison.Ordinal)) return true;

        // Files with extension (e.g. site.css, blazor.web.js, favicon.ico).
        var lastSlash = path.LastIndexOf('/');
        var lastSegment = lastSlash >= 0 ? path[(lastSlash + 1)..] : path;
        return lastSegment.Contains('.');
    }
}
