namespace Sufficit.Identity.UI.Services;

/// <summary>
/// Validates that a <c>returnUrl</c>/<c>ReturnUrl</c> value supplied by the caller
/// (query string, form field, external redirect) is a same-site relative URL before
/// it is ever handed to <c>NavigationManager.NavigateTo</c> or an HTTP redirect.
///
/// Without this check an attacker can craft a link like
/// <c>/account/login?returnUrl=https://evil.example/phish</c> (or the protocol-relative
/// <c>//evil.example</c> variant) and, once the victim authenticates, get silently
/// redirected off-site with a valid session cookie already set — an "authenticated
/// open redirect". This mirrors the logic of ASP.NET Core MVC's
/// <c>IUrlHelper.IsLocalUrl</c> (no built-in equivalent exists for Blazor/NavigationManager).
/// </summary>
public static class LocalUrlValidator
{
    /// <summary>
    /// Returns <paramref name="url"/> unchanged if it is a safe, same-site relative
    /// URL; otherwise returns <paramref name="fallback"/> (default <c>"/"</c>).
    /// </summary>
    public static string EnsureLocal(string? url, string fallback = "/")
    {
        return IsLocal(url) ? url! : fallback;
    }

    /// <summary>
    /// True when <paramref name="url"/> is a same-site relative URL: starts with a
    /// single <c>/</c> (not <c>//</c> or <c>/\</c>, both of which browsers can treat
    /// as protocol-relative — i.e. off-site) or with <c>~/</c>, and is not an
    /// absolute URI (has no scheme/host of its own).
    /// </summary>
    public static bool IsLocal(string? url)
    {
        if (string.IsNullOrEmpty(url)) return false;

        // Reject anything the BCL itself considers an absolute URI (has a scheme,
        // e.g. "https://evil.example", "javascript:...").
        if (Uri.TryCreate(url, UriKind.Absolute, out _)) return false;

        if (url[0] == '/')
        {
            // "/" alone is fine.
            if (url.Length == 1) return true;
            // "//evil.example" or "/\evil.example" — browsers resolve these as
            // scheme-relative absolute URLs. Reject.
            if (url[1] == '/' || url[1] == '\\') return false;
            return true;
        }

        if (url[0] == '~' && url.Length > 1 && url[1] == '/')
        {
            if (url.Length == 2) return true;
            if (url[2] == '/' || url[2] == '\\') return false;
            return true;
        }

        return false;
    }
}
