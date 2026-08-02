namespace Sufficit.Identity.Application.Accounts;

/// <summary>
/// Validates caller-supplied return URLs before navigation or HTTP redirects.
/// </summary>
public static class LocalUrlValidator
{
    public static string EnsureLocal(string? url, string fallback = "/") =>
        IsLocal(url) ? url! : fallback;

    public static bool IsLocal(string? url)
    {
        if (string.IsNullOrEmpty(url)
            || Uri.TryCreate(url, UriKind.Absolute, out _))
        {
            return false;
        }

        if (url[0] == '/')
        {
            return url.Length == 1
                || (url[1] != '/' && url[1] != '\\');
        }

        return url[0] == '~'
            && url.Length > 1
            && url[1] == '/'
            && (url.Length == 2
                || (url[2] != '/' && url[2] != '\\'));
    }
}
