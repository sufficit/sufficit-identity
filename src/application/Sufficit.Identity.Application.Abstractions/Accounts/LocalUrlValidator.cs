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
        if (string.IsNullOrEmpty(url))
        {
            return false;
        }

        // Check local path syntax before Uri.TryCreate: .NET treats a path
        // such as `/connect/authorize?client_id=...` as an absolute `file:`
        // URI, which would otherwise discard valid OIDC return URLs.
        if (url[0] == '/')
        {
            return url.Length == 1
                || (url[1] != '/' && url[1] != '\\');
        }

        if (url[0] == '~')
        {
            return url.Length > 1
                && url[1] == '/'
                && (url.Length == 2
                    || (url[2] != '/' && url[2] != '\\'));
        }

        return false;
    }
}
