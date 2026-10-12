namespace Sufficit.Identity.Application.Security;

/// <summary>
/// Private-use URI schemes (RFC 8252, section 7.1) that a public native
/// client may register as a redirect URI, e.g.
/// <c>vscode://publisher.extension/callback</c>. The same rule the
/// provisioning manifest applies, shared so management and dynamic
/// definition validation cannot drift from it.
/// </summary>
public static class PrivateUseRedirectScheme
{
    private static readonly HashSet<string> Forbidden = new(StringComparer.OrdinalIgnoreCase)
    {
        "about",
        "blob",
        "data",
        "file",
        "ftp",
        "http",
        "https",
        "javascript",
        "mailto",
        "urn",
        "vbscript",
        "ws",
        "wss",
    };

    /// <summary>
    /// True when <paramref name="uri"/> is an absolute, fragment-free,
    /// credential-free URI using a non-web private-use scheme.
    /// </summary>
    public static bool IsAllowed(Uri? uri) =>
        uri is not null
        && uri.IsAbsoluteUri
        && uri.Fragment.Length == 0
        && uri.UserInfo.Length == 0
        && !string.IsNullOrEmpty(uri.Scheme)
        && !Forbidden.Contains(uri.Scheme);
}
