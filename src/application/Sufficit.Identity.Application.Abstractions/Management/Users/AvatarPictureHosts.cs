namespace Sufficit.Identity.Management.Users;

/// <summary>
/// The image origins an operator's browser is allowed to fetch a user avatar
/// from.
/// </summary>
/// <remarks>
/// The <c>picture</c> claim is not ours: it arrives from an external identity
/// provider, and on a self-service profile it is whatever the user typed. A
/// management console that renders it unfiltered makes every operator's browser
/// issue a request to an address the *listed user* chose — which discloses the
/// operator's address and user agent, on a page whose whole purpose is looking
/// at accounts one already distrusts.
///
/// So the value is treated as untrusted input and only rendered when its origin
/// appears here. Everything else falls back to initials, which is also what
/// happens for the overwhelming majority of accounts: they carry no
/// <c>picture</c> claim at all.
///
/// The allowed origins are configuration, not a constant: this product serves
/// several companies, each federating with a different provider, so naming one
/// vendor's image host in the shared library would be wrong for every
/// deployment that does not use it. The default is empty, which renders
/// initials for everyone — the feature is opt-in per deployment.
///
/// Whatever is configured here must also reach the Content-Security-Policy
/// <c>img-src</c> directive. An origin permitted in one and missing from the
/// other yields a broken avatar and reports nothing, because a CSP-blocked
/// image looks exactly like a user who has none.
/// </remarks>
public static class AvatarPictureHosts
{
    /// <summary>
    /// Returns the picture URL when it is safe to render, otherwise null.
    /// </summary>
    /// <remarks>
    /// Requires an absolute HTTPS URL on an allowed origin. Plain HTTP is
    /// rejected even for an allowed host: it would be blocked as mixed content
    /// anyway, and silently.
    /// </remarks>
    public static string? Normalize(
        string? value,
        IReadOnlyCollection<string> allowedOrigins)
    {
        if (allowedOrigins.Count == 0)
        {
            return null;
        }

        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        if (!Uri.TryCreate(value, UriKind.Absolute, out var uri))
        {
            return null;
        }

        if (!string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.Ordinal))
        {
            return null;
        }

        // Authority, not Host: it excludes userinfo. A value that puts an
        // allowed host in the userinfo position, before an "@", reads to a
        // human as that host while a browser resolves the one after the "@".
        // Comparing the authority makes it fail closed.
        var origin = $"{uri.Scheme}://{uri.Authority}";
        return allowedOrigins.Contains(origin, StringComparer.OrdinalIgnoreCase)
            ? uri.AbsoluteUri
            : null;
    }
}
