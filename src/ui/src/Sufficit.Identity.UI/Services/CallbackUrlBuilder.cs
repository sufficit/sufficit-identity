using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Configuration;

namespace Sufficit.Identity.UI.Services;

/// <summary>
/// Builds absolute callback URLs for email links (password reset, email
/// confirmation). Reads a configurable public URL from
/// "Sufficit:Identity:PublicUrl" so that links point to the user-facing
/// host (e.g. https://identity.sufficit.com.br) instead of the internal
/// host the request came from.
/// </summary>
public sealed class CallbackUrlBuilder
{
    private readonly string? _publicBaseUrl;

    public CallbackUrlBuilder(IConfiguration configuration)
    {
        _publicBaseUrl = configuration["Sufficit:Identity:PublicUrl"]?
            .TrimEnd('/');
    }

    /// <summary>
    /// Builds an absolute URL for the given relative path, honoring the
    /// configured PublicUrl when present (otherwise uses the request scheme/host).
    /// Query string parameters preserve their original case.
    /// </summary>
    public string BuildAbsolute(HttpContext httpContext, string relativePath,
        IEnumerable<KeyValuePair<string, string?>> queryParams)
    {
        var pathWithQuery = QueryHelpers.AddQueryString(relativePath, queryParams);

        if (!string.IsNullOrWhiteSpace(_publicBaseUrl))
        {
            return $"{_publicBaseUrl}{pathWithQuery}";
        }

        // Fallback: build from the request scheme + host (honors ForwardedHeaders).
        var request = httpContext.Request;
        var host = request.Host.Value ?? "localhost";
        var scheme = request.Scheme;
        return $"{scheme}://{host}{pathWithQuery}";
    }

    /// <summary>
    /// Convenience helper to base64url-encode a token for transport in
    /// email links (matches the format expected by ResetPassword / ConfirmEmail).
    /// </summary>
    public static string EncodeToken(string token)
    {
        var bytes = System.Text.Encoding.UTF8.GetBytes(token);
        return WebEncoders.Base64UrlEncode(bytes);
    }

    public static string DecodeToken(string encoded)
    {
        var bytes = WebEncoders.Base64UrlDecode(encoded);
        return System.Text.Encoding.UTF8.GetString(bytes);
    }
}
