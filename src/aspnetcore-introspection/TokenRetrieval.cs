using Microsoft.AspNetCore.Http;

namespace Sufficit.Identity.AspNetCore.Authentication.OAuth2Introspection;

/// <summary>Ready-made token retrievers, as in Duende.</summary>
public static class TokenRetrieval
{
    public static Func<HttpRequest, string?> FromAuthorizationHeader(string scheme = "Bearer") => request =>
    {
        string? header = request.Headers.Authorization;
        if (string.IsNullOrEmpty(header) || !header.StartsWith(scheme + " ", StringComparison.OrdinalIgnoreCase)) return null;
        var token = header[(scheme.Length + 1)..].Trim();
        return token.Length == 0 ? null : token;
    };

    public static Func<HttpRequest, string?> FromQueryString(string name = "access_token")
        => request => request.Query.TryGetValue(name, out var value) && !string.IsNullOrWhiteSpace(value) ? value.ToString() : null;
}
