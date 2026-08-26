using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OAuth;

namespace Sufficit.Identity.STS.Integrations;

internal static class IntegrationOAuthProtocol
{
    public static void StoreGrantedScope(
        AuthenticationProperties properties,
        OAuthTokenResponse response)
    {
        if (response.Response?.RootElement is not { } payload
            || !payload.TryGetProperty("scope", out var scopeNode)
            || scopeNode.ValueKind != System.Text.Json.JsonValueKind.String
            || string.IsNullOrWhiteSpace(scopeNode.GetString()))
            return;

        var tokens = properties.GetTokens()
            .Where(token => !string.Equals(token.Name, "scope", StringComparison.Ordinal))
            .ToList();
        tokens.Add(new AuthenticationToken
        {
            Name = "scope",
            Value = scopeNode.GetString()!,
        });
        properties.StoreTokens(tokens);
    }

    /// <summary>
    /// Builds an RFC 7591 registration payload for a provider that requires
    /// one. <paramref name="clientName"/> is the display name of the client
    /// this broker is acting for, read from its registration — the provider's
    /// consent screen must name the application the user actually launched,
    /// which no constant in this server can know.
    /// </summary>
    public static IReadOnlyDictionary<string, object> DynamicRegistration(
        IntegrationOAuthProvider provider,
        string callbackUri,
        string clientName)
    {
        var payload = new Dictionary<string, object>
        {
            ["client_name"] = clientName,
            ["redirect_uris"] = new[] { callbackUri },
            ["scope"] = string.Join(' ', provider.Scopes),
        };
        if (provider.Resource is not null)
            payload["resource"] = provider.Resource.ToString();
        return payload;
    }

    public static Dictionary<string, string> AuthorizationCodeFields(
        IntegrationOAuthProvider provider,
        string code,
        string callbackUri,
        string clientId,
        string? clientSecret,
        string codeVerifier)
    {
        var fields = new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["code"] = code,
            ["redirect_uri"] = callbackUri,
            ["client_id"] = clientId,
            ["code_verifier"] = codeVerifier,
        };
        AddOptional(fields, "client_secret", clientSecret);
        AddOptional(fields, "resource", provider.Resource?.ToString());
        return fields;
    }

    public static Dictionary<string, string> RefreshFields(
        IntegrationOAuthProvider provider,
        string refreshToken,
        string clientId,
        string? clientSecret)
    {
        var fields = new Dictionary<string, string>
        {
            ["grant_type"] = "refresh_token",
            ["refresh_token"] = refreshToken,
            ["client_id"] = clientId,
        };
        AddOptional(fields, "client_secret", clientSecret);
        AddOptional(fields, "resource", provider.Resource?.ToString());
        return fields;
    }

    public static bool HasRequiredScopes(
        IReadOnlyList<string> required,
        string? granted)
    {
        if (required.Count == 0) return true;
        if (string.IsNullOrWhiteSpace(granted)) return false;
        var values = granted.Split(
            [' ', ','],
            StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        var set = new HashSet<string>(values, StringComparer.Ordinal);
        return required.All(scope => Covers(set, scope));
    }

    private static bool Covers(IReadOnlySet<string> granted, string required)
    {
        if (granted.Contains(required)) return true;

        // Google canonicalizes the short OpenID profile/email aliases in its
        // token response. They are the same grants, not broader substitutes.
        if (string.Equals(required, "profile", StringComparison.Ordinal))
            return granted.Contains("https://www.googleapis.com/auth/userinfo.profile");
        if (string.Equals(required, "email", StringComparison.Ordinal))
            return granted.Contains("https://www.googleapis.com/auth/userinfo.email");

        // A previously granted full Calendar scope is a strict superset of
        // every Calendar API sub-scope requested by the broker.
        return required.StartsWith(
                "https://www.googleapis.com/auth/calendar.",
                StringComparison.Ordinal)
            && granted.Contains("https://www.googleapis.com/auth/calendar");
    }

    private static void AddOptional(
        IDictionary<string, string> values,
        string name,
        string? value)
    {
        if (!string.IsNullOrWhiteSpace(value)) values[name] = value;
    }
}
