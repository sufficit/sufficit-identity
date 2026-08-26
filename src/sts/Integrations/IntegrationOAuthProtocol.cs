namespace Sufficit.Identity.STS.Integrations;

internal static class IntegrationOAuthProtocol
{
    public static IReadOnlyDictionary<string, object> DynamicRegistration(
        IntegrationOAuthProvider provider,
        string callbackUri)
    {
        var payload = new Dictionary<string, object>
        {
            ["client_name"] = "Sufficit AI Genius",
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
        return required.All(set.Contains);
    }

    private static void AddOptional(
        IDictionary<string, string> values,
        string name,
        string? value)
    {
        if (!string.IsNullOrWhiteSpace(value)) values[name] = value;
    }
}
