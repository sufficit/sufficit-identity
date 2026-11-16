using System.Security.Claims;
using System.Text.Json;

namespace Sufficit.Identity.AspNetCore.Authentication.OAuth2Introspection;

/// <summary>Parsed RFC 7662 response. A non-active result is a verdict on the token, never an outage.</summary>
public sealed class IntrospectionResult
{
    internal IntrospectionResult(JsonElement root, bool fromCache)
    {
        Raw = root.Clone();
        FromCache = fromCache;
        IsActive = Raw.ValueKind == JsonValueKind.Object && Raw.TryGetProperty("active", out var a) && a.ValueKind == JsonValueKind.True;
        if (Raw.ValueKind == JsonValueKind.Object && Raw.TryGetProperty("exp", out var e) && e.TryGetInt64(out var exp))
            ExpiresAt = DateTimeOffset.FromUnixTimeSeconds(exp);
    }

    /// <summary>The <c>active</c> member is literally <c>true</c>.</summary>
    public bool IsActive { get; }

    /// <summary>The <c>exp</c> member, when present.</summary>
    public DateTimeOffset? ExpiresAt { get; }

    /// <summary>Served from the distributed cache instead of the endpoint.</summary>
    public bool FromCache { get; }

    /// <summary>The full response document.</summary>
    public JsonElement Raw { get; }

    /// <summary>String values of a member: arrays become one value per item; <c>scope</c> is split on spaces.</summary>
    public string[] Values(string name)
    {
        if (Raw.ValueKind != JsonValueKind.Object || !Raw.TryGetProperty(name, out var value)) return [];
        return value.ValueKind switch
        {
            JsonValueKind.Array => value.EnumerateArray().Select(Text).Where(v => v is not null).Select(v => v!).ToArray(),
            JsonValueKind.String when name == "scope" => value.GetString()!.Split(' ', StringSplitOptions.RemoveEmptyEntries),
            _ => Text(value) is { } single ? [single] : [],
        };
    }

    /// <summary>Claims built from every member except <c>active</c>.</summary>
    public IEnumerable<Claim> ToClaims(string issuer)
    {
        if (Raw.ValueKind != JsonValueKind.Object) yield break;
        foreach (var property in Raw.EnumerateObject())
        {
            if (property.Name == "active") continue;
            foreach (var value in Values(property.Name))
                yield return new Claim(property.Name, value, ClaimValueTypes.String, issuer);
        }
    }

    private static string? Text(JsonElement value) => value.ValueKind switch
    {
        JsonValueKind.String => value.GetString(),
        JsonValueKind.Null or JsonValueKind.Undefined => null,
        _ => value.GetRawText(),
    };
}
