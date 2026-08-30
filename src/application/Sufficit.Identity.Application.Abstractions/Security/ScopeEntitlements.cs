using System.Text.Json;

namespace Sufficit.Identity.Application.Security;

/// <summary>
/// One persisted claim granted to a user when they approve a scope.
/// </summary>
public sealed record ScopeEntitlementClaim(string Type, string Value);

/// <summary>
/// Reads and writes the entitlement claims carried by an OpenIddict scope
/// record, so the "approving scope X grants claim Y" policy lives next to the
/// scope it belongs to instead of in each host's configuration file.
/// </summary>
/// <remarks>
/// <b>Why the database rather than appsettings.</b> The scope already lives in
/// the OpenIddict scope store, and the store is what OpenIddict consults when a
/// client requests it — configuration was never required for a scope to work.
/// Keeping the entitlement beside it means the pair is declared once, through
/// the provisioning manifest or the management API, and reaches every replica
/// the same way the scope itself does. With a replicated database that removes
/// the per-server configuration edit entirely, along with the drift that comes
/// from one host being updated and another not (eval 2026-08-30, F-2).
/// <para>The value is stored as a JSON array under
/// <see cref="PropertyName"/> in the scope's <c>Properties</c> bag, the same
/// mechanism the provisioning manifest already uses for its own metadata.</para>
/// </remarks>
public static class ScopeEntitlements
{
    /// <summary>Scope property carrying the entitlement claim array.</summary>
    public const string PropertyName = "identity:scope:entitlement-claims";

    /// <summary>
    /// Reads the entitlement claims from a scope's property bag. Returns an
    /// empty list when the scope declares none, and skips malformed or
    /// incomplete entries rather than failing token issuance — a bad property
    /// value must never be able to break sign-in for every user of that scope.
    /// </summary>
    public static IReadOnlyList<ScopeEntitlementClaim> Read(
        IReadOnlyDictionary<string, JsonElement>? properties)
    {
        if (properties is null
            || !properties.TryGetValue(PropertyName, out var value)
            || value.ValueKind != JsonValueKind.Array)
        {
            return [];
        }

        var claims = new List<ScopeEntitlementClaim>();
        foreach (var element in value.EnumerateArray())
        {
            if (element.ValueKind != JsonValueKind.Object)
            {
                continue;
            }

            var type = ReadString(element, "type");
            var claimValue = ReadString(element, "value");
            if (string.IsNullOrWhiteSpace(type) || string.IsNullOrWhiteSpace(claimValue))
            {
                continue;
            }

            claims.Add(new ScopeEntitlementClaim(type.Trim(), claimValue.Trim()));
        }

        return claims;
    }

    /// <summary>
    /// Serializes entitlement claims into the property value written to the
    /// scope record. Returns null when there is nothing to store, so callers
    /// remove the property instead of persisting an empty array.
    /// </summary>
    public static JsonElement? Write(IEnumerable<ScopeEntitlementClaim>? claims)
    {
        var materialized = (claims ?? [])
            .Where(claim =>
                !string.IsNullOrWhiteSpace(claim.Type)
                && !string.IsNullOrWhiteSpace(claim.Value))
            .Select(claim => new ScopeEntitlementClaim(
                claim.Type.Trim(),
                claim.Value.Trim()))
            .Distinct()
            .ToArray();

        if (materialized.Length == 0)
        {
            return null;
        }

        return JsonSerializer.SerializeToElement(
            materialized.Select(claim => new Dictionary<string, string>
            {
                ["type"] = claim.Type,
                ["value"] = claim.Value,
            }).ToArray());
    }

    private static string? ReadString(JsonElement element, string propertyName) =>
        element.TryGetProperty(propertyName, out var value)
            && value.ValueKind == JsonValueKind.String
                ? value.GetString()
                : null;
}
