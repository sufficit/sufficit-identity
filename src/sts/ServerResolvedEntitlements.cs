using System.Security.Claims;

namespace Sufficit.Identity.STS;

/// <summary>Configurable delivery of opaque stored grants. Identity does not
/// interpret resource identifiers, contexts, wildcards or business permissions.</summary>
public static class ServerResolvedEntitlements
{
    public static bool IsServerResolved(Claim claim, IReadOnlySet<string> keys)
    {
        if (claim.Type is not ("entitlements" or "directive")) return false;
        var separator = claim.Value.IndexOf(':');
        var key = separator < 0 ? claim.Value : claim.Value[..separator];
        return keys.Contains(key);
    }

    public static string[] Resolve(IEnumerable<Claim> claims, IReadOnlySet<string> keys) =>
        claims.Where(claim => IsServerResolved(claim, keys))
            .Select(claim => Validate(claim.Value))
            .OfType<string>().Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal).ToArray();

    private static string? Validate(string value)
    {
        // Transport bounds only. The resource server validates and normalizes
        // the value according to its own authorization model.
        return value.Length is > 0 and <= 256 && !value.Any(char.IsControl) ? value : null;
    }
}
