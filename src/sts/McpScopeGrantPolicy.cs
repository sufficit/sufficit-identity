using System.Collections.Immutable;

namespace Sufficit.Identity.STS;

/// <summary>
/// Adds the dedicated Identity MCP scope to tokens issued for explicitly
/// trusted first-party clients. The policy is applied during every user-token
/// grant so refresh tokens created before the scope existed repair themselves
/// without requiring the user to enroll again.
/// </summary>
public sealed class McpScopeGrantPolicy(SufficitIdentityOptions options)
{
    public ImmutableArray<string> Resolve(
        string? clientId,
        IEnumerable<string> grantedScopes)
    {
        ArgumentNullException.ThrowIfNull(grantedScopes);

        var scopes = grantedScopes
            .Where(scope => !string.IsNullOrWhiteSpace(scope))
            .ToHashSet(StringComparer.Ordinal);
        var requiredScope = options.Mcp.RequiredScope.Trim();
        if (!string.IsNullOrWhiteSpace(clientId)
            && !string.IsNullOrWhiteSpace(requiredScope)
            && options.Mcp.ImplicitClientIds.Contains(clientId))
        {
            scopes.Add(requiredScope);
        }

        return scopes.Order(StringComparer.Ordinal).ToImmutableArray();
    }
}
