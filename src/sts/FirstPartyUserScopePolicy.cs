using System.Collections.Immutable;
using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Sufficit.Identity.STS;

/// <summary>
/// Server-approved scopes for explicitly configured first-party user clients.
/// Applied on interactive user grants and refresh, never client credentials or
/// token exchange. Both registration and client permission remain mandatory.
/// </summary>
public sealed class FirstPartyUserScopePolicy(
    SufficitIdentityOptions options,
    IOpenIddictApplicationManager applications,
    IOpenIddictScopeManager scopes)
{
    public async ValueTask<ImmutableArray<string>> ResolveAsync(
        string? clientId, IEnumerable<string> grantedScopes, CancellationToken ct = default)
    {
        var result = grantedScopes.ToHashSet(StringComparer.Ordinal);
        if (string.IsNullOrWhiteSpace(clientId)
            || !options.FirstPartyUserScopes.TryGetValue(clientId, out var configured)
            || configured.Length == 0)
            return result.Order(StringComparer.Ordinal).ToImmutableArray();

        var application = await applications.FindByClientIdAsync(clientId, ct);
        if (application is null) return result.Order(StringComparer.Ordinal).ToImmutableArray();
        foreach (var scope in configured.Where(s => !string.IsNullOrWhiteSpace(s)).Distinct(StringComparer.Ordinal))
        {
            if (await applications.HasPermissionAsync(application, Permissions.Prefixes.Scope + scope, ct)
                && await scopes.FindByNameAsync(scope, ct) is not null)
                result.Add(scope);
        }
        return result.Order(StringComparer.Ordinal).ToImmutableArray();
    }
}
