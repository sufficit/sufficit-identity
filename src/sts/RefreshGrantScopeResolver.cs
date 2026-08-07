using System.Collections.Immutable;
using System.Security.Claims;
using OpenIddict.Abstractions;

namespace Sufficit.Identity.STS;

/// <summary>
/// Restores the scopes attached to a refresh-token grant.
/// </summary>
/// <remarks>
/// A short-lived production regression issued refresh tokens whose principal
/// had no scopes. The permanent OpenIddict authorization still contains the
/// original grant, so using that record as a fallback repairs those token
/// lineages without granting scopes that the user/client never authorized.
/// </remarks>
internal static class RefreshGrantScopeResolver
{
    public static async ValueTask<ImmutableArray<string>> ResolveAsync(
        ClaimsPrincipal grantPrincipal,
        IOpenIddictAuthorizationManager authorizationManager,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(grantPrincipal);
        ArgumentNullException.ThrowIfNull(authorizationManager);

        var scopes = grantPrincipal.GetScopes();
        if (scopes.Length > 0)
        {
            return scopes;
        }

        var authorizationId = grantPrincipal.GetAuthorizationId();
        if (string.IsNullOrWhiteSpace(authorizationId))
        {
            return scopes;
        }

        var authorization = await authorizationManager.FindByIdAsync(
            authorizationId,
            cancellationToken);
        return authorization is null
            ? scopes
            : await authorizationManager.GetScopesAsync(authorization, cancellationToken);
    }
}
