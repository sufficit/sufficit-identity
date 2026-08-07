using System.Security.Claims;
using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Sufficit.Identity.STS;

public interface IApplicationClaimDestinationPolicy
{
    IReadOnlyDictionary<string, string> MappedClaimScopes { get; }

    IEnumerable<string> GetDestinations(
        Claim claim,
        bool includeIdentityToken);
}

internal sealed class ApplicationClaimDestinationPolicy(
    ClaimScopeMapOptions options) : IApplicationClaimDestinationPolicy
{
    public IReadOnlyDictionary<string, string> MappedClaimScopes =>
        options.ClaimToScope;

    public IEnumerable<string> GetDestinations(
        Claim claim,
        bool includeIdentityToken)
    {
        if (options.ClaimToScope.TryGetValue(claim.Type, out var requiredScope))
        {
            if (!claim.Subject!.HasScope(requiredScope)) yield break;

            yield return Destinations.AccessToken;
            if (includeIdentityToken)
                yield return Destinations.IdentityToken;
            yield break;
        }

        if (options.IncludeUnmappedClaimsInAccessTokens)
            yield return Destinations.AccessToken;
    }
}
