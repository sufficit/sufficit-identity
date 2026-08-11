using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Sufficit.Identity.Management.Authorization;

namespace Sufficit.Identity.Server.Management;

/// <summary>
/// Replaces caller-supplied tenant claims with the deployment-controlled
/// subject-to-tenant resolution. Authentication, OAuth scopes, roles and
/// management capabilities never imply tenant membership.
/// </summary>
public sealed class SufficitManagementTenantClaimsTransformation(
    IManagementTenantResolver tenantResolver) : IClaimsTransformation
{
    public async Task<ClaimsPrincipal> TransformAsync(
        ClaimsPrincipal principal)
    {
        ArgumentNullException.ThrowIfNull(principal);

        if (principal.Identity?.IsAuthenticated is not true)
        {
            return principal;
        }

        const string claimType = ManagementTenantClaims.Type;

        // A tenant claim already present in a cookie/token is not authoritative
        // for Management membership. Remove it before trusted resolution.
        foreach (var identity in principal.Identities)
        {
            foreach (var claim in identity.Claims
                .Where(claim => string.Equals(
                    claim.Type,
                    claimType,
                    StringComparison.Ordinal))
                .ToArray())
            {
                identity.RemoveClaim(claim);
            }
        }

        var access = await tenantResolver.ResolveAsync(principal);
        if (access.TenantIds.Count is 0)
        {
            return principal;
        }

        var identityToEnrich = principal.Identities.FirstOrDefault(
            candidate => candidate.IsAuthenticated);
        if (identityToEnrich is null)
        {
            return principal;
        }

        foreach (var tenantId in access.TenantIds.Order(StringComparer.Ordinal))
        {
            identityToEnrich.AddClaim(new Claim(
                claimType,
                tenantId,
                ClaimValueTypes.String,
                "Sufficit.Identity.Management"));
        }

        return principal;
    }
}
