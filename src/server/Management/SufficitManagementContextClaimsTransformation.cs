using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;
using Sufficit.Identity.Management;
using Sufficit.Identity.Management.Authorization;

namespace Sufficit.Identity.Server.Management;

/// <summary>
/// Projects the deployment's canonical single-context identity into every
/// authenticated management request. The context is granted only after the
/// same entitlement resolver used by the Management UI/API confirms that the
/// principal has at least one management capability; it is never inferred
/// from an OAuth scope or from authentication alone.
/// </summary>
public sealed class SufficitManagementContextClaimsTransformation(
    IManagementEntitlementResolver entitlementResolver,
    IOptions<ManagementOptions> options) : IClaimsTransformation
{
    public async Task<ClaimsPrincipal> TransformAsync(
        ClaimsPrincipal principal)
    {
        ArgumentNullException.ThrowIfNull(principal);

        if (principal.Identity?.IsAuthenticated is not true)
        {
            return principal;
        }

        var objectAccess = options.Value.Authorization.ObjectAccess;
        if (string.IsNullOrWhiteSpace(objectAccess.ContextClaimType)
            || string.IsNullOrWhiteSpace(objectAccess.LegacyContextId))
        {
            return principal;
        }

        var contexts = principal.FindAll(objectAccess.ContextClaimType)
            .SelectMany(claim => claim.Value.Split(
                ' ',
                StringSplitOptions.RemoveEmptyEntries
                | StringSplitOptions.TrimEntries))
            .ToArray();
        if (contexts.Contains(objectAccess.LegacyContextId, StringComparer.Ordinal)
            || contexts.Length > 0)
        {
            return principal;
        }

        var entitlements = await entitlementResolver.ResolveAsync(principal);
        if (entitlements.Capabilities.Count is 0)
        {
            return principal;
        }

        var identity = principal.Identities.FirstOrDefault(
            candidate => candidate.IsAuthenticated);
        identity?.AddClaim(new Claim(
            objectAccess.ContextClaimType,
            objectAccess.LegacyContextId));

        return principal;
    }
}
