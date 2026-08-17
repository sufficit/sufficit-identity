using System.Security.Claims;
using Microsoft.AspNetCore.Identity;
using Sufficit.Identity.Core.Entities;

namespace Sufficit.Identity.STS;

/// <summary>
/// Applies configured persisted claims for scopes explicitly approved by a
/// user. Repeated approvals do not duplicate claims.
/// </summary>
public sealed class ScopeEntitlementProvisioner(
    UserManager<ApplicationUser> userManager,
    SufficitIdentityOptions options)
{
    public async Task<IdentityResult> ProvisionAsync(
        ApplicationUser user,
        IEnumerable<string> approvedScopes,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(user);
        ArgumentNullException.ThrowIfNull(approvedScopes);
        cancellationToken.ThrowIfCancellationRequested();

        var scopeSet = approvedScopes
            .Where(scope => !string.IsNullOrWhiteSpace(scope))
            .ToHashSet(StringComparer.Ordinal);
        var existing = (await userManager.GetClaimsAsync(user))
            .Select(claim => (claim.Type, claim.Value))
            .ToHashSet();
        var additions = new List<Claim>();

        foreach (var grant in options.ScopeEntitlements.Grants)
        {
            if (!scopeSet.Contains(grant.Key))
            {
                continue;
            }

            foreach (var configuredClaim in grant.Value)
            {
                if (string.IsNullOrWhiteSpace(configuredClaim.Type)
                    || string.IsNullOrWhiteSpace(configuredClaim.Value)
                    || !existing.Add((configuredClaim.Type, configuredClaim.Value)))
                {
                    continue;
                }

                additions.Add(new Claim(
                    configuredClaim.Type.Trim(),
                    configuredClaim.Value.Trim()));
            }
        }

        if (additions.Count == 0)
        {
            return IdentityResult.Success;
        }

        cancellationToken.ThrowIfCancellationRequested();
        return await userManager.AddClaimsAsync(user, additions);
    }
}
