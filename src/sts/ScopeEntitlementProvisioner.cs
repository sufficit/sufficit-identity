using System.Security.Claims;
using Microsoft.AspNetCore.Identity;
using OpenIddict.Abstractions;
using Sufficit.Identity.Application.Security;
using Sufficit.Identity.Core.Entities;

namespace Sufficit.Identity.STS;

/// <summary>
/// Applies the persisted claims a scope entitles when a user approves it.
/// Repeated approvals do not duplicate claims.
/// </summary>
/// <remarks>
/// <b>The scope record is the source of truth.</b> Entitlements are read from
/// the approved scope's own OpenIddict registration
/// (<see cref="ScopeEntitlements"/>), so the policy is declared once — through
/// the provisioning manifest or the management API — and reaches every replica
/// through the database, exactly as the scope itself does. That is what removes
/// the per-server configuration edit this used to require (eval 2026-08-30,
/// F-2).
/// <para><see cref="ScopeEntitlementOptions.Grants"/> remains supported and is
/// merged on top, for a deployment that prefers to pin the policy in its own
/// configuration. It is empty by default, so the ordinary path costs nothing.
/// </para>
/// </remarks>
public sealed class ScopeEntitlementProvisioner(
    UserManager<ApplicationUser> userManager,
    SufficitIdentityOptions options,
    IOpenIddictScopeManager? scopes = null)
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
            .Select(scope => scope.Trim())
            .ToHashSet(StringComparer.Ordinal);
        if (scopeSet.Count == 0)
        {
            return IdentityResult.Success;
        }

        var entitlements = new List<ScopeEntitlementClaim>();
        entitlements.AddRange(await ReadFromScopeRecordsAsync(scopeSet, cancellationToken));
        entitlements.AddRange(ReadFromConfiguration(scopeSet));

        if (entitlements.Count == 0)
        {
            return IdentityResult.Success;
        }

        var existing = (await userManager.GetClaimsAsync(user))
            .Select(claim => (claim.Type, claim.Value))
            .ToHashSet();
        var additions = entitlements
            // Add() returning false covers both a claim the user already holds
            // and the same entitlement declared in two places.
            .Where(claim => existing.Add((claim.Type, claim.Value)))
            .Select(claim => new Claim(claim.Type, claim.Value))
            .ToList();

        if (additions.Count == 0)
        {
            return IdentityResult.Success;
        }

        cancellationToken.ThrowIfCancellationRequested();
        return await userManager.AddClaimsAsync(user, additions);
    }

    private async Task<IReadOnlyList<ScopeEntitlementClaim>> ReadFromScopeRecordsAsync(
        IReadOnlySet<string> approvedScopes,
        CancellationToken cancellationToken)
    {
        if (scopes is null)
        {
            return [];
        }

        var claims = new List<ScopeEntitlementClaim>();
        foreach (var name in approvedScopes)
        {
            var scope = await scopes.FindByNameAsync(name, cancellationToken);
            if (scope is null)
            {
                continue;
            }

            claims.AddRange(ScopeEntitlements.Read(
                await scopes.GetPropertiesAsync(scope, cancellationToken)));
        }

        return claims;
    }

    private IReadOnlyList<ScopeEntitlementClaim> ReadFromConfiguration(
        IReadOnlySet<string> approvedScopes) =>
        options.ScopeEntitlements.Grants
            .Where(grant => approvedScopes.Contains(grant.Key))
            .SelectMany(grant => grant.Value)
            .Where(claim =>
                !string.IsNullOrWhiteSpace(claim.Type)
                && !string.IsNullOrWhiteSpace(claim.Value))
            .Select(claim => new ScopeEntitlementClaim(
                claim.Type.Trim(),
                claim.Value.Trim()))
            .ToArray();
}
