using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
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
/// <para><b>When it runs.</b> On authorization_code, refresh_token and
/// device_code. Running on refresh is deliberate — it repairs access for tokens
/// issued before scope-based entitlements existed — but it has a real cost:
/// removing the claim from a user does NOT survive that user's next refresh.
/// <b>An entitlement revocation must therefore be paired with revoking the
/// user's active grants</b>, which the management API already supports. The two
/// behaviours (backfill on refresh, revocation that sticks) are mutually
/// exclusive; this codebase chose backfill.
/// It does NOT run on the password grant, which has no approval step at all —
/// a scope obtained through ROPC was never consented to.</para>
/// <para><b>Where it can be declared.</b> Only the provisioning manifest
/// (<c>entitlementClaims</c>) writes the scope property today, plus the
/// optional configuration map above. The management API's scope endpoints do
/// NOT expose it — granting a persisted claim to every user who approves a
/// scope is a privilege-granting surface, and adding it needs deliberate
/// capability gating rather than riding on ordinary scope editing.</para>
/// </remarks>
public sealed class ScopeEntitlementProvisioner(
    UserManager<ApplicationUser> userManager,
    SufficitIdentityOptions options,
    ILogger<ScopeEntitlementProvisioner> logger,
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

            try
            {
                claims.AddRange(ScopeEntitlements.Read(
                    await scopes.GetPropertiesAsync(scope, cancellationToken)));
            }
            catch (Exception exception)
                when (exception is JsonException or InvalidOperationException)
            {
                // ScopeEntitlements.Read tolerates a malformed ENTRY, but a
                // properties column that is not valid JSON throws inside
                // GetPropertiesAsync — before Read ever runs. Letting that
                // escape would take the whole grant down for every user of the
                // scope, turning one bad row into an outage. An entitlement is
                // an additive grant, so degrading to "not granted" is the safe
                // direction; the scope itself still works.
                logger.LogError(
                    exception,
                    "Scope {Scope} has unreadable entitlement properties; no "
                    + "entitlement was applied for it.",
                    name);
            }
        }

        return claims;
    }

    private IReadOnlyList<ScopeEntitlementClaim> ReadFromConfiguration(
        IReadOnlySet<string> approvedScopes) =>
        options.ScopeEntitlements.Grants
            .Where(grant => approvedScopes.Contains(grant.Key))
            .SelectMany(grant => grant.Value)
            // The same claim-type rule as the database path: an entitlement
            // must not mint authorization regardless of where it was declared.
            // Filtering only the database path would have left configuration as
            // an open door to the very escalation the rule exists to stop.
            .Where(claim =>
                ScopeEntitlements.IsGrantableClaimType(claim.Type)
                && !string.IsNullOrWhiteSpace(claim.Value))
            .Select(claim => new ScopeEntitlementClaim(
                claim.Type.Trim(),
                claim.Value.Trim()))
            .ToArray();
}
