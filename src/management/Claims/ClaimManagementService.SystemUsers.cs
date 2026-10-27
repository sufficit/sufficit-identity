using Sufficit.Identity.Core.Services;
using Sufficit.Identity.Management.Authorization;

namespace Sufficit.Identity.Management.Claims;

/// <summary>
/// The <see cref="ManagementCapabilities.ClaimsSystem"/> qualifier: every
/// claims action, but only on claims whose owner is a system user.
/// </summary>
/// <remarks>
/// The general capability is tried first, so an operator holding both keeps
/// the unrestricted behavior. Only when it is missing does the system-only
/// qualifier apply, and then every operation must prove its owner is a system
/// user — recognized by <see cref="SystemUserStore.WhereSystemUser"/>, the one
/// rule the sign-in manager and the system-users API also use. For any other
/// owner the qualifier never satisfies anything: the attempt is refused under
/// the general capability, and mutations record the refusal like any other.
/// Reserved claim types are validated before any of this and still apply;
/// mutations carry the owner as <c>SubjectId</c>, so the protected-principal
/// policy still decides on the target.
/// </remarks>
internal sealed partial class ClaimManagementService
{
    internal const string OwnerNotSystemUserReason = "claim_owner_not_system_user";

    /// <param name="Decision">The decision that let the operation start.</param>
    /// <param name="SystemUsersOnly">
    /// Granted only through <see cref="ManagementCapabilities.ClaimsSystem"/>:
    /// every claim reached must belong to a system user.
    /// </param>
    private sealed record ClaimAccess(
        ManagementAuthorizationDecision Decision,
        bool SystemUsersOnly);

    /// <summary>
    /// <paramref name="capability"/> first, then
    /// <see cref="ManagementCapabilities.ClaimsSystem"/>; when neither is
    /// granted, the refusal is the general capability's (and audited when
    /// <paramref name="auditDenial"/> says so).
    /// </summary>
    private async Task<ClaimAccess> DemandClaimAccessAsync(
        ManagementRequestContext context,
        string capability,
        ManagementResource resource,
        CancellationToken cancellationToken,
        bool auditDenial = false)
    {
        try
        {
            return new(
                await guard.DemandAsync(context, capability, resource, cancellationToken),
                SystemUsersOnly: false);
        }
        catch (ManagementAccessException)
        {
        }

        try
        {
            return new(
                await guard.DemandAsync(
                    context, ManagementCapabilities.ClaimsSystem, resource, cancellationToken),
                SystemUsersOnly: true);
        }
        catch (ManagementAccessException)
        {
        }

        return new(
            await guard.DemandAsync(
                context, capability, resource, cancellationToken, auditDenial),
            SystemUsersOnly: false);
    }

    /// <summary>
    /// For an operation running on the system-only qualifier: refuses unless
    /// <paramref name="ownerId"/> is a system user, then decides again on
    /// <paramref name="resource"/> (which carries the owner as
    /// <c>SubjectId</c> on mutations, so protected principals still apply).
    /// </summary>
    private async Task<ManagementAuthorizationDecision> DemandSystemOwnerAsync(
        ManagementRequestContext context,
        string capability,
        ManagementResource resource,
        string? ownerId,
        CancellationToken cancellationToken,
        bool auditDenial = false)
    {
        if (!await SystemUserStore.IsSystemUserAsync(database, ownerId, cancellationToken))
        {
            return await guard.RefuseAsync(
                context,
                capability,
                resource,
                ManagementAuthorizationDecision.Denied(
                    OwnerNotSystemUserReason,
                    capability),
                cancellationToken,
                auditDenial);
        }

        return await guard.DemandAsync(
            context,
            ManagementCapabilities.ClaimsSystem,
            resource,
            cancellationToken,
            auditDenial);
    }
}
