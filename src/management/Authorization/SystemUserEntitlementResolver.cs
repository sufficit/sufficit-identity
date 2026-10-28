using System.Security.Claims;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.Core.Services;

namespace Sufficit.Identity.Management.Authorization;

/// <summary>
/// Capabilities of a SYSTEM USER, read from its roles at check time.
///
/// A system user is software acting as a user (see
/// <see cref="SystemUserClientBinding"/>). It gets management capabilities the
/// same way a person does, from its roles mapped by <c>RoleCapabilities</c>,
/// with two differences that come from being software:
///
/// - <b>roles are read now, not from the token.</b> Removing a role, or
///   disabling the user, stops the next call instead of waiting for the token
///   to expire. A person's roles ride in the token; a compromised service is
///   the case where waiting is not acceptable.
/// - <b>what the roles grant is MFA-exempt.</b> A system user has nothing to
///   present a second factor with; requiring one is a permanent denial, not a
///   gate. Its control is the client secret (or bound key), the roles the
///   database gives it and what configuration says those roles allow.
///
/// Anything that is not a system user passes through unchanged.
/// </summary>
public sealed class SystemUserEntitlementResolver(
    IManagementEntitlementResolver inner,
    SystemUserStore systemUsers,
    UserManager<ApplicationUser> users,
    IServicePrincipalRoleSource clientRoles,
    IOptions<ManagementOptions> options) : IManagementEntitlementResolver
{
    public async ValueTask<ManagementEntitlements> ResolveAsync(
        ClaimsPrincipal principal,
        CancellationToken cancellationToken = default)
    {
        var resolved = await inner.ResolveAsync(principal, cancellationToken);
        if (ManagementPrincipal.IsService(principal))
        {
            return resolved;
        }

        var subject = principal.FindFirst("sub")?.Value
            ?? principal.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (string.IsNullOrWhiteSpace(subject)
            || !await systemUsers.IsSystemUserAsync(subject, cancellationToken))
        {
            return resolved;
        }

        var none = new HashSet<string>(StringComparer.Ordinal);
        var user = await users.FindByIdAsync(subject);
        if (user is null || await users.IsLockedOutAsync(user))
        {
            return new ManagementEntitlements(none, none);
        }

        var roles = new List<string>(await users.GetRolesAsync(user));

        // Transition: a client that used to carry roles itself keeps them
        // while it is moved to its system user.
        var clientId = ManagementPrincipal.ClientId(principal);
        if (!string.IsNullOrWhiteSpace(clientId))
        {
            roles.AddRange(await clientRoles.RolesAsync(clientId, cancellationToken));
        }

        var granted = Map(roles, options.Value.Authorization);

        // Replaces, not adds to, what the token said: roles stamped at
        // issuance are exactly what must not outlive a revocation.
        return new ManagementEntitlements(granted, granted);
    }

    internal static HashSet<string> Map(
        IEnumerable<string> roles,
        ManagementAuthorizationOptions authorization)
    {
        var granted = new HashSet<string>(StringComparer.Ordinal);
        foreach (var role in roles)
        {
            if (authorization.FullAdministratorRoles.Contains(role, StringComparer.OrdinalIgnoreCase))
            {
                granted.UnionWith(ManagementCapabilities.All);
                continue;
            }

            if (!authorization.RoleCapabilities.TryGetValue(role, out var mapped))
            {
                continue;
            }

            foreach (var raw in mapped ?? [])
            {
                var capability = ManagementCapabilities.Normalize(raw);
                if (ManagementCapabilities.All.Contains(capability))
                {
                    granted.Add(capability);
                }
            }
        }

        return granted;
    }
}
