using System.Security.Claims;
using Microsoft.Extensions.Options;

namespace Sufficit.Identity.Management.Authorization;

/// <summary>
/// Capabilities of a MACHINE principal, read from the client registration.
///
/// A <c>client_credentials</c> token goes through none of the common
/// resolver's capability sources: the <c>permission</c> claim is only issued
/// from an authenticated operator, and the client holds no user role at all.
/// Before this, the only way to grant management access to a service was to
/// put it in an administrator role — trading "can do nothing" for "can do
/// everything".
///
/// The grant lives in the DATABASE, in the client's own
/// <c>identity:client:roles</c> property, exactly like a human's lives in
/// <c>userroles</c>. What the role means stays in <c>RoleCapabilities</c>,
/// which is reviewed config. It's the same split that already applied to
/// people: the database says who is what, the configuration says what that
/// allows.
///
/// Two consequences drove this design, rather than the alternative of
/// declaring capabilities directly in configuration:
///
/// - <b>revoking doesn't require a deployment.</b> Removing the role is an
///   UPDATE. In a configuration, revoking access from a compromised service
///   would depend on publishing — and publishing is exactly what breaks first
///   on a bad day;
/// - <b>revoking takes effect immediately.</b> The lookup happens at check
///   time, not at token issuance. A capability stamped inside the token
///   survives revocation until it expires.
/// </summary>
public sealed class ServicePrincipalEntitlementResolver(
    IManagementEntitlementResolver inner,
    IServicePrincipalRoleSource roles,
    IOptions<ManagementOptions> options) : IManagementEntitlementResolver
{
    public async ValueTask<ManagementEntitlements> ResolveAsync(
        ClaimsPrincipal principal,
        CancellationToken cancellationToken = default)
    {
        var resolved = await inner.ResolveAsync(principal, cancellationToken);

        if (!ManagementPrincipal.IsService(principal))
        {
            return resolved;
        }

        var clientId = ManagementPrincipal.ClientId(principal);
        if (string.IsNullOrWhiteSpace(clientId))
        {
            return resolved;
        }

        var declared = await roles.RolesAsync(clientId, cancellationToken);
        if (declared.Count == 0)
        {
            return resolved;
        }

        var authorization = options.Value.Authorization;
        var capabilities = new HashSet<string>(resolved.Capabilities, StringComparer.Ordinal);
        var machine = new HashSet<string>(StringComparer.Ordinal);

        foreach (var role in declared)
        {
            if (authorization.FullAdministratorRoles.Contains(role, StringComparer.OrdinalIgnoreCase))
            {
                // A service in a full administrator role is a deployment
                // decision, and it still holds — but it's made explicit here
                // instead of happening by accident.
                machine.UnionWith(ManagementCapabilities.All);
                continue;
            }

            if (!authorization.RoleCapabilities.TryGetValue(role, out var mapped))
            {
                continue;
            }

            foreach (var raw in mapped ?? [])
            {
                var capability = ManagementCapabilities.Normalize(raw);
                // An unknown name is ignored: it already grants nothing, and
                // failing the whole resolution over a config typo would take
                // down the same client's valid capabilities too.
                if (ManagementCapabilities.All.Contains(capability))
                {
                    machine.Add(capability);
                }
            }
        }

        capabilities.UnionWith(machine);

        // Everything a machine receives is MFA-exempt, and nothing beyond
        // that.
        //
        // This isn't leniency: a principal authenticated with a client secret
        // never carries `amr`, so requiring a second factor from it isn't a
        // gate, it's a permanent denial. Its control is the roles the
        // database gives it and what the configuration says those roles
        // allow.
        return resolved with
        {
            Capabilities = capabilities,
            MultiFactorExempt = machine
        };
    }

}
