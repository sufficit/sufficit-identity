using System.Security.Claims;
using Microsoft.Extensions.Options;
using Sufficit.Identity.Management;
using Sufficit.Identity.Management.Authorization;

namespace Sufficit.Identity.Server.Management;

/// <summary>
/// Sufficit host adapter for provider-operator access. The company-specific
/// administrator role is mapped at composition time and never becomes part of
/// the generic managed-user model. The former tenant-membership condition was
/// removed with the internal multi-tenant system (2026-08 decision): the
/// administrator role alone grants every capability.
/// </summary>
public sealed class SufficitOperatorManagementEntitlementResolver(
    IOptions<ManagementOptions> options) : IManagementEntitlementResolver
{
    private const string SufficitAdministratorRole = "administrator";
    private readonly ScopeAndRoleManagementEntitlementResolver generic =
        new(options);

    public async ValueTask<ManagementEntitlements> ResolveAsync(
        ClaimsPrincipal principal,
        CancellationToken cancellationToken = default)
    {
        var resolved = await generic.ResolveAsync(
            principal,
            cancellationToken);
        if (!principal.IsInRole(SufficitAdministratorRole))
        {
            return resolved;
        }

        var capabilities = new HashSet<string>(
            resolved.Capabilities,
            StringComparer.Ordinal);
        capabilities.UnionWith(ManagementCapabilities.All);
        return new ManagementEntitlements(capabilities);
    }
}
