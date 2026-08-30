using Sufficit.Identity.Management.Authorization;
using Sufficit.Identity.Application.Security;

namespace Sufficit.Identity.Management.Provisioning;

/// <summary>
/// Canonical application boundary for declarative OpenIddict provisioning.
/// HTTP and embedded UI adapters must both use this service.
/// </summary>
public interface IProvisioningManagementService
{
    /// <summary>
    /// Returns a read-only ownership/drift inventory. The operation never
    /// resolves secrets and never changes OpenIddict state.
    /// </summary>
    Task<IdentityProvisioningInventory> InventoryAsync(
        IdentityProvisioningManifest manifest,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default) =>
        throw new NotSupportedException(
            "This provisioning adapter does not support inventory queries.");

    Task<IdentityProvisioningPlan> PreviewAsync(
        IdentityProvisioningManifest manifest,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default);

    Task<IdentityProvisioningPlan> ApplyAsync(
        IdentityProvisioningManifest manifest,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default);
}
