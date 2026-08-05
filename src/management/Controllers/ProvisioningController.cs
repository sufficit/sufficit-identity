using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Sufficit.Identity.Management.Authorization;
using Sufficit.Identity.Management.Provisioning;

namespace Sufficit.Identity.Management.Controllers;

/// <summary>
/// Previews and applies additive, versioned OpenIddict provisioning manifests.
/// Omitted clients and scopes are never deleted.
/// </summary>
[ApiController]
[Authorize(Policy = "sufficit-identity-management")]
[Route("api/provisioning/manifest")]
public sealed class ProvisioningController(
    IProvisioningManagementService provisioning) : ControllerBase
{
    /// <summary>
    /// Returns the create/update/unchanged plan without changing the database
    /// or resolving any secret references.
    /// </summary>
    [HttpPost("preview")]
    public async Task<ActionResult<IdentityProvisioningPlan>> Preview(
        [FromBody] IdentityProvisioningManifest manifest,
        CancellationToken cancellationToken) =>
        Ok(await provisioning.PreviewAsync(
            manifest,
            RequestContext(),
            cancellationToken));

    /// <summary>
    /// Applies the additive plan. Creating a confidential client or rotating
    /// its secret requires an environment-specific IClientSecretResolver.
    /// </summary>
    [HttpPost("apply")]
    public async Task<ActionResult<IdentityProvisioningPlan>> Apply(
        [FromBody] IdentityProvisioningManifest manifest,
        CancellationToken cancellationToken) =>
        Ok(await provisioning.ApplyAsync(
            manifest,
            RequestContext(),
            cancellationToken));

    private ManagementRequestContext RequestContext() =>
        new(User, HttpContext.TraceIdentifier);
}
