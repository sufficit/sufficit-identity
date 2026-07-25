using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Sufficit.Identity.Management.Provisioning;

namespace Sufficit.Identity.Management.Controllers;

/// <summary>
/// Previews and applies additive, versioned OpenIddict provisioning manifests.
/// Omitted clients and scopes are never deleted.
/// </summary>
[ApiController]
[Authorize(Policy = "sufficit-identity-management")]
[Route("api/provisioning/manifest")]
public sealed class ProvisioningController : ControllerBase
{
    private readonly OpenIddictManifestProvisioner _provisioner;

    public ProvisioningController(OpenIddictManifestProvisioner provisioner)
        => _provisioner = provisioner;

    /// <summary>
    /// Returns the create/update/unchanged plan without changing the database
    /// or resolving any secret references.
    /// </summary>
    [HttpPost("preview")]
    public async Task<IActionResult> Preview(
        [FromBody] IdentityProvisioningManifest manifest,
        CancellationToken cancellationToken)
    {
        try
        {
            return Ok(await _provisioner.PreviewAsync(manifest, cancellationToken));
        }
        catch (IdentityProvisioningManifestException exception)
        {
            return InvalidManifest(exception);
        }
    }

    /// <summary>
    /// Applies the additive plan. Creating a confidential client or rotating
    /// its secret requires an environment-specific IClientSecretResolver.
    /// </summary>
    [HttpPost("apply")]
    public async Task<IActionResult> Apply(
        [FromBody] IdentityProvisioningManifest manifest,
        CancellationToken cancellationToken)
    {
        try
        {
            return Ok(await _provisioner.ApplyAsync(manifest, cancellationToken));
        }
        catch (IdentityProvisioningManifestException exception)
        {
            return InvalidManifest(exception);
        }
    }

    private BadRequestObjectResult InvalidManifest(
        IdentityProvisioningManifestException exception)
    {
        var details = new ProblemDetails
        {
            Status = StatusCodes.Status400BadRequest,
            Title = "Invalid identity provisioning manifest",
            Detail = "No database changes were made.",
        };
        details.Extensions["errors"] = exception.Errors;

        return BadRequest(details);
    }
}
