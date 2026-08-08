using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Sufficit.Identity.Management.Authorization;
using Sufficit.Identity.Management.Vault;

namespace Sufficit.Identity.Management.Controllers;

/// <summary>
/// Named-secret administration. Values are accepted only on PUT and are never
/// returned by this API; GET exposes metadata so operators can audit rotation.
/// </summary>
[ApiController]
[Authorize(Policy = "sufficit-identity-management")]
[Route("api/vault/secrets")]
public sealed class VaultSecretsController(
    IVaultSecretsManagementService secrets) : ControllerBase
{
    [HttpGet]
    public async Task<ActionResult<IReadOnlyList<ManagementVaultSecret>>> List(
        CancellationToken cancellationToken) =>
        Ok(await secrets.ListAsync(RequestContext(), cancellationToken));

    [HttpGet("{*name}")]
    public async Task<ActionResult<ManagementVaultSecret>> Get(
        string name,
        CancellationToken cancellationToken)
    {
        var result = await secrets.GetAsync(name, RequestContext(), cancellationToken);
        return result is null ? NotFound() : Ok(result);
    }

    [HttpPut("{*name}")]
    public async Task<ActionResult<ManagementVaultSecret>> Put(
        string name,
        [FromBody] SaveManagementVaultSecret command,
        CancellationToken cancellationToken) =>
        Ok(await secrets.PutAsync(name, command, RequestContext(), cancellationToken));

    [HttpDelete("{*name}")]
    public async Task<IActionResult> Delete(
        string name,
        CancellationToken cancellationToken)
    {
        await secrets.DeleteAsync(name, RequestContext(), cancellationToken);
        return NoContent();
    }

    private ManagementRequestContext RequestContext() =>
        new(User, HttpContext.TraceIdentifier);
}
