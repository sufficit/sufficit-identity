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
        [FromQuery] string contextId = "global",
        CancellationToken cancellationToken = default) =>
        Ok(await secrets.ListAsync(contextId, RequestContext(), cancellationToken));

    [HttpGet("{*name}")]
    public async Task<ActionResult<ManagementVaultSecret>> Get(
        string name,
        [FromQuery] string contextId = "global",
        CancellationToken cancellationToken = default)
    {
        var result = await secrets.GetAsync(
            name,
            contextId,
            RequestContext(),
            cancellationToken);
        return result is null ? NotFound() : Ok(result);
    }

    [HttpPut("{*name}")]
    public async Task<ActionResult<ManagementVaultSecret>> Put(
        string name,
        [FromBody] SaveManagementVaultSecret command,
        [FromQuery] string contextId = "global",
        CancellationToken cancellationToken = default) =>
        Ok(await secrets.PutAsync(
            name,
            contextId,
            command,
            RequestContext(),
            cancellationToken));

    [HttpDelete("{*name}")]
    public async Task<IActionResult> Delete(
        string name,
        [FromQuery] string contextId = "global",
        CancellationToken cancellationToken = default)
    {
        await secrets.DeleteAsync(
            name,
            contextId,
            RequestContext(),
            cancellationToken);
        return NoContent();
    }

    private ManagementRequestContext RequestContext() =>
        new(User, HttpContext.TraceIdentifier);
}
