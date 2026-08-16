using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
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

    /// <summary>
    /// Plaintext resolution for authorized service principals. Querystring on
    /// purpose: the literal segment keeps it out of the catch-all metadata
    /// route ("resolve" can never be a secret name — names require a '/').
    /// 404 = absent, 410 = present but expired (value withheld).
    /// </summary>
    [HttpGet("resolve")]
    public async Task<ActionResult<ResolvedManagementVaultSecret>> Resolve(
        [FromQuery] string name,
        [FromQuery] string contextId = "global",
        CancellationToken cancellationToken = default)
    {
        var result = await secrets.ResolveAsync(
            name,
            contextId,
            RequestContext(),
            cancellationToken);
        if (result is null) return NotFound();
        return result.Status == VaultSecretStatus.Expired
            ? StatusCode(StatusCodes.Status410Gone, result)
            : Ok(result);
    }

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
