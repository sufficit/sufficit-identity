using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Sufficit.Identity.Management.Authorization;
using Sufficit.Identity.Management.Vault;

namespace Sufficit.Identity.Management.Controllers;

/// <summary>
/// Metadata-only administration of user Vaults. Secret values are never
/// returned; deletion endpoints require the Vault management capability.
/// </summary>
[ApiController]
[Authorize(Policy = "sufficit-identity-management")]
[Route("api/vault/users")]
public sealed class VaultUsersController(
    IUserVaultManagementService vaultUsers) : ControllerBase
{
    [HttpGet]
    public async Task<ActionResult<VaultUserInventoryPage>> List(
        [FromQuery] string? search = null,
        [FromQuery] int offset = 0,
        [FromQuery] int limit = 25,
        CancellationToken cancellationToken = default) =>
        Ok(await vaultUsers.ListUsersAsync(
            new VaultUserInventoryQuery(search, offset, limit),
            RequestContext(),
            cancellationToken));

    [HttpGet("{ownerSubject}")]
    public async Task<ActionResult<VaultUserDetail>> Get(
        string ownerSubject,
        CancellationToken cancellationToken = default)
    {
        var result = await vaultUsers.GetUserAsync(
            ownerSubject,
            RequestContext(),
            cancellationToken);
        return result is null ? NotFound() : Ok(result);
    }

    [HttpDelete("{ownerSubject}/personal")]
    public async Task<IActionResult> DeletePersonal(
        string ownerSubject,
        [FromQuery] string @namespace,
        [FromQuery] string name,
        CancellationToken cancellationToken = default)
    {
        await vaultUsers.DeletePersonalSecretAsync(
            ownerSubject,
            @namespace,
            name,
            RequestContext(),
            cancellationToken);
        return NoContent();
    }

    [HttpDelete("{ownerSubject}/credentials")]
    public async Task<IActionResult> DeleteManaged(
        string ownerSubject,
        [FromQuery] string name,
        CancellationToken cancellationToken = default)
    {
        await vaultUsers.DeleteManagedCredentialAsync(
            ownerSubject,
            name,
            RequestContext(),
            cancellationToken);
        return NoContent();
    }

    [HttpDelete("{ownerSubject}")]
    public async Task<ActionResult<VaultUserCleanupResult>> Clear(
        string ownerSubject,
        CancellationToken cancellationToken = default) =>
        Ok(await vaultUsers.ClearUserAsync(
            ownerSubject,
            RequestContext(),
            cancellationToken));

    private ManagementRequestContext RequestContext() =>
        new(User, HttpContext.TraceIdentifier);
}
