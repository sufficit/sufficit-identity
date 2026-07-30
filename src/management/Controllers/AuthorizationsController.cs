using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Sufficit.Identity.Management.Authorization;
using Sufficit.Identity.Management.Authorizations;

namespace Sufficit.Identity.Management.Controllers;

/// <summary>
/// HTTP adapter for OAuth/OpenID Connect authorizations and consents.
/// </summary>
[ApiController]
[Authorize(Policy = "sufficit-identity-management")]
[Route("api/authorizations")]
public sealed class AuthorizationsController(
    IAuthorizationManagementService authorizations) : ControllerBase
{
    [HttpGet]
    public async Task<ActionResult<ManagementAuthorizationPage>> Search(
        [FromQuery] string? search,
        [FromQuery] string? userId,
        [FromQuery] string? clientId,
        [FromQuery] bool activeOnly = true,
        [FromQuery] int page = 1,
        [FromQuery] int pageSize = 25,
        CancellationToken cancellationToken = default) =>
        Ok(await authorizations.SearchAsync(
            new ManagementAuthorizationSearch(
                search,
                userId,
                clientId,
                activeOnly,
                page,
                pageSize),
            RequestContext(),
            cancellationToken));

    [HttpDelete("{id}")]
    public async Task<IActionResult> Revoke(
        string id,
        CancellationToken cancellationToken)
    {
        await authorizations.RevokeAsync(
            id,
            RequestContext(),
            cancellationToken);
        return NoContent();
    }

    private ManagementRequestContext RequestContext() =>
        new(User, HttpContext.TraceIdentifier);
}
