using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Sufficit.Identity.Management.Authorization;
using Sufficit.Identity.Management.Sessions;
using Sufficit.Identity.Management.Users;

namespace Sufficit.Identity.Management.Controllers;

/// <summary>
/// HTTP adapter for provider-issued credentials and account-wide session
/// invalidation. Browser cookies are invalidated only by the account-wide
/// operation, which rotates the ASP.NET Identity security stamp.
/// </summary>
[ApiController]
[Authorize(Policy = "sufficit-identity-management")]
[Route("api/sessions")]
public sealed class SessionsController(ISessionManagementService sessions)
    : ControllerBase
{
    [HttpGet]
    public async Task<ActionResult<ManagementSessionPage>> Search(
        [FromQuery] string? search,
        [FromQuery] string? userId,
        [FromQuery] string? clientId,
        [FromQuery] bool activeOnly = true,
        [FromQuery] int page = 1,
        [FromQuery] int pageSize = 25,
        CancellationToken cancellationToken = default) =>
        Ok(await sessions.SearchAsync(
            new ManagementSessionSearch(
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
        await sessions.RevokeAsync(
            id,
            RequestContext(),
            cancellationToken);
        return NoContent();
    }

    [HttpDelete("users/{userId}")]
    public async Task<ActionResult<ManagementUserSessionRevocation>> RevokeAll(
        string userId,
        CancellationToken cancellationToken) =>
        Ok(await sessions.RevokeAllForUserAsync(
            userId,
            RequestContext(),
            cancellationToken));

    private ManagementRequestContext RequestContext() =>
        new(User, HttpContext.TraceIdentifier);
}
