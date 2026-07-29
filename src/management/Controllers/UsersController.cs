using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Sufficit.Identity.Management.Authorization;
using Sufficit.Identity.Management.Users;

namespace Sufficit.Identity.Management.Controllers;

/// <summary>
/// HTTP adapter for contextual user discovery. Mutations are deliberately
/// absent until multi-context account semantics are defined.
/// </summary>
[ApiController]
[Authorize(Policy = "sufficit-identity-management")]
[Route("api/users")]
public sealed class UsersController(IUserManagementService users)
    : ControllerBase
{
    [HttpGet("access")]
    public async Task<ActionResult<ManagementUserAccess>> GetAccess(
        CancellationToken cancellationToken) =>
        Ok(await users.GetAccessAsync(RequestContext(), cancellationToken));

    [HttpGet]
    public async Task<ActionResult<ManagementUserPage>> Search(
        [FromQuery] string? search,
        [FromQuery] string? contextId,
        [FromQuery] int page = 1,
        [FromQuery] int pageSize = 25,
        CancellationToken cancellationToken = default) =>
        Ok(await users.SearchAsync(
            new ManagementUserSearch(search, contextId, page, pageSize),
            RequestContext(),
            cancellationToken));

    [HttpGet("{id}")]
    public async Task<ActionResult<ManagementUserDetail>> Get(
        string id,
        [FromQuery] string? contextId,
        CancellationToken cancellationToken) =>
        Ok(await users.GetAsync(
            id,
            contextId,
            RequestContext(),
            cancellationToken));

    private ManagementRequestContext RequestContext() =>
        new(User, HttpContext.TraceIdentifier);
}
