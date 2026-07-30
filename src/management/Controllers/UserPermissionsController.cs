using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Sufficit.Identity.Management.Authorization;
using Sufficit.Identity.Management.Permissions;

namespace Sufficit.Identity.Management.Controllers;

/// <summary>
/// HTTP adapter for user role and contextual permission delegation. All
/// authorization, validation, revocation and audit behavior belongs to the
/// shared application service also used by the embedded UI.
/// </summary>
[ApiController]
[Authorize(Policy = "sufficit-identity-management")]
[Route("api/users/{userId}/permissions")]
public sealed class UserPermissionsController(
    IUserPermissionManagementService permissions) : ControllerBase
{
    [HttpGet]
    public async Task<ActionResult<ManagementUserPermissions>> Get(
        string userId,
        [FromQuery] string? contextId,
        CancellationToken cancellationToken) =>
        Ok(await permissions.GetAsync(
            userId,
            contextId,
            RequestContext(),
            cancellationToken));

    [HttpPut("roles")]
    public async Task<ActionResult<ManagementUserPermissions>> SetRole(
        string userId,
        [FromBody] SetManagementUserRoleCommand command,
        CancellationToken cancellationToken) =>
        Ok(await permissions.SetRoleAsync(
            userId,
            command,
            RequestContext(),
            cancellationToken));

    [HttpPut("contextual")]
    public async Task<ActionResult<ManagementUserPermissions>>
        SetContextualPermission(
            string userId,
            [FromBody] SetManagementUserContextualPermissionCommand command,
            CancellationToken cancellationToken) =>
        Ok(await permissions.SetContextualPermissionAsync(
            userId,
            command,
            RequestContext(),
            cancellationToken));

    private ManagementRequestContext RequestContext() =>
        new(User, HttpContext.TraceIdentifier);
}
