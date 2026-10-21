using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Sufficit.Identity.Management.Authorization;
using Sufficit.Identity.Management.SystemUsers;

namespace Sufficit.Identity.Management.Controllers;

/// <summary>
/// System users (never sign in) and their enrollment codes. Identifiers go in
/// the query string. The code is returned only by <see cref="IssueEnrollment"/>.
/// </summary>
[ApiController]
[Authorize(Policy = "sufficit-identity-management")]
[Route("api/system-users")]
public sealed class SystemUsersController(ISystemUserManagementService systemUsers) : ControllerBase
{
    [HttpGet]
    public async Task<ActionResult<IReadOnlyList<SystemUserSummary>>> List(CancellationToken cancellationToken) =>
        Ok(await systemUsers.ListAsync(RequestContext(), cancellationToken));

    [HttpPost]
    public async Task<ActionResult<SystemUserSummary>> Create(
        [FromBody] CreateSystemUserCommand command,
        CancellationToken cancellationToken) =>
        Ok(await systemUsers.CreateAsync(command, RequestContext(), cancellationToken));

    /// <summary><paramref name="enabled"/> null inverts the current state.</summary>
    [HttpPatch("toggle")]
    public async Task<ActionResult<SystemUserSummary>> Toggle(
        [FromQuery] string userId,
        [FromQuery] bool? enabled,
        CancellationToken cancellationToken) =>
        Ok(await systemUsers.ToggleAsync(userId, enabled, RequestContext(), cancellationToken));

    [HttpGet("enrollments")]
    public async Task<ActionResult<IReadOnlyList<SystemUserEnrollmentSummary>>> ListEnrollments(
        [FromQuery] string userId,
        CancellationToken cancellationToken) =>
        Ok(await systemUsers.ListEnrollmentsAsync(userId, RequestContext(), cancellationToken));

    [HttpPost("enrollments")]
    public async Task<ActionResult<SystemUserEnrollmentIssueResult>> IssueEnrollment(
        [FromQuery] string userId,
        [FromBody] IssueSystemUserEnrollmentCommand command,
        CancellationToken cancellationToken) =>
        Ok(await systemUsers.IssueEnrollmentAsync(userId, command, RequestContext(), cancellationToken));

    [HttpDelete("enrollments")]
    public async Task<IActionResult> RevokeEnrollment(
        [FromQuery] string userId,
        [FromQuery] Guid id,
        CancellationToken cancellationToken)
    {
        await systemUsers.RevokeEnrollmentAsync(userId, id, RequestContext(), cancellationToken);
        return NoContent();
    }

    private ManagementRequestContext RequestContext() => new(User, HttpContext.TraceIdentifier);
}
