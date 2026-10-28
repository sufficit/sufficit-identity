using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Sufficit.Identity.Management.Authorization;
using Sufficit.Identity.Management.SystemUsers;

namespace Sufficit.Identity.Management.Controllers;

/// <summary>
/// System users (never sign in) and their enrollment codes. Identifiers go in
/// the query string. The code is returned only by <see cref="IssueEnrollment"/>.
/// </summary>
/// <remarks>
/// Canonical route: <c>api/users/system</c> (the users resource with the
/// <c>.system</c> qualifier, like <c>identity.users.system</c>). The literal
/// segment outranks <c>api/users/{id}</c> in route precedence, so it never
/// reaches the users controller. <c>api/system-users</c> stays as an alias.
/// </remarks>
[ApiController]
[Authorize(Policy = "sufficit-identity-management")]
[Route(CanonicalRoute)]
[Route(LegacyRoute)]
public sealed class SystemUsersController(ISystemUserManagementService systemUsers) : ControllerBase
{
    public const string CanonicalRoute = "api/users/system";
    public const string LegacyRoute = "api/system-users";

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

    /// <summary>Confidential clients that act as the system user (client_credentials).</summary>
    [HttpGet("clients")]
    public async Task<ActionResult<IReadOnlyList<SystemUserClientSummary>>> ListClients(
        [FromQuery] string userId,
        CancellationToken cancellationToken) =>
        Ok(await systemUsers.ListClientsAsync(userId, RequestContext(), cancellationToken));

    [HttpPut("clients")]
    public async Task<ActionResult<SystemUserClientSummary>> BindClient(
        [FromQuery] string userId,
        [FromQuery] string clientId,
        CancellationToken cancellationToken) =>
        Ok(await systemUsers.BindClientAsync(userId, clientId, RequestContext(), cancellationToken));

    [HttpDelete("clients")]
    public async Task<IActionResult> UnbindClient(
        [FromQuery] string userId,
        [FromQuery] string clientId,
        CancellationToken cancellationToken)
    {
        await systemUsers.UnbindClientAsync(userId, clientId, RequestContext(), cancellationToken);
        return NoContent();
    }

    private ManagementRequestContext RequestContext() => new(User, HttpContext.TraceIdentifier);
}

/// <summary>
/// Legacy entitlements of a system user, only on <c>api/system-users</c>.
/// </summary>
/// <remarks>
/// OBSOLETE — kept working for the transition. Entitlements are ordinary
/// <c>entitlements</c> claims: use <c>/api/claims</c> with
/// <c>identity.claims.system</c> (every claims action, only on system
/// users). <c>identity.users.system</c> still satisfies these two routes until
/// they are removed. Not offered on the canonical <c>api/users/system</c>.
/// </remarks>
[Obsolete("Use /api/claims with identity.claims.system.")]
[ApiController]
[Authorize(Policy = "sufficit-identity-management")]
[Route(SystemUsersController.LegacyRoute + "/entitlements")]
public sealed class SystemUserEntitlementsController(ISystemUserManagementService systemUsers) : ControllerBase
{
    [HttpGet]
    public async Task<ActionResult<IReadOnlyList<string>>> GetEntitlements(
        [FromQuery] string userId,
        CancellationToken cancellationToken) =>
        Ok(await systemUsers.GetEntitlementsAsync(userId, RequestContext(), cancellationToken));

    [HttpPut]
    public async Task<ActionResult<IReadOnlyList<string>>> SetEntitlements(
        [FromQuery] string userId,
        [FromBody] SetSystemUserEntitlementsCommand command,
        CancellationToken cancellationToken) =>
        Ok(await systemUsers.SetEntitlementsAsync(userId, command, RequestContext(), cancellationToken));

    private ManagementRequestContext RequestContext() => new(User, HttpContext.TraceIdentifier);
}
