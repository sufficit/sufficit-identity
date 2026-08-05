using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Sufficit.Identity.Management.Authorization;
using Sufficit.Identity.Management.Users;

namespace Sufficit.Identity.Management.Controllers;

/// <summary>
/// HTTP adapter for identity-account administration. Authorization and
/// validation live in the shared application service used by this controller
/// and the embedded UI.
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
        [FromQuery] int page = 1,
        [FromQuery] int pageSize = 25,
        [FromQuery] DateOnly? registeredFrom = null,
        [FromQuery] DateOnly? registeredTo = null,
        [FromQuery] DateOnly? registeredOn = null,
        [FromQuery] ManagementUserStateFilter state = ManagementUserStateFilter.All,
        [FromQuery] ManagementUserBooleanFilter emailConfirmed = ManagementUserBooleanFilter.All,
        [FromQuery] ManagementUserBooleanFilter mfa = ManagementUserBooleanFilter.All,
        [FromQuery] ManagementUserSort sort = ManagementUserSort.CreatedNewest,
        [FromQuery] int analyticsDays = 30,
        [FromQuery] ManagementUserReviewFilter review = ManagementUserReviewFilter.All,
        CancellationToken cancellationToken = default) =>
        Ok(await users.SearchAsync(
            new ManagementUserSearch(
                search, page, pageSize, registeredFrom, registeredTo,
                registeredOn, state, emailConfirmed, mfa, sort, analyticsDays,
                review),
            RequestContext(),
            cancellationToken));

    [HttpGet("{id}")]
    public async Task<ActionResult<ManagementUserDetail>> Get(
        string id,
        CancellationToken cancellationToken) =>
        Ok(await users.GetAsync(
            id,
            RequestContext(),
            cancellationToken));

    [HttpPost]
    public async Task<ActionResult<ManagementUserDetail>> Create(
        [FromBody] CreateManagementUserCommand command,
        CancellationToken cancellationToken) =>
        Ok(await users.CreateAsync(
            command,
            RequestContext(),
            cancellationToken));

    [HttpPut("{id}/profile")]
    public async Task<ActionResult<ManagementUserDetail>> UpdateProfile(
        string id,
        [FromBody] UpdateManagementUserProfileCommand command,
        CancellationToken cancellationToken) =>
        Ok(await users.UpdateProfileAsync(
            id,
            command,
            RequestContext(),
            cancellationToken));

    [HttpPost("{id}/reset-password")]
    public async Task<ActionResult<ManagementUserDetail>> ResetPassword(
        string id,
        [FromBody] ResetManagementUserPasswordCommand command,
        CancellationToken cancellationToken) =>
        Ok(await users.ResetPasswordAsync(
            id,
            command,
            RequestContext(),
            cancellationToken));

    [HttpPost("{id}/lockout")]
    public async Task<ActionResult<ManagementUserDetail>> SetLockout(
        string id,
        [FromBody] SetManagementUserLockoutCommand command,
        CancellationToken cancellationToken) =>
        Ok(await users.SetLockoutAsync(
            id,
            command,
            RequestContext(),
            cancellationToken));

    [HttpPost("{id}/resend-confirmation")]
    public async Task<IActionResult> ResendConfirmation(
        string id,
        CancellationToken cancellationToken)
    {
        await users.RequestEmailConfirmationAsync(
            id,
            RequestContext(),
            cancellationToken);
        return NoContent();
    }

    [HttpDelete("{id}")]
    public async Task<IActionResult> Delete(
        string id,
        CancellationToken cancellationToken)
    {
        await users.DeleteAsync(
            id,
            RequestContext(),
            cancellationToken);
        return NoContent();
    }

    private ManagementRequestContext RequestContext() =>
        new(User, HttpContext.TraceIdentifier);
}
