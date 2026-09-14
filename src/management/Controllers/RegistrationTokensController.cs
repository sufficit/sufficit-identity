using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Sufficit.Identity.Management.Authorization;
using Sufficit.Identity.Management.Registration;

namespace Sufficit.Identity.Management.Controllers;

/// <summary>
/// Initial access tokens for RFC 7591 dynamic client registration. The token
/// value is returned only by <see cref="Issue"/>.
/// </summary>
[ApiController]
[Authorize(Policy = "sufficit-identity-management")]
[Route("api/registration-tokens")]
public sealed class RegistrationTokensController(
    IDcrInitialAccessTokenManagementService tokens) : ControllerBase
{
    [HttpGet]
    public async Task<ActionResult<IReadOnlyList<DcrInitialAccessTokenSummary>>> List(
        CancellationToken cancellationToken) =>
        Ok(await tokens.ListAsync(RequestContext(), cancellationToken));

    [HttpPost]
    public async Task<ActionResult<DcrInitialAccessTokenIssueResult>> Issue(
        [FromBody] IssueDcrInitialAccessTokenCommand command,
        CancellationToken cancellationToken) =>
        Ok(await tokens.IssueAsync(command, RequestContext(), cancellationToken));

    [HttpDelete("{id:guid}")]
    public async Task<IActionResult> Revoke(
        Guid id,
        CancellationToken cancellationToken)
    {
        await tokens.RevokeAsync(id, RequestContext(), cancellationToken);
        return NoContent();
    }

    private ManagementRequestContext RequestContext() =>
        new(User, HttpContext.TraceIdentifier);
}
