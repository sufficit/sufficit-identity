using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Sufficit.Identity.Management.Authorization;
using Sufficit.Identity.Management.OperatorTokens;

namespace Sufficit.Identity.Management.Controllers;

/// <summary>
/// Manages the authenticated operator's own short-lived, attenuated Management
/// tokens. The token value is returned only by <see cref="Issue"/>.
/// </summary>
[ApiController]
[Authorize(Policy = "sufficit-identity-management")]
[Route("api/operator-tokens")]
public sealed class OperatorTokensController(
    IOperatorTokenManagementService tokens) : ControllerBase
{
    [HttpGet]
    public async Task<ActionResult<OperatorTokenWorkspace>> Get(
        CancellationToken cancellationToken) =>
        Ok(await tokens.GetWorkspaceAsync(
            RequestContext(),
            cancellationToken));

    [HttpPost]
    public async Task<ActionResult<OperatorTokenIssueResult>> Issue(
        [FromBody] IssueOperatorTokenCommand command,
        CancellationToken cancellationToken) =>
        Ok(await tokens.IssueAsync(
            command,
            RequestContext(),
            cancellationToken));

    [HttpDelete("{id}")]
    public async Task<IActionResult> Revoke(
        string id,
        CancellationToken cancellationToken)
    {
        await tokens.RevokeAsync(
            id,
            RequestContext(),
            cancellationToken);
        return NoContent();
    }

    private ManagementRequestContext RequestContext() =>
        new(User, HttpContext.TraceIdentifier);
}
