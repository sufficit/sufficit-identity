using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Sufficit.Identity.Management.Authorization;
using Sufficit.Identity.Management.Provisioning;

namespace Sufficit.Identity.Management.Controllers;

/// <summary>
/// Issues a short-lived, provisioning-only Bearer token for an already
/// authenticated operator. The token value is never stored in audit data.
/// </summary>
[ApiController]
[Authorize(Policy = "sufficit-identity-management")]
[Route("api/provisioning/token")]
public sealed class ProvisioningTokenController(
    IProvisioningTokenManagementService tokens) : ControllerBase
{
    [HttpPost]
    public async Task<ActionResult<ProvisioningTokenIssueResult>> Issue(
        [FromBody] ProvisioningTokenIssueRequest? request,
        CancellationToken cancellationToken) =>
        Ok(await tokens.IssueAsync(
            new ManagementRequestContext(User, HttpContext.TraceIdentifier),
            request,
            cancellationToken));
}
