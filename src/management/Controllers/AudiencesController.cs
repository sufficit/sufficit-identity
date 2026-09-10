using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Sufficit.Identity.Management.Authorization;
using Sufficit.Identity.Management.Scopes;

namespace Sufficit.Identity.Management.Controllers;

/// <summary>Audiences are scope-resource bindings, not a second registry.</summary>
[ApiController]
[Authorize(Policy = "sufficit-identity-management")]
[Route("api/audiences")]
public sealed class AudiencesController(IScopeManagementService scopes) : ControllerBase
{
    [HttpGet]
    public async Task<ActionResult<ManagementAudienceInventory>> List(CancellationToken cancellationToken) =>
        Ok(await scopes.ListAudiencesAsync(new(User, HttpContext.TraceIdentifier), cancellationToken));

    [HttpPut("scopes/{scopeId}")]
    public async Task<ActionResult<ManagementScopeDetail>> UpdateBinding(string scopeId,
        [FromBody] UpdateAudienceBindingCommand command, CancellationToken cancellationToken) =>
        Ok(await scopes.UpdateAudienceBindingAsync(scopeId, command,
            new ManagementRequestContext(User, HttpContext.TraceIdentifier), cancellationToken));
}
