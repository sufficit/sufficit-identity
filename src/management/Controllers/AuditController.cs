using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Sufficit.Identity.Management.Audit;
using Sufficit.Identity.Management.Authorization;

namespace Sufficit.Identity.Management.Controllers;

/// <summary>Read-only HTTP adapter for administrative audit events.</summary>
[ApiController]
[Authorize(Policy = "sufficit-identity-management")]
[Route("api/audit")]
public sealed class AuditController(IManagementAuditService audit)
    : ControllerBase
{
    [HttpGet]
    public async Task<ActionResult<IReadOnlyList<ManagementAuditRecord>>> List(
        [FromQuery] int limit = 100,
        CancellationToken cancellationToken = default) =>
        Ok(await audit.ListAsync(
            new ManagementRequestContext(User, HttpContext.TraceIdentifier),
            limit,
            cancellationToken));
}
