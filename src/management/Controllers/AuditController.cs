using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Sufficit.Identity.Management.Audit;
using Sufficit.Identity.Management.Authorization;

namespace Sufficit.Identity.Management.Controllers;

/// <summary>Read-only HTTP adapter for administrative audit events.</summary>
[ApiController]
[Authorize(Policy = "sufficit-identity-management")]
[Route("api/audit")]
[ResponseCache(NoStore = true, Location = ResponseCacheLocation.None)]
public sealed class AuditController(IManagementAuditService audit)
    : ControllerBase
{
    [HttpPost("search")]
    public async Task<ActionResult<ManagementAuditPage>> Search(
        [FromBody] ManagementAuditQuery query,
        CancellationToken cancellationToken = default) =>
        Ok(await audit.SearchAsync(
            new ManagementRequestContext(User, HttpContext.TraceIdentifier),
            query,
            cancellationToken));

    [HttpGet]
    public async Task<ActionResult<IReadOnlyList<ManagementAuditRecord>>> List(
        [FromQuery] int limit = 100,
        CancellationToken cancellationToken = default) =>
        Ok(await audit.ListAsync(
            new ManagementRequestContext(User, HttpContext.TraceIdentifier),
            limit,
            cancellationToken));
}
