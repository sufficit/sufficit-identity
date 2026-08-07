using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Sufficit.Identity.Application.Diagnostics;
using Sufficit.Identity.Management.Authorization;
using Sufficit.Identity.Management.Database;

namespace Sufficit.Identity.Management.Controllers;

/// <summary>
/// Read-only HTTP adapter for connection-pool and active-connection telemetry.
/// Connection strings, SQL and command parameters never cross this boundary.
/// </summary>
[ApiController]
[Authorize(Policy = "sufficit-identity-management")]
[Route("api/database/connections")]
public sealed class DatabaseController(IDatabaseMonitoringService database)
    : ControllerBase
{
    [HttpGet]
    public async Task<ActionResult<DatabaseRuntimeSnapshot>> Get(
        CancellationToken cancellationToken) =>
        Ok(await database.GetAsync(
            new ManagementRequestContext(User, HttpContext.TraceIdentifier),
            cancellationToken));
}
