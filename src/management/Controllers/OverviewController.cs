using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Sufficit.Identity.Management.Authorization;
using Sufficit.Identity.Management.Overview;

namespace Sufficit.Identity.Management.Controllers;

/// <summary>
/// HTTP adapter for the canonical management runtime discovery use case.
/// </summary>
[ApiController]
[Authorize(Policy = "sufficit-identity-management")]
[Route("api/overview")]
public sealed class OverviewController(IManagementOverviewService overview)
    : ControllerBase
{
    /// <summary>
    /// Returns effective runtime configuration, supported modules and the
    /// authenticated operator's provider-management access.
    /// </summary>
    [HttpGet]
    public async Task<ActionResult<ManagementOverview>> Get(
        CancellationToken cancellationToken) =>
        Ok(await overview.GetAsync(
            new ManagementRequestContext(
                User,
                HttpContext.TraceIdentifier),
            cancellationToken));
}
