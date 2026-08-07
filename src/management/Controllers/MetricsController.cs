using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Sufficit.Identity.Management.Authorization;
using Sufficit.Identity.Management.Metrics;

namespace Sufficit.Identity.Management.Controllers;

/// <summary>HTTP adapter for privacy-safe Identity usage telemetry.</summary>
[ApiController]
[Authorize(Policy = "sufficit-identity-management")]
[Route("api/metrics")]
public sealed class MetricsController(IMetricsManagementService metrics) : ControllerBase
{
    [HttpGet("overview")]
    public async Task<ActionResult<ManagementMetricsOverview>> GetOverview(
        [FromQuery] DateTime? fromUtc,
        [FromQuery] DateTime? toUtc,
        [FromQuery, StringLength(255)] string? clientId,
        CancellationToken cancellationToken) =>
        Ok(await metrics.GetOverviewAsync(fromUtc, toUtc, clientId,
            RequestContext(), cancellationToken));

    [HttpGet("configuration")]
    public async Task<ActionResult<ManagementMetricsConfiguration>> GetConfiguration(
        CancellationToken cancellationToken) =>
        Ok(await metrics.GetConfigurationAsync(RequestContext(), cancellationToken));

    [HttpPut("configuration")]
    public async Task<ActionResult<ManagementMetricsConfiguration>> UpdateConfiguration(
        [FromBody] SaveManagementMetricsConfiguration command,
        CancellationToken cancellationToken) =>
        Ok(await metrics.UpdateConfigurationAsync(command, RequestContext(), cancellationToken));

    private ManagementRequestContext RequestContext() =>
        new(User, HttpContext.TraceIdentifier);
}
