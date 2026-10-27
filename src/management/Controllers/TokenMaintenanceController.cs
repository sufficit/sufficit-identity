using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Sufficit.Identity.Management.Maintenance;

namespace Sufficit.Identity.Management.Controllers;

[ApiController]
[Authorize(Policy = "sufficit-identity-management")]
[Route("api/maintenance/tokens")]
public sealed class TokenMaintenanceController(ITokenMaintenanceManagementService service) : ControllerBase
{
    [HttpGet]
    public async Task<ActionResult<TokenMaintenanceOverview>> Get(CancellationToken ct) =>
        Ok(await service.GetAsync(new(User, HttpContext.TraceIdentifier), ct));

    [HttpPut]
    public async Task<IActionResult> Save(SaveTokenMaintenance command, CancellationToken ct)
    {
        await service.SaveAsync(command, new(User, HttpContext.TraceIdentifier), ct);
        return NoContent();
    }

    [HttpPost("runs")]
    public async Task<IActionResult> RequestRun(RequestTokenMaintenance command, CancellationToken ct)
    {
        await service.RequestRunAsync(command.Revision, new(User, HttpContext.TraceIdentifier), ct);
        return Accepted();
    }
}
