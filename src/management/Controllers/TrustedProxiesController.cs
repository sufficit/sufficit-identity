using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Sufficit.Identity.Management.Authorization;
using Sufficit.Identity.Management.Networking;

namespace Sufficit.Identity.Management.Controllers;

[ApiController]
[Authorize(Policy = "sufficit-identity-management")]
[Route("api/trusted-proxies")]
public sealed class TrustedProxiesController(ITrustedProxyManagementService service) : ControllerBase
{
    [HttpGet]
    public async Task<ActionResult<ManagementTrustedProxies>> Get(CancellationToken cancellationToken) =>
        Ok(await service.GetAsync(new(User, HttpContext.TraceIdentifier), cancellationToken));

    [HttpPut]
    public async Task<ActionResult<ManagementTrustedProxies>> Save(SaveTrustedProxies command,
        CancellationToken cancellationToken) =>
        Ok(await service.SaveAsync(command, new(User, HttpContext.TraceIdentifier), cancellationToken));
}
