using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.Management.Audit;
using Sufficit.Identity.Management.Authorization;

namespace Sufficit.Identity.Management.Controllers;

/// <summary>Current user and role claims for an authorized management consumer.
/// Values remain opaque; consumers own their authorization semantics.</summary>
[ApiController]
[Authorize(Policy = "sufficit-identity-management")]
[Route("api/claims/effective")]
public sealed class EffectiveClaimsController(UserManager<ApplicationUser> users,
    IUserClaimsPrincipalFactory<ApplicationUser> principals, ManagementOperationGuard guard) : ControllerBase
{
    [HttpGet]
    public async Task<IActionResult> Get(string userId, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(userId) || userId.Length > 200) return BadRequest();
        await guard.DemandAsync(new ManagementRequestContext(User, HttpContext.TraceIdentifier),
            ManagementCapabilities.ClaimsRead, new ManagementResource(ManagementResourceTypes.ClaimCollection, userId), cancellationToken);
        var user = await users.FindByIdAsync(userId);
        if (user is null) return NotFound();
        if (await users.IsLockedOutAsync(user)) return Forbid();
        var principal = await principals.CreateAsync(user);
        cancellationToken.ThrowIfCancellationRequested();
        Response.Headers.CacheControl = "no-store";
        return Ok(new { schemaVersion = 1, subject = user.Id, claims = principal.Claims
            .Where(c => c.Type is "entitlements" or "directive" or "role" || c.Type == System.Security.Claims.ClaimTypes.Role)
            .Select(c => new { type = c.Type, value = c.Value }).Distinct().ToArray() });
    }
}
