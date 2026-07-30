using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Sufficit.Identity.Management.Authorization;
using Sufficit.Identity.Management.Claims;

namespace Sufficit.Identity.Management.Controllers;

/// <summary>
/// HTTP adapter for custom claims assigned to identity accounts.
/// </summary>
[ApiController]
[Authorize(Policy = "sufficit-identity-management")]
[Route("api/claims")]
public sealed class ClaimsController(IClaimManagementService claims)
    : ControllerBase
{
    [HttpGet("metadata")]
    public async Task<ActionResult<ManagementClaimMetadata>> Metadata(
        CancellationToken cancellationToken) =>
        Ok(await claims.GetMetadataAsync(
            RequestContext(),
            cancellationToken));

    [HttpGet]
    public async Task<ActionResult<ManagementClaimPage>> Search(
        [FromQuery] string? search,
        [FromQuery] string? userId,
        [FromQuery] int page = 1,
        [FromQuery] int pageSize = 25,
        CancellationToken cancellationToken = default) =>
        Ok(await claims.SearchAsync(
            new ManagementClaimSearch(search, userId, page, pageSize),
            RequestContext(),
            cancellationToken));

    [HttpGet("{id:int}")]
    public async Task<ActionResult<ManagementClaimAssignment>> Get(
        int id,
        CancellationToken cancellationToken) =>
        Ok(await claims.GetAsync(
            id,
            RequestContext(),
            cancellationToken));

    [HttpPost]
    public async Task<ActionResult<ManagementClaimAssignment>> Create(
        [FromBody] CreateClaimRequest request,
        CancellationToken cancellationToken)
    {
        var result = await claims.CreateAsync(
            new CreateManagementClaimCommand(
                request.UserId,
                request.Type,
                request.Value),
            RequestContext(),
            cancellationToken);

        return CreatedAtAction(
            nameof(Get),
            new { id = result.Id },
            result);
    }

    [HttpDelete("{id:int}")]
    public async Task<IActionResult> Delete(
        int id,
        CancellationToken cancellationToken)
    {
        await claims.DeleteAsync(
            id,
            RequestContext(),
            cancellationToken);
        return NoContent();
    }

    private ManagementRequestContext RequestContext() =>
        new(User, HttpContext.TraceIdentifier);
}

public sealed class CreateClaimRequest
{
    [Required]
    public string UserId { get; set; } = string.Empty;

    [Required]
    public string Type { get; set; } = string.Empty;

    [Required]
    public string Value { get; set; } = string.Empty;
}
