using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Sufficit.Identity.Management.Authorization;
using Sufficit.Identity.Management.Scopes;

namespace Sufficit.Identity.Management.Controllers;

/// <summary>
/// HTTP adapter for custom OAuth scope administration.
/// </summary>
[ApiController]
[Authorize(Policy = "sufficit-identity-management")]
[Route("api/scopes")]
public sealed class ScopesController(IScopeManagementService scopes)
    : ControllerBase
{
    [HttpGet]
    public async Task<ActionResult<IReadOnlyList<ManagementScopeSummary>>> List(
        CancellationToken cancellationToken) =>
        Ok(await scopes.ListAsync(RequestContext(), cancellationToken));

    [HttpGet("{id}")]
    public async Task<ActionResult<ManagementScopeDetail>> Get(
        string id,
        CancellationToken cancellationToken) =>
        Ok(await scopes.GetAsync(id, RequestContext(), cancellationToken));

    [HttpPost]
    public async Task<ActionResult<ManagementScopeDetail>> Create(
        [FromBody] CreateScopeRequest request,
        CancellationToken cancellationToken)
    {
        var result = await scopes.CreateAsync(
            new CreateManagementScopeCommand(
                request.Name,
                request.DisplayName,
                request.Description,
                request.Resources),
            RequestContext(),
            cancellationToken);

        return CreatedAtAction(
            nameof(Get),
            new { id = result.Id },
            result);
    }

    [HttpPut("{id}")]
    public async Task<ActionResult<ManagementScopeDetail>> Update(
        string id,
        [FromBody] UpdateScopeRequest request,
        CancellationToken cancellationToken) =>
        Ok(await scopes.UpdateAsync(
            id,
            new UpdateManagementScopeCommand(
                request.DisplayName,
                request.Description,
                request.Resources),
            RequestContext(),
            cancellationToken));

    [HttpDelete("{id}")]
    public async Task<IActionResult> Delete(
        string id,
        CancellationToken cancellationToken)
    {
        await scopes.DeleteAsync(id, RequestContext(), cancellationToken);
        return NoContent();
    }

    private ManagementRequestContext RequestContext() =>
        new(User, HttpContext.TraceIdentifier);
}

public sealed class CreateScopeRequest
{
    [Required]
    public string Name { get; set; } = string.Empty;

    public string? DisplayName { get; set; }

    public string? Description { get; set; }

    public List<string> Resources { get; set; } = [];
}

public sealed class UpdateScopeRequest
{
    public string? DisplayName { get; set; }

    public string? Description { get; set; }

    public List<string> Resources { get; set; } = [];
}
