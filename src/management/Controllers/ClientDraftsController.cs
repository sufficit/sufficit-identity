using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Sufficit.Identity.Management.Authorization;
using Sufficit.Identity.Management.Clients;

namespace Sufficit.Identity.Management.Controllers;

/// <summary>
/// HTTP adapter for resumable OAuth/OIDC application configuration drafts.
/// Draft payloads never contain a client secret.
/// </summary>
[ApiController]
[Authorize(Policy = "sufficit-identity-management")]
[Route("api/client-drafts")]
public sealed class ClientDraftsController(IClientConfigurationDraftService drafts)
    : ControllerBase
{
    [HttpGet("profiles")]
    public async Task<ActionResult<IReadOnlyList<ManagementClientProfile>>> Profiles(
        CancellationToken cancellationToken) =>
        Ok(await drafts.GetProfilesAsync(RequestContext(), cancellationToken));

    [HttpGet("available-scopes")]
    public async Task<ActionResult<IReadOnlyList<ManagementClientAvailableScope>>> AvailableScopes(
        CancellationToken cancellationToken) =>
        Ok(await drafts.GetAvailableScopesAsync(RequestContext(), cancellationToken));

    [HttpGet]
    public async Task<ActionResult<IReadOnlyList<ManagementClientDraftSummary>>> List(
        CancellationToken cancellationToken) =>
        Ok(await drafts.ListAsync(RequestContext(), cancellationToken));

    [HttpPost]
    public async Task<ActionResult<ManagementClientDraftDetail>> Create(
        [FromBody] CreateClientDraftRequest request,
        CancellationToken cancellationToken)
    {
        var result = await drafts.CreateAsync(
            request.Profile,
            RequestContext(),
            cancellationToken);
        return CreatedAtAction(nameof(Get), new { id = result.Id }, result);
    }

    [HttpGet("{id:guid}")]
    public async Task<ActionResult<ManagementClientDraftDetail>> Get(
        Guid id,
        CancellationToken cancellationToken) =>
        Ok(await drafts.GetAsync(id, RequestContext(), cancellationToken));

    [HttpPut("{id:guid}")]
    public async Task<ActionResult<ManagementClientDraftDetail>> Save(
        Guid id,
        [FromBody] SaveClientDraftRequest request,
        CancellationToken cancellationToken) =>
        Ok(await drafts.SaveAsync(
            new SaveManagementClientDraftCommand(
                id,
                request.Version,
                request.CurrentStep,
                request.Values),
            RequestContext(),
            cancellationToken));

    [HttpPost("{id:guid}/complete")]
    public async Task<ActionResult<CompleteManagementClientDraftResult>> Complete(
        Guid id,
        [FromBody] CompleteClientDraftRequest request,
        CancellationToken cancellationToken) =>
        Ok(await drafts.CompleteAsync(
            id,
            request.Version,
            RequestContext(),
            cancellationToken));

    [HttpDelete("{id:guid}")]
    public async Task<IActionResult> Abandon(
        Guid id,
        CancellationToken cancellationToken)
    {
        await drafts.AbandonAsync(id, RequestContext(), cancellationToken);
        return NoContent();
    }

    private ManagementRequestContext RequestContext() =>
        new(User, HttpContext.TraceIdentifier);
}

public sealed class CreateClientDraftRequest
{
    public string Profile { get; set; } = string.Empty;
}

public sealed class SaveClientDraftRequest
{
    public string Version { get; set; } = string.Empty;
    public string CurrentStep { get; set; } = ManagementClientDraftSteps.Identity;
    public ManagementClientDraftValues Values { get; set; } = new();
}

public sealed class CompleteClientDraftRequest
{
    public string Version { get; set; } = string.Empty;
}
