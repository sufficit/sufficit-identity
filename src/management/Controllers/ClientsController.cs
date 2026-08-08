using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Sufficit.Identity.Management.Authorization;
using Sufficit.Identity.Management.Clients;

namespace Sufficit.Identity.Management.Controllers;

/// <summary>
/// HTTP adapter for the canonical OAuth/OIDC client management use cases.
/// </summary>
[ApiController]
[Authorize(Policy = "sufficit-identity-management")]
[Route("api/clients")]
public sealed class ClientsController(IClientManagementService clients)
    : ControllerBase
{
    /// <summary>Lists all registered clients.</summary>
    [HttpGet]
    public async Task<ActionResult<IReadOnlyList<ManagementClientSummary>>> List(
        CancellationToken cancellationToken) =>
        Ok(await clients.ListAsync(RequestContext(), cancellationToken));

    /// <summary>Gets a single client by client_id.</summary>
    [HttpGet("{clientId}")]
    public async Task<ActionResult<ManagementClientDetail>> Get(
        string clientId,
        CancellationToken cancellationToken) =>
        Ok(await clients.GetByClientIdAsync(
            clientId,
            RequestContext(),
            cancellationToken));

    /// <summary>Creates a new client using secure application defaults.</summary>
    [HttpPost]
    public async Task<ActionResult<ManagementClientDetail>> Create(
        [FromBody] CreateClientRequest request,
        CancellationToken cancellationToken)
    {
        var result = await clients.CreateAsync(
            new CreateManagementClientCommand(
                request.ClientId,
                request.ClientSecret,
                request.DisplayName,
                request.ConsentType,
                request.RequirePar,
                request.GrantTypes,
                request.Scopes,
                request.RedirectUris,
                request.PostLogoutRedirectUris,
                request.FrontchannelLogoutUri,
                request.FrontchannelLogoutSessionRequired,
                request.BackchannelLogoutUri,
                request.BackchannelLogoutSessionRequired),
            RequestContext(),
            cancellationToken);

        return CreatedAtAction(
            nameof(Get),
            new { clientId = result.ClientId },
            result);
    }

    /// <summary>Updates a manually managed client without changing its secret.</summary>
    [HttpPut("{clientId}")]
    public async Task<ActionResult<ManagementClientDetail>> Update(
        string clientId,
        [FromBody] UpdateClientRequest request,
        CancellationToken cancellationToken)
    {
        var result = await clients.UpdateAsync(
            new UpdateManagementClientCommand(
                clientId,
                request.DisplayName,
                request.ConsentType,
                request.RequirePar,
                request.GrantTypes,
                request.Scopes,
                request.RedirectUris,
                request.PostLogoutRedirectUris,
                request.FrontchannelLogoutUri,
                request.FrontchannelLogoutSessionRequired,
                request.BackchannelLogoutUri,
                request.BackchannelLogoutSessionRequired,
                request.ExpectedVersion),
            RequestContext(),
            cancellationToken);

        return Ok(result);
    }

    /// <summary>Deletes a client.</summary>
    [HttpDelete("{clientId}")]
    public async Task<IActionResult> Delete(
        string clientId,
        CancellationToken cancellationToken)
    {
        await clients.DeleteAsync(
            clientId,
            RequestContext(),
            cancellationToken);
        return NoContent();
    }

    private ManagementRequestContext RequestContext() =>
        new(User, HttpContext.TraceIdentifier);
}

public sealed class CreateClientRequest
{
    [Required]
    public string ClientId { get; set; } = string.Empty;

    public string? ClientSecret { get; set; }

    public string? DisplayName { get; set; }

    /// <summary>
    /// Optional consent type. When omitted, explicit consent is used.
    /// </summary>
    public string? ConsentType { get; set; }

    /// <summary>
    /// Requires Pushed Authorization Requests (RFC 9126) for this client.
    /// </summary>
    public bool RequirePar { get; set; }

    public List<string> GrantTypes { get; set; } = [];

    public List<string> Scopes { get; set; } = [];

    public List<string> RedirectUris { get; set; } = [];

    public List<string> PostLogoutRedirectUris { get; set; } = [];

    public string? FrontchannelLogoutUri { get; set; }

    public bool FrontchannelLogoutSessionRequired { get; set; }

    public string? BackchannelLogoutUri { get; set; }

    public bool BackchannelLogoutSessionRequired { get; set; }
}

public sealed class UpdateClientRequest
{
    public string? DisplayName { get; set; }
    public string? ConsentType { get; set; }
    public bool RequirePar { get; set; }
    public List<string> GrantTypes { get; set; } = [];
    public List<string> Scopes { get; set; } = [];
    public List<string> RedirectUris { get; set; } = [];
    public List<string> PostLogoutRedirectUris { get; set; } = [];
    public string? FrontchannelLogoutUri { get; set; }
    public bool FrontchannelLogoutSessionRequired { get; set; }
    public string? BackchannelLogoutUri { get; set; }
    public bool BackchannelLogoutSessionRequired { get; set; }
    public string? ExpectedVersion { get; set; }
}
