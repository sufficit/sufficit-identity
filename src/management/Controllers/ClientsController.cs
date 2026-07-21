using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using OpenIddict.Abstractions;

namespace Sufficit.Identity.Management.Controllers;

/// <summary>
/// CRUD for OAuth clients (OpenIddict Applications).
/// Gated by the "sufficit-identity-management" policy (configured in
/// <see cref="ServiceCollectionExtensions.AddSufficitIdentityManagement"/>).
/// </summary>
[ApiController]
[Authorize(Policy = "sufficit-identity-management")]
[Route("api/clients")]
public sealed class ClientsController : ControllerBase
{
    private readonly IOpenIddictApplicationManager _applications;

    public ClientsController(IOpenIddictApplicationManager applications)
        => _applications = applications;

    /// <summary>Lists all registered clients.</summary>
    [HttpGet]
    public async Task<IActionResult> List(CancellationToken ct)
    {
        var result = new List<ClientSummary>();
        await foreach (var app in _applications.ListAsync(cancellationToken: ct))
        {
            result.Add(new ClientSummary
            {
                Id = (await _applications.GetIdAsync(app))!,
                ClientId = (string)(await _applications.GetClientIdAsync(app))!,
                DisplayName = (string?)await _applications.GetDisplayNameAsync(app),
                Type = (string?)await _applications.GetClientTypeAsync(app),
            });
        }
        return Ok(result);
    }

    /// <summary>Gets a single client by client_id.</summary>
    [HttpGet("{clientId}")]
    public async Task<IActionResult> Get(string clientId, CancellationToken ct)
    {
        var app = await _applications.FindByClientIdAsync(clientId, ct);
        if (app is null) return NotFound();
        return Ok(await ToDto(app));
    }

    /// <summary>Creates a new client.</summary>
    [HttpPost]
    public async Task<IActionResult> Create([FromBody] CreateClientRequest request, CancellationToken ct)
    {
        if (await _applications.FindByClientIdAsync(request.ClientId, ct) is not null)
            return Conflict($"Client '{request.ClientId}' already exists.");

        var descriptor = new OpenIddictApplicationDescriptor
        {
            ClientId = request.ClientId,
            ClientSecret = request.ClientSecret,
            DisplayName = request.DisplayName,
            ConsentType = OpenIddictConstants.ConsentTypes.Implicit,
            ClientType = string.IsNullOrEmpty(request.ClientSecret)
                ? OpenIddictConstants.ClientTypes.Public
                : OpenIddictConstants.ClientTypes.Confidential,
        };

        foreach (var grant in request.GrantTypes)
            descriptor.Permissions.Add(grant);

        foreach (var scope in request.Scopes)
            descriptor.Permissions.Add(OpenIddictConstants.Permissions.Prefixes.Scope + scope);

        foreach (var redirect in request.RedirectUris)
            descriptor.RedirectUris.Add(redirect);

        // Public clients using authorization_code must require PKCE (RFC 7636).
        if (request.GrantTypes.Contains(OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode) &&
            descriptor.ClientType == OpenIddictConstants.ClientTypes.Public)
        {
            descriptor.Requirements.Add(OpenIddictConstants.Requirements.Features.ProofKeyForCodeExchange);
        }

        var app = await _applications.CreateAsync(descriptor, ct);
        return CreatedAtAction(nameof(Get), new { clientId = request.ClientId }, await ToDto(app));
    }

    /// <summary>Deletes a client.</summary>
    [HttpDelete("{clientId}")]
    public async Task<IActionResult> Delete(string clientId, CancellationToken ct)
    {
        var app = await _applications.FindByClientIdAsync(clientId, ct);
        if (app is null) return NotFound();
        await _applications.DeleteAsync(app, ct);
        return NoContent();
    }

    private async Task<object> ToDto(object app)
    {
        return new
        {
            Id = await _applications.GetIdAsync(app),
            ClientId = await _applications.GetClientIdAsync(app),
            DisplayName = await _applications.GetDisplayNameAsync(app),
            Type = await _applications.GetClientTypeAsync(app),
            Permissions = await _applications.GetPermissionsAsync(app),
        };
    }
}

public sealed class ClientSummary
{
    public string Id { get; set; } = "";
    public string ClientId { get; set; } = "";
    public string? DisplayName { get; set; }
    public string? Type { get; set; }
}

public sealed class CreateClientRequest
{
    [Required] public string ClientId { get; set; } = "";
    public string? ClientSecret { get; set; }
    public string? DisplayName { get; set; }
    public List<string> GrantTypes { get; set; } = new();
    public List<string> Scopes { get; set; } = new();
    public List<Uri> RedirectUris { get; set; } = new();
}
