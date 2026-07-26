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

        // Redirect URI validation (eval M4). OAuth 2.1 requires exact redirect
        // matching at runtime — the STS already enforces that — but validating
        // at creation gives the operator early feedback and prevents obviously
        // insecure entries (public http, fragments, wildcards) from being
        // persisted. http is allowed ONLY for loopback (dev); everything else
        // must be https.
        foreach (var redirect in request.RedirectUris)
        {
            if (redirect.Fragment.Length > 0)
                return BadRequest($"redirect_uri cannot contain a fragment: {redirect}");

            var isLoopback = redirect.IsLoopback
                || string.Equals(redirect.Host, "localhost", StringComparison.OrdinalIgnoreCase);
            if (redirect.Scheme != Uri.UriSchemeHttps && !isLoopback)
                return BadRequest(
                    $"redirect_uri must use https (http is only allowed for loopback): {redirect}");
        }

        // Consent type default (eval M4). Previously every client was created
        // as ConsentTypes.Implicit — i.e. it NEVER asks the resource owner for
        // consent. The secure-by-default is Explicit: consent is required
        // unless a valid cached authorization already covers the request. The
        // caller may still opt into a different consent type explicitly.
        string consentType;
        try
        {
            consentType = NormalizeConsentType(request.ConsentType)
                ?? OpenIddictConstants.ConsentTypes.Explicit;
        }
        catch (ArgumentException ex)
        {
            return BadRequest(ex.Message);
        }

        var descriptor = new OpenIddictApplicationDescriptor
        {
            ClientId = request.ClientId,
            ClientSecret = request.ClientSecret,
            DisplayName = request.DisplayName,
            ConsentType = consentType,
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

        // Pushed Authorization Request (RFC 9126) requirement, opt-in per
        // client (item 3.3). When set, this client must obtain a request_uri
        // from /connect/par before hitting /connect/authorize — front-channel
        // request params are rejected. Prerequisite for FAPI 2.0. Opt-in (not
        // global) so legacy clients continue to work; the endpoint /connect/par
        // is already registered server-side.
        if (request.RequirePar)
        {
            descriptor.Requirements.Add(OpenIddictConstants.Requirements.Features.PushedAuthorizationRequests);
        }

        var app = await _applications.CreateAsync(descriptor, ct);
        return CreatedAtAction(nameof(Get), new { clientId = request.ClientId }, await ToDto(app));
    }

    /// <summary>
    /// Maps a caller-supplied consent type string (case-insensitive short name
    /// or the full OpenIddict constant) to the canonical OpenIddict value, or
    /// null when the caller left it unset (so the caller can apply its own
    /// default). Rejects unknown values with a 400 by throwing — caught and
    /// turned into a BadRequest by the caller.
    /// </summary>
    private static string? NormalizeConsentType(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
            return null;

        return raw switch
        {
            var s when string.Equals(s, "explicit", StringComparison.OrdinalIgnoreCase)
                || string.Equals(s, OpenIddictConstants.ConsentTypes.Explicit, StringComparison.OrdinalIgnoreCase)
                => OpenIddictConstants.ConsentTypes.Explicit,
            var s when string.Equals(s, "implicit", StringComparison.OrdinalIgnoreCase)
                || string.Equals(s, OpenIddictConstants.ConsentTypes.Implicit, StringComparison.OrdinalIgnoreCase)
                => OpenIddictConstants.ConsentTypes.Implicit,
            var s when string.Equals(s, "external", StringComparison.OrdinalIgnoreCase)
                || string.Equals(s, OpenIddictConstants.ConsentTypes.External, StringComparison.OrdinalIgnoreCase)
                => OpenIddictConstants.ConsentTypes.External,
            var s when string.Equals(s, "systematic", StringComparison.OrdinalIgnoreCase)
                || string.Equals(s, OpenIddictConstants.ConsentTypes.Systematic, StringComparison.OrdinalIgnoreCase)
                => OpenIddictConstants.ConsentTypes.Systematic,
            _ => throw new ArgumentException($"Unknown consent type: '{raw}'. " +
                "Valid values: explicit, implicit, external, systematic.")
        };
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
            ConsentType = await _applications.GetConsentTypeAsync(app),
            Permissions = await _applications.GetPermissionsAsync(app),
            Requirements = await _applications.GetRequirementsAsync(app),
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

    /// <summary>
    /// Optional consent type for the new client. Accepts the short name
    /// (<c>explicit</c>/<c>implicit</c>/<c>external</c>/<c>systematic</c>) or
    /// the full OpenIddict constant. When omitted, the client is created as
    /// <c>Explicit</c> (secure-by-default — eval M4).
    /// </summary>
    public string? ConsentType { get; set; }

    /// <summary>
    /// When <c>true</c>, the client is required to use Pushed Authorization
    /// Requests (RFC 9126): it must POST its authorization request params to
    /// <c>/connect/par</c> first and reference the result via
    /// <c>request_uri</c> on <c>/connect/authorize</c>. Default <c>false</c>
    /// (opt-in per client — does not affect legacy clients).
    /// </summary>
    public bool RequirePar { get; set; }

    public List<string> GrantTypes { get; set; } = new();
    public List<string> Scopes { get; set; } = new();
    public List<Uri> RedirectUris { get; set; } = new();
}
