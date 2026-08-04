using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using OpenIddict.Abstractions;

namespace Sufficit.Identity.STS.Controllers;

/// <summary>
/// RFC 7591 Dynamic Client Registration (DCR) — item 4.3. Exposes
/// <c>/connect/register</c> so clients (including MCP clients) can self-register.
/// Gated: off by default, and requires an initial access token when enabled.
/// </summary>
/// <remarks>
/// OpenIddict 7.6 ships no DCR (verified: zero "registration" strings). This
/// is a from-scratch implementation that reuses the secure defaults established
/// for the management API's <c>ClientsController.Create</c>: every registered
/// client is born with <c>ConsentType=Explicit</c>, public clients require
/// PKCE, and redirect URIs are validated (https except loopback, no fragment).
/// DCR is a high-risk open-registration surface; it is opt-in AND requires an
/// initial access token by default — see <c>DcrOptions</c>.
/// </remarks>
[ApiController]
[AllowAnonymous]
[Route("connect/register")]
public sealed class RegistrationController : ControllerBase
{
    private readonly IOpenIddictApplicationManager _applications;
    private readonly DcrOptions _options;

    public RegistrationController(IOpenIddictApplicationManager applications, IConfiguration configuration)
    {
        _applications = applications;
        var root = configuration.GetSection("Sufficit:Identity")
            .Get<SufficitIdentityOptions>() ?? new SufficitIdentityOptions();
        _options = root.Mcp.Dcr;
    }

    [HttpPost]
    [IgnoreAntiforgeryToken]
    [Produces("application/json")]
    public async Task<IActionResult> Register([FromBody] DcrRequest request, CancellationToken ct)
    {
        // Gate 1: the endpoint exists only when Dcr.Enabled. (The controller is
        // always routable because it is in the STS assembly's application part;
        // this check makes it 404-equivalent when disabled. Returning
        // NotFound keeps the endpoint invisible to probing.)
        if (!_options.Enabled)
        {
            return NotFound();
        }

        // Gate 2: initial access token. When required (default), the caller
        // must present the configured bearer token in the Authorization header.
        // Without it, anyone could register a client — the open-registration
        // risk DCR is notorious for.
        if (_options.RequireInitialAccessToken)
        {
            if (string.IsNullOrEmpty(_options.InitialAccessToken))
            {
                // Enabled + require token, but no token configured: fail closed.
                return StatusCode(StatusCodes.Status503ServiceUnavailable, new
                {
                    error = "server_error",
                    error_description = "Dynamic client registration is enabled but no initial access token is configured."
                });
            }

            var header = Request.Headers.Authorization.ToString();
            // L2 fix (eval L2): constant-time comparison to avoid a theoretical
            // timing side-channel on the initial access token.
            var expected = "Bearer " + _options.InitialAccessToken;
            var headerBytes = System.Text.Encoding.UTF8.GetBytes(header);
            var expectedBytes = System.Text.Encoding.UTF8.GetBytes(expected);
            if (headerBytes.Length != expectedBytes.Length
                || !System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(headerBytes, expectedBytes))
            {
                return Unauthorized(new { error = "invalid_token" });
            }
        }

        if (string.IsNullOrWhiteSpace(request.ClientId))
        {
            // RFC 7591 allows the AS to assign client_id; for Sufficit, require
            // the caller to propose one (simpler, and avoids collisions with
            // the seeded/managed clients).
            return BadRequest(new { error = "invalid_client_metadata", error_description = "client_id is required." });
        }

        if (await _applications.FindByClientIdAsync(request.ClientId, ct) is not null)
        {
            return Conflict(new { error = "invalid_client_metadata", error_description = $"Client '{request.ClientId}' already exists." });
        }

        // Validate redirect URIs with the SAME rules as the management API
        // (item 2.4): https required except loopback, no fragment. DCR must not
        // be a bypass for weaker client registration.
        foreach (var redirect in request.RedirectUris)
        {
            if (redirect.Fragment.Length > 0)
                return BadRequest(new { error = "invalid_client_metadata", error_description = $"redirect_uri cannot contain a fragment: {redirect}" });
            var isLoopback = redirect.IsLoopback
                || string.Equals(redirect.Host, "localhost", StringComparison.OrdinalIgnoreCase);
            if (redirect.Scheme != Uri.UriSchemeHttps && !isLoopback)
                return BadRequest(new { error = "invalid_redirect_uri", error_description = $"redirect_uri must use https (http only for loopback): {redirect}" });
        }

        var descriptor = new OpenIddictApplicationDescriptor
        {
            ClientId = request.ClientId,
            ClientSecret = request.ClientSecret,
            DisplayName = request.ClientName ?? request.ClientId,
            // Secure-by-default (mirrors ClientsController.Create item 2.4): DCR
            // clients are born Explicit-consent, never Implicit.
            ConsentType = OpenIddictConstants.ConsentTypes.Explicit,
            ClientType = string.IsNullOrEmpty(request.ClientSecret)
                ? OpenIddictConstants.ClientTypes.Public
                : OpenIddictConstants.ClientTypes.Confidential,
        };

        var requestedGrants = request.GrantTypes ?? new List<string>();
        var disallowedGrant = requestedGrants.FirstOrDefault(grant =>
            !_options.AllowedGrantTypes.Contains(grant));
        if (disallowedGrant is not null)
        {
            return BadRequest(new
            {
                error = "invalid_client_metadata",
                error_description = $"grant_type '{disallowedGrant}' is not allowed for dynamic registration."
            });
        }

        var requestedScopes = request.Scopes ?? new List<string>();
        var disallowedScope = requestedScopes.FirstOrDefault(scope =>
            !_options.AllowedScopes.Contains(scope));
        if (disallowedScope is not null)
        {
            return BadRequest(new
            {
                error = "invalid_client_metadata",
                error_description = $"scope '{disallowedScope}' is not allowed for dynamic registration."
            });
        }

        // Normalize the validated RFC 7591 grant-type names to OpenIddict
        // permission constants.
        var grants = requestedGrants.Select(NormalizeGrantType).ToList();
        foreach (var grant in grants)
            descriptor.Permissions.Add(grant);
        foreach (var scope in requestedScopes)
            descriptor.Permissions.Add(OpenIddictConstants.Permissions.Prefixes.Scope + scope);
        foreach (var redirect in request.RedirectUris)
            descriptor.RedirectUris.Add(redirect);

        // A DCR client must be able to reach the token endpoint to redeem its
        // grant. Add the token-endpoint permission whenever any grant was
        // requested (mirrors how the seeded test clients are configured).
        if (grants.Count > 0)
        {
            descriptor.Permissions.Add(OpenIddictConstants.Permissions.Endpoints.Token);
        }
        // authorization_code grant also needs the authorization endpoint.
        if (grants.Contains(OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode))
        {
            descriptor.Permissions.Add(OpenIddictConstants.Permissions.Endpoints.Authorization);
            descriptor.Permissions.Add(OpenIddictConstants.Permissions.ResponseTypes.Code);
        }

        // Public clients using authorization_code must require PKCE (RFC 7636).
        if (grants.Contains(OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode)
            && descriptor.ClientType == OpenIddictConstants.ClientTypes.Public)
        {
            descriptor.Requirements.Add(OpenIddictConstants.Requirements.Features.ProofKeyForCodeExchange);
        }

        await _applications.CreateAsync(descriptor, ct);

        // RFC 7591 §3.2.1 response: client_id, and client_secret when confidential.
        return Created(Url.Action(nameof(Register), new { clientId = request.ClientId })!, new
        {
            client_id = descriptor.ClientId,
            client_secret = descriptor.ClientSecret,
            client_name = descriptor.DisplayName,
            client_id_issued_at = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
        });
    }

    /// <summary>
    /// Maps an RFC 7591 grant-type name (plain: <c>client_credentials</c>,
    /// <c>authorization_code</c>, <c>refresh_token</c>, <c>password</c>,
    /// <c>urn:ietf:params:oauth:grant-type:token-exchange</c>) to the OpenIddict
    /// permission constant (<c>gt:&lt;name&gt;</c>). Input is allowlisted before
    /// this method is called.
    /// </summary>
    private static string NormalizeGrantType(string grant)
    {
        // Already a prefixed OpenIddict permission, or a URN grant (token
        // exchange) — pass through verbatim.
        if (grant.StartsWith("gt:", StringComparison.Ordinal)
            || grant.StartsWith("urn:", StringComparison.Ordinal))
        {
            return grant;
        }
        return grant switch
        {
            "authorization_code" => OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode,
            "client_credentials" => OpenIddictConstants.Permissions.GrantTypes.ClientCredentials,
            "refresh_token" => OpenIddictConstants.Permissions.GrantTypes.RefreshToken,
            "password" => OpenIddictConstants.Permissions.GrantTypes.Password,
            "device_code" => OpenIddictConstants.Permissions.GrantTypes.DeviceCode,
            _ => grant // unknown — let OpenIddict reject it.
        };
    }
}

/// <summary>DCR request body (RFC 7591 §2 metadata fields, Sufficit subset).</summary>
public sealed class DcrRequest
{
    public string? ClientId { get; set; }
    public string? ClientSecret { get; set; }
    public string? ClientName { get; set; }
    public List<string>? GrantTypes { get; set; }
    public List<string>? Scopes { get; set; }
    public List<Uri> RedirectUris { get; set; } = new();
}
