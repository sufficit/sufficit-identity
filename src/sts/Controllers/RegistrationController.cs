using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.AspNetCore.WebUtilities;
using System.Security.Cryptography;
using Sufficit.Identity.STS.Dpop;
using Sufficit.Identity.Application.Security;
using Sufficit.Identity.Vault;
using OpenIddict.Abstractions;
using System.Text.Json;
using Sufficit.Identity.STS.Jar;

namespace Sufficit.Identity.STS.Controllers;

/// <summary>
/// RFC 7591 Dynamic Client Registration (DCR) — item 4.3. Exposes
/// <c>/connect/register</c> so clients (including MCP clients) can self-register.
/// Gated: off by default, and requires an operator-issued initial access token
/// when enabled.
/// </summary>
/// <remarks>
/// OpenIddict 7.6 ships no DCR (verified: zero "registration" strings). This
/// is a from-scratch implementation that reuses the secure defaults established
/// for the management API's <c>ClientsController.Create</c>: every registered
/// client is born with <c>ConsentType=Explicit</c>, authorization-code clients
/// require PKCE, and redirect URIs are validated (https except loopback, no
/// fragment).
/// DCR is a high-risk open-registration surface; it is opt-in AND requires an
/// initial access token by default — see <c>DcrOptions</c>.
/// </remarks>
[ApiController]
[AllowAnonymous]
[Route("connect/register")]
public sealed class RegistrationController : ControllerBase
{
    /// <summary>Provenance markers written to the application's Properties so
    /// the management console can tell self-registered clients apart from
    /// operator-created ones. Shared with the management assembly through
    /// <c>DynamicClientRegistrationProperties</c>.</summary>
    internal const string OriginProperty =
        DynamicClientRegistrationProperties.Origin;
    internal const string OriginValue =
        DynamicClientRegistrationProperties.OriginValue;
    internal const string RegisteredAtProperty =
        DynamicClientRegistrationProperties.RegisteredAt;
    internal const string AnonymousProperty =
        DynamicClientRegistrationProperties.Anonymous;
    internal const string RemoteAddressProperty =
        DynamicClientRegistrationProperties.RemoteAddress;
    internal const string UserAgentProperty =
        DynamicClientRegistrationProperties.UserAgent;
    internal const string InitialAccessTokenIdProperty =
        DynamicClientRegistrationProperties.InitialAccessTokenId;

    private readonly IOpenIddictApplicationManager _applications;
    private readonly DcrOptions _options;
    private readonly IClientDefinitionValidator _validator;
    private readonly Sufficit.Identity.Core.Services.DcrInitialAccessTokenStore _initialAccessTokens;

    public RegistrationController(
        IOpenIddictApplicationManager applications,
        IConfiguration configuration,
        IClientDefinitionValidator validator,
        Sufficit.Identity.Core.Services.DcrInitialAccessTokenStore initialAccessTokens)
    {
        _applications = applications;
        _validator = validator;
        _initialAccessTokens = initialAccessTokens;
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

        // Gate 2: initial access token. Each token is issued by an operator
        // to one registrant through the management API, expires, can be
        // revoked and is single-use by default, so every registration traces
        // back to who allowed it. Without the gate anyone could register a
        // client, the open-registration risk DCR is notorious for.
        Sufficit.Identity.Core.Entities.DcrInitialAccessToken? initialAccessToken = null;
        if (_options.RequireInitialAccessToken)
        {
            initialAccessToken = await _initialAccessTokens.FindActiveAsync(
                ReadBearerToken(), ct);
            if (initialAccessToken is null)
            {
                return InvalidInitialAccessToken();
            }
        }

        var clientId = string.IsNullOrWhiteSpace(request.ClientId)
            ? "dcr_" + WebEncoders.Base64UrlEncode(
                RandomNumberGenerator.GetBytes(24))
            : request.ClientId;
        if (await _applications.FindByClientIdAsync(clientId, ct) is not null)
        {
            return Conflict(new { error = "invalid_client_metadata", error_description = "The requested client identifier already exists." });
        }

        // An anonymous registration (no initial access token) is only
        // acceptable because the resulting client is powerless beyond signing
        // the user in: public, PKCE-bound, interactive grants, and a scope
        // allowlist that excludes every API/administrative scope. Enforced
        // here rather than trusted to configuration so turning the gate off
        // cannot silently widen what an unauthenticated caller may create.
        var anonymous = !_options.RequireInitialAccessToken;
        if (anonymous
            && ValidateAnonymousProfile(request) is { } anonymousIssue)
        {
            return BadRequest(anonymousIssue);
        }

        var authenticationMethod = anonymous
            ? "none"
            : string.IsNullOrWhiteSpace(request.TokenEndpointAuthMethod)
                ? "none"
                : request.TokenEndpointAuthMethod;
        var confidential = authenticationMethod != "none";
        var clientSecret = confidential
            ? (_options.AllowCallerSuppliedSecrets
                && !string.IsNullOrWhiteSpace(request.ClientSecret)
                    ? request.ClientSecret
                    : WebEncoders.Base64UrlEncode(
                        RandomNumberGenerator.GetBytes(48)))
            : null;

        var validation = DynamicClientDefinitionValidation.Validate(
            _validator,
            request,
            _options,
            confidential
                ? OpenIddictConstants.ClientTypes.Confidential
                : OpenIddictConstants.ClientTypes.Public,
            clientSecret is not null);
        if (!validation.IsValid)
        {
            var issue = validation.Issues[0];
            return BadRequest(new
            {
                error = issue.Code,
                error_description = issue.Message,
            });
        }

        // The operator may narrow what a registration with this particular
        // token may request; the server-wide allowlist still applies on top.
        if (initialAccessToken is not null
            && ValidateTokenPolicy(initialAccessToken, request) is { } policyIssue)
        {
            return BadRequest(policyIssue);
        }

        if (request.JwksUri is not null)
        {
            try
            {
                RemoteJwksProvider.ValidateUri(request.JwksUri);
            }
            catch (HttpRequestException)
            {
                return BadRequest(new
                {
                    error = "invalid_client_metadata",
                    error_description = "jwks_uri must be a public absolute HTTPS URI without user-info or fragment.",
                });
            }
        }

        var descriptor = new OpenIddictApplicationDescriptor
        {
            ClientId = clientId,
            ClientSecret = clientSecret,
            DisplayName = request.ClientName ?? clientId,
            // Secure-by-default (mirrors ClientsController.Create item 2.4): DCR
            // clients are born Explicit-consent, never Implicit.
            ConsentType = OpenIddictConstants.ConsentTypes.Explicit,
            ClientType = confidential
                ? OpenIddictConstants.ClientTypes.Confidential
                : OpenIddictConstants.ClientTypes.Public,
        };
        if (request.JwksUri is not null)
        {
            descriptor.Settings["jwks_uri"] = request.JwksUri.AbsoluteUri;
        }

        // Provenance for the operator console: which clients appeared on their
        // own, when, from where. Without this every DCR client is
        // indistinguishable from one an operator created by hand.
        descriptor.Properties[OriginProperty] =
            JsonSerializer.SerializeToElement(OriginValue);
        descriptor.Properties[RegisteredAtProperty] =
            JsonSerializer.SerializeToElement(
                DateTimeOffset.UtcNow.ToString("O"));
        descriptor.Properties[AnonymousProperty] =
            JsonSerializer.SerializeToElement(anonymous);
        if (ResolveRemoteAddress() is { } remoteAddress)
        {
            descriptor.Properties[RemoteAddressProperty] =
                JsonSerializer.SerializeToElement(remoteAddress);
        }
        if (Request.Headers.UserAgent.ToString() is { Length: > 0 } userAgent)
        {
            descriptor.Properties[UserAgentProperty] =
                JsonSerializer.SerializeToElement(
                    userAgent[..Math.Min(userAgent.Length, 256)]);
        }

        var requestedGrants = request.GrantTypes ?? new List<string>();
        var requestedScopes = request.Scopes ?? new List<string>();

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
        if (_validator.RequiresProofKeyForCodeExchange(grants))
        {
            descriptor.Permissions.Add(OpenIddictConstants.Permissions.Endpoints.Authorization);
            descriptor.Permissions.Add(OpenIddictConstants.Permissions.ResponseTypes.Code);
        }

        // Every dynamically registered authorization-code client must require
        // PKCE (RFC 7636). Confidential authentication does not replace the
        // code-verifier binding: a leaked authorization code is still
        // redeemable by a different client without this requirement.
        if (grants.Contains(OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode))
        {
            descriptor.Requirements.Add(OpenIddictConstants.Requirements.Features.ProofKeyForCodeExchange);
        }

        // Consume only now, after the metadata validated, so a rejected request
        // does not burn a single-use token. The update is atomic: of two
        // concurrent registrations with one single-use token, one proceeds.
        if (initialAccessToken is not null)
        {
            if (!await _initialAccessTokens.TryConsumeAsync(initialAccessToken.Id, ct))
            {
                return InvalidInitialAccessToken();
            }

            descriptor.Properties[InitialAccessTokenIdProperty] =
                JsonSerializer.SerializeToElement(initialAccessToken.Id.ToString());
        }

        await _applications.CreateAsync(descriptor, ct);

        // RFC 7591 §3.2.1 response: client_id, and client_secret when confidential.
        return Created(Url.Action(nameof(Register), new { clientId })!, new
        {
            client_id = descriptor.ClientId,
            client_secret = clientSecret,
            client_name = descriptor.DisplayName,
            token_endpoint_auth_method = authenticationMethod,
            jwks_uri = request.JwksUri?.AbsoluteUri,
            client_id_issued_at = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
        });
    }

    /// <summary>
    /// Rejects an anonymous registration that asks for more than the
    /// interactive sign-in profile. Rejecting (instead of narrowing) keeps the
    /// client honest about what it received.
    /// </summary>
    private object? ValidateAnonymousProfile(DcrRequest request)
    {
        if (!string.IsNullOrWhiteSpace(request.TokenEndpointAuthMethod)
            && !string.Equals(
                request.TokenEndpointAuthMethod, "none", StringComparison.Ordinal))
        {
            return new
            {
                error = "invalid_client_metadata",
                error_description =
                    "Anonymous registration issues public clients only; omit token_endpoint_auth_method or send \"none\".",
            };
        }

        if (!string.IsNullOrWhiteSpace(request.ClientSecret))
        {
            return new
            {
                error = "invalid_client_metadata",
                error_description =
                    "Anonymous registration cannot carry a client secret.",
            };
        }

        var deniedGrant = (request.GrantTypes ?? [])
            .Select(NormalizeGrantTypeName)
            .FirstOrDefault(grant => !_options.AnonymousGrantTypes.Contains(grant));
        if (deniedGrant is not null)
        {
            return new
            {
                error = "invalid_client_metadata",
                error_description =
                    $"Anonymous registration does not allow the '{deniedGrant}' grant type.",
            };
        }

        var deniedScope = (request.Scopes ?? [])
            .FirstOrDefault(scope => !_options.AnonymousScopes.Contains(scope));
        if (deniedScope is not null)
        {
            return new
            {
                error = "invalid_client_metadata",
                error_description =
                    $"Anonymous registration does not allow the '{deniedScope}' scope.",
            };
        }

        return null;
    }

    private static object? ValidateTokenPolicy(
        Sufficit.Identity.Core.Entities.DcrInitialAccessToken token,
        DcrRequest request)
    {
        var allowedGrants = Sufficit.Identity.Core.Services.DcrInitialAccessTokenStore
            .ReadList(token.AllowedGrantTypesJson);
        var deniedGrant = allowedGrants is null
            ? null
            : (request.GrantTypes ?? [])
                .Select(NormalizeGrantTypeName)
                .FirstOrDefault(grant => !allowedGrants.Contains(grant, StringComparer.Ordinal));
        if (deniedGrant is not null)
        {
            return new
            {
                error = "invalid_client_metadata",
                error_description =
                    $"The initial access token does not allow the '{deniedGrant}' grant type.",
            };
        }

        var allowedScopes = Sufficit.Identity.Core.Services.DcrInitialAccessTokenStore
            .ReadList(token.AllowedScopesJson);
        var deniedScope = allowedScopes is null
            ? null
            : (request.Scopes ?? [])
                .FirstOrDefault(scope => !allowedScopes.Contains(scope, StringComparer.Ordinal));
        return deniedScope is null
            ? null
            : new
            {
                error = "invalid_client_metadata",
                error_description =
                    $"The initial access token does not allow the '{deniedScope}' scope.",
            };
    }

    /// <summary>Maps the RFC 7591 spelling to the value the allowlists use.</summary>
    private static string NormalizeGrantTypeName(string grantType) =>
        grantType.Trim();

    private string? ResolveRemoteAddress()
    {
        var address = HttpContext.Connection.RemoteIpAddress;
        return address is null ? null : address.ToString();
    }

    private string? ReadBearerToken()
    {
        const string scheme = "Bearer ";
        var header = Request.Headers.Authorization.ToString();
        return header.StartsWith(scheme, StringComparison.OrdinalIgnoreCase)
            ? header[scheme.Length..].Trim()
            : null;
    }

    private IActionResult InvalidInitialAccessToken()
    {
        // RFC 6750 §3: the challenge names the bearer error.
        Response.Headers.WWWAuthenticate = "Bearer error=\"invalid_token\"";
        return Unauthorized(new { error = "invalid_token" });
    }

    /// <summary>
    /// Maps an RFC 7591 grant-type name (plain: <c>client_credentials</c>,
    /// <c>authorization_code</c>, <c>refresh_token</c>, <c>password</c>,
    /// <c>urn:ietf:params:oauth:grant-type:token-exchange</c>) to the OpenIddict
    /// permission constant (<c>gt:&lt;name&gt;</c>). Input is allowlisted before
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
    public string? TokenEndpointAuthMethod { get; set; }
    public string? ClientName { get; set; }
    public List<string>? GrantTypes { get; set; }
    public List<string>? Scopes { get; set; }
    public List<Uri> RedirectUris { get; set; } = new();
    public Uri? JwksUri { get; set; }
}
