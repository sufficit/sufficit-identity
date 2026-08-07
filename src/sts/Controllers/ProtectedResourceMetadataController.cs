using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Sufficit.Identity.STS.Controllers;

/// <summary>
/// Serves the RFC 9728 Protected Resource Metadata document at
/// <c>/.well-known/oauth-protected-resource</c>.
/// </summary>
/// <remarks>
/// RFC 9728 defines the metadata a Resource Server (RS) — including an MCP
/// server, or this STS's own protected endpoints (introspection) — publishes so
/// a client can discover which Authorization Server(s) issue tokens it accepts.
/// The handshake (item 4.1): client calls the RS → 401 with a
/// <c>WWW-Authenticate</c> header advertising the metadata URL → client reads
/// the document → finds the AS in <c>authorization_servers</c> → reads the AS's
/// <c>.well-known/openid-configuration</c> → obtains an audience-bound token.
/// This STS is primarily an AS, but its introspection/revocation endpoints are
/// themselves protected resources; serving this document completes the MCP
/// discovery loop when this host acts as both.
/// </remarks>
[ApiController]
[AllowAnonymous]
[Route(".well-known/oauth-protected-resource")]
public sealed class ProtectedResourceMetadataController : ControllerBase
{
    private readonly SufficitIdentityOptions _options;
    private readonly IPublicOriginResolver _publicOrigin;

    public ProtectedResourceMetadataController(
        SufficitIdentityOptions options,
        IPublicOriginResolver publicOrigin)
    {
        _options = options;
        _publicOrigin = publicOrigin;
    }

    [HttpGet]
    public IActionResult Get()
    {
        // The resource identifier: the canonical URL of this protected
        // resource (the STS's own issuer root). The AS that issues tokens for
        // it is the STS itself.
        var issuer = ResolveIssuer();

        // RFC 9728 §2.1 required/recommended fields:
        //   - resource (required): the resource's identifier.
        //   - authorization_servers (required): array of AS issuer identifiers.
        //   - bearer_methods_supported: how to present the token (header only).
        //   - scopes_supported: scopes this RS recognizes.
        // The document is intentionally minimal and static — it advertises the
        // AS location, which is the load-bearing piece for MCP discovery.
        var applicationScopes = _options.ClaimScopeMap.ClaimToScope
            .Values
            .Where(scope => !string.IsNullOrWhiteSpace(scope))
            .Distinct(StringComparer.Ordinal)
            .ToArray();

        return Ok(new
        {
            resource = issuer,
            authorization_servers = new[] { issuer },
            bearer_methods_supported = new[] { "header" },
            // The RS-recognized scopes are the same the AS advertises (this host
            // is both); a client can read the canonical list from the AS
            // discovery's scopes_supported.
            scopes_supported = new[]
            {
                "openid", "profile", "email", "roles",
                "identity.management",
                "sufficit_ai_openai_bridge"
            }.Concat(applicationScopes).Distinct(StringComparer.Ordinal).ToArray(),
            // Introspection is the protected resource this host exposes for RSs.
            introspection_signing_alg_values_supported = new[] { "RS256" }
        });
    }

    private string ResolveIssuer()
    {
        return _publicOrigin.Resolve(Request);
    }
}
