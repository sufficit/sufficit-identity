using Microsoft.AspNetCore.Mvc;

namespace Sufficit.Identity.STS.Controllers;

[ApiController]
public sealed class SharedSignalsController : ControllerBase
{
    private readonly SufficitIdentityOptions _options;

    public SharedSignalsController(SufficitIdentityOptions options) =>
        _options = options;

    [HttpGet("~/.well-known/ssf-configuration")]
    [Produces("application/json")]
    public IActionResult Configuration()
    {
        if (!_options.SharedSignals.Enabled) return NotFound();

        var issuer = new Uri(_options.Issuer!, UriKind.Absolute);
        var jwksUri = new Uri(issuer, ".well-known/openid-configuration/jwks");
        return Ok(new
        {
            spec_version = "1_0",
            // This exact canonical value is also used as `iss` in every SET.
            issuer = issuer.AbsoluteUri,
            jwks_uri = jwksUri.AbsoluteUri,
            delivery_methods_supported = new[] { "urn:ietf:rfc:8935" },
            default_subjects = "ALL",
        });
    }
}
