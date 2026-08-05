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

        var deliveryMethods = _options.SharedSignals.StreamManagementEnabled
            ? new[] { "urn:ietf:rfc:8935", "urn:ietf:rfc:8934" }
            : new[] { "urn:ietf:rfc:8935" };

        var metadata = new Dictionary<string, object?>
        {
            ["spec_version"] = "1_0",
            // This exact canonical value is also used as `iss` in every SET.
            ["issuer"] = issuer.AbsoluteUri,
            ["jwks_uri"] = jwksUri.AbsoluteUri,
            ["delivery_methods_supported"] = deliveryMethods,
            ["default_subjects"] = "ALL",
            // CAEP event types this transmitter can emit (SSF 1.0 optional
            // metadata). Kept in sync with CaepEventGenerator.*EventType.
            ["events_supported"] = new[]
            {
                SharedSignals.CaepEventGenerator.SessionRevokedEventType,
                SharedSignals.CaepEventGenerator.CredentialChangeEventType,
                SharedSignals.CaepEventGenerator.DeviceChangeEventType,
                SharedSignals.CaepEventGenerator.AssuranceLevelChangeEventType,
                SharedSignals.CaepEventGenerator.VerificationEventType,
            },
        };

        if (_options.SharedSignals.StreamManagementEnabled)
        {
            metadata["configuration_endpoint"] = "/ssf/streams";
            metadata["assertion_shape_supported"] = new[] { "secevent+jwt" };
        }

        return Ok(metadata);
    }
}
