using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using OpenIddict.Abstractions;
using OpenIddict.Validation.AspNetCore;
using Sufficit.Identity.STS.SharedSignals;

namespace Sufficit.Identity.STS.Controllers;

/// <summary>
/// RFC 8934 poll delivery surface. A client pulls queued SETs for its stream
/// from <c>GET /ssf/events</c> and the transmitter marks them consumed.
/// Only mapped when stream management is enabled; requires the
/// <c>ssf_transmitter</c> scope.
/// </summary>
[ApiController]
[Authorize(Policy = "sufficit-ssf-transmitter",
    AuthenticationSchemes = OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme)]
[Route("ssf/events")]
public sealed class SsfPollController : ControllerBase
{
    private readonly ISsfStreamStore _store;

    public SsfPollController(ISsfStreamStore store) => _store = store;

    [HttpGet]
    public async Task<IActionResult> Pull(
        [FromQuery] string stream_id,
        [FromQuery] int limit = 10,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(stream_id))
        {
            return BadRequest(new { error = "invalid_request", error_description = "stream_id is required." });
        }

        var ownerClientId = ResolveOwnerClientId();
        if (ownerClientId is null) return Forbid();

        var stream = await _store.GetByStreamIdForOwnerAsync(
            ownerClientId, stream_id, cancellationToken);
        if (stream is null)
        {
            return NotFound(new { error = "stream_not_found" });
        }
        if (stream.DeliveryMethod != SsfStreamStore.PollDeliveryMethod)
        {
            return BadRequest(new
            {
                error = "invalid_request",
                error_description = "This stream is not configured for poll delivery.",
            });
        }

        var (payloads, moreAvailable) = await _store.PullAndConsumeAsync(
            stream_id, limit, cancellationToken);

        return Ok(new
        {
            events = payloads,
            more_available = moreAvailable,
        });
    }

    private string? ResolveOwnerClientId() =>
        User.FindFirst(OpenIddictConstants.Claims.ClientId)?.Value
        ?? User.FindFirst(OpenIddictConstants.Claims.AuthorizedParty)?.Value
        ?? User.FindFirst(OpenIddictConstants.Claims.Private.Presenter)?.Value
        ?? User.FindFirst("azp")?.Value;
}
