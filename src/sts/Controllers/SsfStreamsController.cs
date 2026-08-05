using System.ComponentModel.DataAnnotations;
using System.Net.Http.Headers;
using System.Text.Json;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using OpenIddict.Validation.AspNetCore;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.STS.SharedSignals;

namespace Sufficit.Identity.STS.Controllers;

/// <summary>Policy requirement that checks for a specific OAuth scope.</summary>
internal sealed class SsfScopeRequirement : IAuthorizationRequirement
{
    public string Scope { get; }
    public SsfScopeRequirement(string scope) => Scope = scope;
}

/// <summary>Validates that the access token carries the required scope.</summary>
internal sealed class SsfScopeHandler : AuthorizationHandler<SsfScopeRequirement>
{
    private const string ScopeClaimType = "scope";

    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context, SsfScopeRequirement requirement)
    {
        var scopes = context.User.FindAll(ScopeClaimType).SelectMany(c =>
            c.Value.Split(' ', StringSplitOptions.RemoveEmptyEntries));

        if (scopes.Contains(requirement.Scope))
        {
            context.Succeed(requirement);
        }

        return Task.CompletedTask;
    }
}

/// <summary>
/// RFC 8933 dynamic stream-management surface. Only mapped when
/// <c>Sufficit:Identity:SharedSignals:StreamManagementEnabled</c> is true.
/// All endpoints require the <c>ssf_transmitter</c> scope (configurable).
/// </summary>
[ApiController]
[Authorize(Policy = "sufficit-ssf-transmitter",
    AuthenticationSchemes = OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme)]
[Route("ssf/streams")]
public sealed class SsfStreamsController : ControllerBase
{
    private readonly ISsfStreamStore _store;
    private readonly CaepEventGenerator _generator;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly ILogger<SsfStreamsController> _logger;
    private readonly SufficitIdentityOptions _options;

    public SsfStreamsController(
        ISsfStreamStore store,
        CaepEventGenerator generator,
        IHttpClientFactory httpClientFactory,
        ILogger<SsfStreamsController> logger,
        IOptions<SufficitIdentityOptions> options)
    {
        _store = store;
        _generator = generator;
        _httpClientFactory = httpClientFactory;
        _logger = logger;
        _options = options.Value;
    }

    public sealed class CreateStreamRequest
    {
        [Required]
        public string Audience { get; init; } = string.Empty;

        /// <summary>Either <c>urn:ietf:rfc:8935</c> (push) or <c>urn:ietf:rfc:8934</c> (poll).</summary>
        [Required]
        public string Delivery { get; init; } = SsfStreamStore.PushDeliveryMethod;

        /// <summary>HTTPS push endpoint (required for push, ignored for poll).</summary>
        public string? Endpoint { get; init; }

        /// <summary>Optional Authorization header value for push delivery.</summary>
        public string? Authorization { get; init; }

        /// <summary>Subject scope JSON or "ALL".</summary>
        public string? Subject { get; init; }

        /// <summary>Event-type URIs to receive; empty = all supported.</summary>
        public IReadOnlyCollection<string>? EventsRequested { get; init; }

        public string? Description { get; init; }
    }

    [HttpPost]
    public async Task<IActionResult> Create(
        [FromBody] CreateStreamRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        SsfStream stream;
        try
        {
            stream = await _store.CreateAsync(
                request.Audience,
                request.Delivery,
                request.Endpoint,
                request.Authorization,
                request.Subject ?? "ALL",
                request.EventsRequested ?? [],
                request.Description,
                cancellationToken);
        }
        catch (ArgumentException ex)
        {
            return BadRequest(new { error = "invalid_request", error_description = ex.Message });
        }

        // RFC 8933 §6: emit a verification SET so the receiver can confirm it
        // decodes SETs from this transmitter before the stream goes live.
        await EmitVerificationAsync(stream, cancellationToken);

        return CreatedAtAction(
            actionName: nameof(Get),
            routeValues: new { id = stream.StreamId },
            value: ToResponse(stream));
    }

    [HttpGet]
    public async Task<IActionResult> List(CancellationToken cancellationToken)
    {
        var streams = await _store.ListEnabledAsync(cancellationToken);
        return Ok(streams.Select(ToResponse).ToArray());
    }

    [HttpGet("{id}")]
    public async Task<IActionResult> Get(string id, CancellationToken cancellationToken)
    {
        var stream = await _store.GetByStreamIdAsync(id, cancellationToken);
        return stream is null
            ? NotFound(new { error = "stream_not_found" })
            : Ok(ToResponse(stream));
    }

    [HttpDelete("{id}")]
    public async Task<IActionResult> Delete(string id, CancellationToken cancellationToken)
    {
        await _store.DisableAsync(id, cancellationToken);
        return NoContent();
    }

    [HttpPost("{id}/verify")]
    public async Task<IActionResult> Verify(string id, CancellationToken cancellationToken)
    {
        var stream = await _store.GetByStreamIdAsync(id, cancellationToken);
        if (stream is null)
        {
            return NotFound(new { error = "stream_not_found" });
        }

        await _store.MarkVerifiedAsync(id, cancellationToken);
        return Ok(new { stream_id = id, status = "verified" });
    }

    private object ToResponse(SsfStream stream) => new
    {
        stream_id = stream.StreamId,
        description = stream.Description,
        configuration_endpoint = $"/ssf/streams/{stream.StreamId}",
        verification_endpoint = $"/ssf/streams/{stream.StreamId}/verify",
        delivery = new
        {
            method = stream.DeliveryMethod,
            endpoint_url = stream.Endpoint,
        },
        events_requested = ParseJsonArray(stream.EventsRequested),
        subject = ParseSubject(stream.SubjectScope),
        status = stream.Status,
        verification_state = stream.VerificationState,
    };

    /// <summary>
    /// Emits the RFC 8933 verification SET for a freshly-created stream: push
    /// streams get an immediate HTTP POST, poll streams get an enqueued row.
    /// Failures are logged but never fail the create response — the receiver
    /// can call <c>/verify</c> explicitly later.
    /// </summary>
    private async Task EmitVerificationAsync(SsfStream stream, CancellationToken cancellationToken)
    {
        var state = System.Security.Cryptography.RandomNumberGenerator.GetBytes(16);
        var stateB64 = Microsoft.AspNetCore.WebUtilities.WebEncoders.Base64UrlEncode(state);
        var set = _generator.GenerateVerification(stream.Audience, stateB64);

        try
        {
            if (stream.DeliveryMethod == SsfStreamStore.PollDeliveryMethod)
            {
                var jwt = new Microsoft.IdentityModel.JsonWebTokens.JsonWebToken(set);
                var jti = jwt.TryGetPayloadValue("jti", out string j)
                    ? j : Guid.NewGuid().ToString("N");
                await _store.EnqueuePollDeliveryAsync(stream.StreamId, jti, set, cancellationToken);
            }
            else if (!string.IsNullOrWhiteSpace(stream.Endpoint))
            {
                var client = _httpClientFactory.CreateClient("ssf-verification");
                using var request = new HttpRequestMessage(HttpMethod.Post, stream.Endpoint);
                request.Content = new StringContent(set);
                request.Content.Headers.ContentType =
                    new System.Net.Http.Headers.MediaTypeHeaderValue("application/secevent+jwt");
                if (!string.IsNullOrWhiteSpace(stream.Authorization))
                {
                    request.Headers.TryAddWithoutValidation(
                        "Authorization", stream.Authorization);
                }
                using var response = await client.SendAsync(request, cancellationToken);
                if (!response.IsSuccessStatusCode)
                {
                    _logger.LogWarning(
                        "SSF verification POST to stream {StreamId} returned {Status}.",
                        stream.StreamId, (int)response.StatusCode);
                }
            }
        }
        catch (Exception exception)
        {
            _logger.LogWarning(exception,
                "SSF verification emission to stream {StreamId} failed.",
                stream.StreamId);
        }
    }

    private static IReadOnlyCollection<string> ParseJsonArray(string value)
    {
        if (string.IsNullOrWhiteSpace(value)) return [];
        try
        {
            return System.Text.Json.JsonSerializer.Deserialize<string[]>(value) ?? [];
        }
        catch
        {
            return [];
        }
    }

    private static object ParseSubject(string value)
    {
        if (string.IsNullOrWhiteSpace(value) || value == "ALL") return "ALL";
        return value;
    }
}
