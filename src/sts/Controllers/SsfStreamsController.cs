using System.ComponentModel.DataAnnotations;
using System.Net.Http.Headers;
using System.Text.Json;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.Extensions.Logging;
using OpenIddict.Abstractions;
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
        SufficitIdentityOptions options)
    {
        _store = store;
        _generator = generator;
        _httpClientFactory = httpClientFactory;
        _logger = logger;
        _options = options;
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

        /// <summary>Subject scope JSON, or "ALL" for every subject.</summary>
        public string? Subject { get; init; }

        /// <summary>
        /// Event-type URIs to receive. Must list at least one type; an empty
        /// list subscribes to nothing, not to everything.
        /// </summary>
        public IReadOnlyCollection<string>? EventsRequested { get; init; }

        public string? Description { get; init; }
    }

    public sealed class VerifyStreamRequest
    {
        public string? State { get; init; }
    }

    [HttpPost]
    public async Task<IActionResult> Create(
        [FromBody] CreateStreamRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        var ownerClientId = ResolveOwnerClientId();
        if (ownerClientId is null) return Forbid();

        // Least privilege on subscription scope. An omitted events_requested
        // used to mean "every supported event type", so the least specific
        // request produced the broadest delivery — every CAEP signal for every
        // subject. Require the subscription to be stated explicitly.
        var requestedEvents = request.EventsRequested ?? [];
        if (requestedEvents.Count == 0)
        {
            return BadRequest(new
            {
                error = "invalid_request",
                error_description =
                    "events_requested must list at least one event type. A stream "
                    + "that subscribes to nothing receives nothing; an empty list "
                    + "is no longer interpreted as 'all events'.",
            });
        }

        // Subject scope. ALL means every subject in the deployment, so an
        // omitted subject is a broad grant by accident. Tightening this is
        // breaking for existing receivers, so it is opt-in; otherwise the
        // legacy default is kept but surfaced in the logs.
        if (string.IsNullOrWhiteSpace(request.Subject))
        {
            if (_options.SharedSignals.RequireExplicitSubject)
            {
                return BadRequest(new
                {
                    error = "invalid_request",
                    error_description =
                        "subject must be supplied explicitly. Use \"ALL\" to "
                        + "deliberately subscribe to every subject.",
                });
            }

            _logger.LogWarning(
                "SSF stream created by client {OwnerClientId} without an explicit "
                + "subject; defaulting to ALL (every subject in the deployment). "
                + "Set Sufficit:Identity:SharedSignals:RequireExplicitSubject=true "
                + "to require an explicit choice.",
                ownerClientId);
        }

        var state = Microsoft.AspNetCore.WebUtilities.WebEncoders.Base64UrlEncode(
            System.Security.Cryptography.RandomNumberGenerator.GetBytes(32));
        var verificationExpiresAtUtc = DateTime.UtcNow.AddHours(24);

        SsfStream stream;
        try
        {
            stream = await _store.CreateAsync(
                ownerClientId,
                request.Audience,
                request.Delivery,
                request.Endpoint,
                request.Authorization,
                request.Subject ?? "ALL",
                requestedEvents,
                request.Description,
                state,
                verificationExpiresAtUtc,
                cancellationToken);
        }
        catch (ArgumentException ex)
        {
            return BadRequest(new { error = "invalid_request", error_description = ex.Message });
        }

        // RFC 8933 §6: emit a verification SET so the receiver can confirm it
        // decodes SETs from this transmitter before the stream goes live.
        await EmitVerificationAsync(stream, state, cancellationToken);

        return CreatedAtAction(
            actionName: nameof(Get),
            routeValues: new { id = stream.StreamId },
            value: ToResponse(stream));
    }

    [HttpGet]
    public async Task<IActionResult> List(CancellationToken cancellationToken)
    {
        var ownerClientId = ResolveOwnerClientId();
        if (ownerClientId is null) return Forbid();
        var streams = await _store.ListEnabledForOwnerAsync(
            ownerClientId, cancellationToken);
        return Ok(streams.Select(ToResponse).ToArray());
    }

    [HttpGet("{id}")]
    public async Task<IActionResult> Get(string id, CancellationToken cancellationToken)
    {
        var ownerClientId = ResolveOwnerClientId();
        if (ownerClientId is null) return Forbid();
        var stream = await _store.GetByStreamIdForOwnerAsync(
            ownerClientId, id, cancellationToken);
        return stream is null
            ? NotFound(new { error = "stream_not_found" })
            : Ok(ToResponse(stream));
    }

    [HttpDelete("{id}")]
    public async Task<IActionResult> Delete(string id, CancellationToken cancellationToken)
    {
        var ownerClientId = ResolveOwnerClientId();
        if (ownerClientId is null) return Forbid();
        await _store.DisableForOwnerAsync(ownerClientId, id, cancellationToken);
        return NoContent();
    }

    [HttpPost("{id}/verify")]
    public async Task<IActionResult> Verify(
        string id,
        [FromBody(EmptyBodyBehavior = EmptyBodyBehavior.Allow)] VerifyStreamRequest? request,
        CancellationToken cancellationToken)
    {
        var ownerClientId = ResolveOwnerClientId();
        if (ownerClientId is null) return Forbid();

        var result = await _store.VerifyAsync(
            ownerClientId, id, request?.State, cancellationToken);
        return result switch
        {
            SsfVerificationResult.Verified =>
                Ok(new { stream_id = id, status = "verified" }),
            SsfVerificationResult.NotFound =>
                NotFound(new { error = "stream_not_found" }),
            SsfVerificationResult.Expired =>
                Conflict(new
                {
                    error = "verification_expired",
                    error_description = "The verification state has expired; recreate the stream to issue a new challenge.",
                }),
            _ => BadRequest(new
            {
                error = "invalid_verification_state",
                error_description = "The verification state does not match the state sent in the verification SET.",
            }),
        };
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
    private async Task EmitVerificationAsync(
        SsfStream stream,
        string state,
        CancellationToken cancellationToken)
    {
        var set = _generator.GenerateVerification(stream.Audience, state);

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

    private string? ResolveOwnerClientId() =>
        User.FindFirst(OpenIddictConstants.Claims.ClientId)?.Value
        ?? User.FindFirst(OpenIddictConstants.Claims.AuthorizedParty)?.Value
        ?? User.FindFirst(OpenIddictConstants.Claims.Private.Presenter)?.Value
        ?? User.FindFirst("azp")?.Value;
}
