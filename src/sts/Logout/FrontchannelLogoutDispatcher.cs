using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Logging;
using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Sufficit.Identity.STS.Logout;

/// <summary>
/// Prepares and consumes the one-time RP iframe list used by OIDC
/// Front-Channel Logout 1.0.
/// </summary>
public interface IFrontchannelLogoutDispatcher
{
    Task<string?> PrepareAsync(
        string subject,
        string? sessionId,
        CancellationToken cancellationToken);

    Task<IReadOnlyList<string>> ConsumeAsync(
        string contextId,
        CancellationToken cancellationToken);
}

internal sealed class FrontchannelLogoutDispatcher : IFrontchannelLogoutDispatcher
{
    internal const string CacheKeyPrefix = "oidc:frontchannel-logout:";

    private static readonly DistributedCacheEntryOptions CacheOptions = new()
    {
        AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(2),
    };

    /// <summary>
    /// Durable-state namespace for the logout context. See
    /// <see cref="IProtocolStateStore"/>.
    /// </summary>
    private const string StatePurpose = "frontchannel-logout";

    private static readonly TimeSpan ContextLifetime = TimeSpan.FromMinutes(2);

    private readonly IOpenIddictAuthorizationManager _authorizationManager;
    private readonly IOpenIddictApplicationManager _applicationManager;
    private readonly IDistributedCache _cache;
    // Durable primary. Optional so focused unit tests can construct the
    // dispatcher with a cache alone; the STS composition always supplies it.
    private readonly IProtocolStateStore? _state;
    private readonly ILogger<FrontchannelLogoutDispatcher> _logger;
    private readonly string _issuer;

    public FrontchannelLogoutDispatcher(
        IOpenIddictAuthorizationManager authorizationManager,
        IOpenIddictApplicationManager applicationManager,
        IDistributedCache cache,
        SufficitIdentityOptions options,
        ILogger<FrontchannelLogoutDispatcher> logger,
        IProtocolStateStore? state = null)
    {
        _authorizationManager = authorizationManager;
        _applicationManager = applicationManager;
        _cache = cache;
        _state = state;
        _logger = logger;
        _issuer = string.IsNullOrWhiteSpace(options.Issuer)
            ? "https://localhost/"
            : options.Issuer;
    }

    public async Task<string?> PrepareAsync(
        string subject,
        string? sessionId,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(subject);

        var logoutUris = new HashSet<string>(StringComparer.Ordinal);

        await foreach (var authorization in _authorizationManager.FindAsync(
            subject: subject,
            client: null,
            status: Statuses.Valid,
            type: AuthorizationTypes.Permanent,
            scopes: System.Collections.Immutable.ImmutableArray<string>.Empty,
            cancellationToken: cancellationToken))
        {
            var applicationId = await _authorizationManager.GetApplicationIdAsync(
                authorization, cancellationToken);
            if (applicationId is null)
            {
                continue;
            }

            var application = await _applicationManager.FindByIdAsync(
                applicationId, cancellationToken);
            if (application is null)
            {
                continue;
            }

            var settings = await _applicationManager.GetSettingsAsync(
                application, cancellationToken);
            if (!settings.TryGetValue("frontchannel_logout_uri", out var configuredUri) ||
                !TryValidateLogoutUri(configuredUri, out var logoutUri))
            {
                continue;
            }

            var sessionRequired = settings.TryGetValue(
                    "frontchannel_logout_session_required", out var rawSessionRequired) &&
                bool.TryParse(rawSessionRequired, out var parsedSessionRequired) &&
                parsedSessionRequired;

            if (sessionRequired && string.IsNullOrWhiteSpace(sessionId))
            {
                var clientId = await _applicationManager.GetClientIdAsync(
                    application, cancellationToken);
                _logger.LogWarning(
                    "Front-channel logout skipped for client {ClientId}: the RP requires sid, " +
                    "but this OP session does not expose one.",
                    clientId);
                continue;
            }

            var absoluteUri = logoutUri.AbsoluteUri;
            if (!string.IsNullOrWhiteSpace(sessionId))
            {
                absoluteUri = QueryHelpers.AddQueryString(absoluteUri, new Dictionary<string, string?>
                {
                    ["iss"] = _issuer,
                    ["sid"] = sessionId,
                });
            }

            logoutUris.Add(absoluteUri);
        }

        if (logoutUris.Count == 0)
        {
            return null;
        }

        var contextId = WebEncoders.Base64UrlEncode(RandomNumberGenerator.GetBytes(32));
        var payload = JsonSerializer.Serialize(logoutUris.Order(StringComparer.Ordinal));

        // Written to both backends: the durable store is what makes the context
        // visible to whichever replica the browser's follow-up request reaches
        // (eval 2026-08-30, F-4), while the cache keeps a not-yet-upgraded
        // replica working through a rolling deployment.
        if (_state is not null)
        {
            await _state.SetAsync(
                StatePurpose,
                contextId,
                Encoding.UTF8.GetBytes(payload),
                ContextLifetime,
                cancellationToken);
        }

        await _cache.SetStringAsync(
            CacheKeyPrefix + contextId,
            payload,
            CacheOptions,
            cancellationToken);

        return contextId;
    }

    public async Task<IReadOnlyList<string>> ConsumeAsync(
        string contextId,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(contextId) || contextId.Length > 128)
        {
            return [];
        }

        var key = CacheKeyPrefix + contextId;

        // The durable store is AUTHORITATIVE whenever it is registered: the
        // cache must never answer a single-use consume. Falling back to it
        // reintroduced the replay this context exists to prevent — the replica
        // that PREPARED the context keeps a copy in its process-local cache,
        // so after another replica consumed and deleted the durable row, a
        // browser landing back on the first replica read the stale copy and
        // logged the user out of every RP a second time. The cache is written
        // alongside only so a not-yet-upgraded replica can still serve a
        // context it created; it is never consulted once the durable store is
        // present.
        string? payload;
        if (_state is not null)
        {
            var durable = await _state.GetAsync(
                StatePurpose,
                contextId,
                cancellationToken);
            payload = durable is { Length: > 0 }
                ? Encoding.UTF8.GetString(durable)
                : null;
        }
        else
        {
            payload = await _cache.GetStringAsync(key, cancellationToken);
        }

        if (payload is null)
        {
            return [];
        }

        // Single-use: remove before parsing/rendering so a refresh cannot
        // repeatedly log the user out of every RP. Both backends are cleared —
        // the cache copy is not authoritative, but leaving it behind would
        // resurrect the context on a replica that later lost its durable store.
        if (_state is not null)
        {
            await _state.RemoveAsync(StatePurpose, contextId, cancellationToken);
        }

        await _cache.RemoveAsync(key, cancellationToken);

        try
        {
            return JsonSerializer.Deserialize<string[]>(payload)?
                .Where(value => TryValidateLogoutUri(value, out _))
                .Distinct(StringComparer.Ordinal)
                .ToArray() ?? [];
        }
        catch (JsonException ex)
        {
            _logger.LogWarning(ex, "Invalid front-channel logout context {ContextId} was discarded.", contextId);
            return [];
        }
    }

    private static bool TryValidateLogoutUri(string? value, out Uri uri)
    {
        if (Uri.TryCreate(value, UriKind.Absolute, out uri!) &&
            uri.Fragment.Length == 0 &&
            uri.Scheme == Uri.UriSchemeHttps)
        {
            return true;
        }

        uri = null!;
        return false;
    }
}

internal sealed class NullFrontchannelLogoutDispatcher : IFrontchannelLogoutDispatcher
{
    public Task<string?> PrepareAsync(
        string subject,
        string? sessionId,
        CancellationToken cancellationToken) => Task.FromResult<string?>(null);

    public Task<IReadOnlyList<string>> ConsumeAsync(
        string contextId,
        CancellationToken cancellationToken) => Task.FromResult<IReadOnlyList<string>>([]);
}
