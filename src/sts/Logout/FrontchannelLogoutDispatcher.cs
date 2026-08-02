using System.Security.Cryptography;
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

    private readonly IOpenIddictAuthorizationManager _authorizationManager;
    private readonly IOpenIddictApplicationManager _applicationManager;
    private readonly IDistributedCache _cache;
    private readonly ILogger<FrontchannelLogoutDispatcher> _logger;
    private readonly string _issuer;

    public FrontchannelLogoutDispatcher(
        IOpenIddictAuthorizationManager authorizationManager,
        IOpenIddictApplicationManager applicationManager,
        IDistributedCache cache,
        SufficitIdentityOptions options,
        ILogger<FrontchannelLogoutDispatcher> logger)
    {
        _authorizationManager = authorizationManager;
        _applicationManager = applicationManager;
        _cache = cache;
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
        await _cache.SetStringAsync(
            CacheKeyPrefix + contextId,
            JsonSerializer.Serialize(logoutUris.Order(StringComparer.Ordinal)),
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
        var payload = await _cache.GetStringAsync(key, cancellationToken);
        if (payload is null)
        {
            return [];
        }

        // A front-channel context is deliberately single-use. Remove it before
        // parsing/rendering so a refresh cannot repeatedly log the user out of
        // every RP.
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
            (uri.Scheme == Uri.UriSchemeHttps || uri.Scheme == Uri.UriSchemeHttp))
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
