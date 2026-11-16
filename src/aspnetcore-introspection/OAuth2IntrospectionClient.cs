using System.Collections.Concurrent;
using System.Text.Json;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Logging;

namespace Sufficit.Identity.AspNetCore.Authentication.OAuth2Introspection;

/// <summary>
/// Default <see cref="IOAuth2IntrospectionClient"/>:
/// <list type="bullet">
/// <item>active results are cached for <see cref="OAuth2IntrospectionOptions.CacheDuration"/>, never beyond <c>exp</c>;
/// inactive results and failures are never cached;</item>
/// <item>concurrent lookups of the same token share one call to the endpoint, so a burst does not multiply introspection load;</item>
/// <item>anything that is not a 2xx RFC 7662 document becomes <see cref="IntrospectionUnavailableException"/>.</item>
/// </list>
/// </summary>
public sealed class OAuth2IntrospectionClient(IHttpClientFactory clients, IDistributedCache cache, ILogger<OAuth2IntrospectionClient> logger,
    TimeProvider? time = null) : IOAuth2IntrospectionClient
{
    private readonly TimeProvider clock = time ?? TimeProvider.System;
    private readonly ConcurrentDictionary<string, Lazy<Task<IntrospectionResult>>> inflight = new();

    public async Task<IntrospectionResult> IntrospectAsync(string token, OAuth2IntrospectionOptions options, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(token);
        ArgumentNullException.ThrowIfNull(options);
        var key = options.CacheKeyGenerator(options, token);
        if (options.EnableCaching)
        {
            var cached = await ReadCacheAsync(key, cancellationToken);
            if (cached is not null) return cached;
        }
        // The shared call is not bound to the first caller's cancellation: one aborted request must not fail the others.
        var flight = key + "|" + options.ResolveEndpoint() + "|" + options.ClientId;
        var shared = inflight.GetOrAdd(flight, k => new Lazy<Task<IntrospectionResult>>(() => FetchAndRelease(k, key, token, options)));
        return await shared.Value.WaitAsync(cancellationToken);
    }

    private async Task<IntrospectionResult> FetchAndRelease(string flight, string cacheKey, string token, OAuth2IntrospectionOptions options)
    {
        try
        {
            var result = await FetchAsync(token, options);
            if (options.EnableCaching && result.IsActive) await WriteCacheAsync(cacheKey, result, options);
            return result;
        }
        finally { inflight.TryRemove(flight, out _); }
    }

    private async Task<IntrospectionResult> FetchAsync(string token, OAuth2IntrospectionOptions options)
    {
        var form = new Dictionary<string, string> { ["token"] = token, ["client_id"] = options.ClientId };
        if (!string.IsNullOrEmpty(options.ClientSecret)) form["client_secret"] = options.ClientSecret!;
        if (!string.IsNullOrEmpty(options.TokenTypeHint)) form["token_type_hint"] = options.TokenTypeHint!;
        var http = clients.CreateClient(OAuth2IntrospectionDefaults.HttpClientName);
        HttpResponseMessage response;
        try { response = await http.PostAsync(options.ResolveEndpoint(), new FormUrlEncodedContent(form)); }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException)
        {
            logger.LogWarning(ex, "Introspection endpoint unreachable.");
            throw new IntrospectionUnavailableException("Introspection endpoint unreachable.", null, ex);
        }
        using (response)
        {
            // RFC 7662 answers 200 with active=false for a bad token; any other status is the endpoint failing
            // (outage, throttling, or this resource's own client credentials) and never a verdict on the token.
            if (!response.IsSuccessStatusCode)
            {
                logger.LogWarning("Introspection endpoint answered {Status}.", (int)response.StatusCode);
                throw new IntrospectionUnavailableException($"Introspection endpoint answered {(int)response.StatusCode}.", response.StatusCode);
            }
            try
            {
                using var document = await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync());
                if (document.RootElement.ValueKind != JsonValueKind.Object || !document.RootElement.TryGetProperty("active", out _))
                    throw new IntrospectionUnavailableException("Introspection response is not an RFC 7662 document.", response.StatusCode);
                return new IntrospectionResult(document.RootElement, fromCache: false);
            }
            catch (JsonException ex)
            {
                throw new IntrospectionUnavailableException("Introspection response is not JSON.", response.StatusCode, ex);
            }
        }
    }

    private async Task<IntrospectionResult?> ReadCacheAsync(string key, CancellationToken ct)
    {
        byte[]? bytes;
        try { bytes = await cache.GetAsync(key, ct); }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // A broken cache degrades to calling the endpoint; it never refuses the request by itself.
            logger.LogWarning(ex, "Introspection cache read failed.");
            return null;
        }
        if (bytes is null) return null;
        try
        {
            using var document = JsonDocument.Parse(bytes);
            var result = new IntrospectionResult(document.RootElement, fromCache: true);
            return result.IsActive && (result.ExpiresAt is null || result.ExpiresAt > clock.GetUtcNow()) ? result : null;
        }
        catch (JsonException) { return null; }
    }

    private async Task WriteCacheAsync(string key, IntrospectionResult result, OAuth2IntrospectionOptions options)
    {
        var now = clock.GetUtcNow();
        var until = now + options.CacheDuration;
        if (result.ExpiresAt is { } exp && exp < until) until = exp;
        if (until <= now) return;
        try
        {
            await cache.SetAsync(key, JsonSerializer.SerializeToUtf8Bytes(result.Raw),
                new DistributedCacheEntryOptions { AbsoluteExpiration = until });
        }
        catch (Exception ex) { logger.LogWarning(ex, "Introspection cache write failed."); }
    }
}
