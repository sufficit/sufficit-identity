using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using Sufficit.Identity.Application.Security;

namespace Sufficit.Identity.STS.Jar;

internal interface IJarSigningKeyResolver
{
    Task<IReadOnlyList<SecurityKey>> ResolveAsync(
        object application,
        string? kid,
        CancellationToken cancellationToken);
}

internal sealed class JarSigningKeyResolver(
    IOpenIddictApplicationManager applications,
    RemoteJwksProvider remoteJwks)
    : IJarSigningKeyResolver
{
    public async Task<IReadOnlyList<SecurityKey>> ResolveAsync(
        object application,
        string? kid,
        CancellationToken cancellationToken)
    {
        var embedded = await applications.GetJsonWebKeySetAsync(
            application,
            cancellationToken);
        if (embedded is { Keys.Count: > 0 })
        {
            return ParseEmbedded(embedded.Keys, kid);
        }

        var settings = await applications.GetSettingsAsync(
            application,
            cancellationToken);
        var properties = await applications.GetPropertiesAsync(
            application,
            cancellationToken);
        settings.TryGetValue("jwks_uri", out var settingsUri);
        var propertiesUri = properties.TryGetValue(
                "jwks_uri",
                out var property)
            && property.ValueKind == JsonValueKind.String
            ? property.GetString()
            : null;
        if (!string.IsNullOrWhiteSpace(settingsUri)
            && !string.IsNullOrWhiteSpace(propertiesUri)
            && !string.Equals(
                settingsUri,
                propertiesUri,
                StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                "Client metadata contains conflicting jwks_uri values.");
        }

        var value = settingsUri ?? propertiesUri;
        if (string.IsNullOrWhiteSpace(value)) return [];
        if (!Uri.TryCreate(value, UriKind.Absolute, out var uri))
        {
            throw new InvalidOperationException(
                "The registered client jwks_uri is not an absolute URI.");
        }
        return await remoteJwks.GetKeysAsync(uri, kid, cancellationToken);
    }

    private static IReadOnlyList<SecurityKey> ParseEmbedded(
        IEnumerable<Microsoft.IdentityModel.Tokens.JsonWebKey> keys,
        string? kid)
    {
        var result = new List<SecurityKey>();
        foreach (var key in keys)
        {
            try
            {
                var parsed = Microsoft.IdentityModel.Tokens.JsonWebKey.Create(
                    JsonSerializer.Serialize(key));
                if (kid is null || string.Equals(
                        parsed.KeyId,
                        kid,
                        StringComparison.Ordinal))
                {
                    result.Add(parsed);
                }
            }
            catch (Exception exception) when (
                exception is ArgumentException or JsonException)
            {
                // Invalid embedded members are ignored; an empty result fails
                // the request object closed in the caller.
            }
        }
        return result;
    }
}

internal sealed class RemoteJwksProvider
{
    private const int MaximumKeys = 64;
    private readonly HttpClient _client;
    private readonly JarOptions _options;
    private readonly TimeProvider _timeProvider;
    private readonly ConcurrentDictionary<string, CacheEntry> _cache =
        new(StringComparer.Ordinal);
    private readonly SemaphoreSlim _refreshLock = new(1, 1);

    public RemoteJwksProvider(
        IHttpClientFactory clients,
        SufficitIdentityOptions options,
        TimeProvider timeProvider)
        : this(
            clients.CreateClient("jar-remote-jwks"),
            options.Jar,
            timeProvider)
    {
    }

    internal RemoteJwksProvider(
        HttpClient client,
        JarOptions options,
        TimeProvider? timeProvider = null)
    {
        _client = client;
        _options = options;
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    internal int CacheEntryCount => _cache.Count;

    public async Task<IReadOnlyList<SecurityKey>> GetKeysAsync(
        Uri uri,
        string? kid,
        CancellationToken cancellationToken)
    {
        ValidateUri(uri);
        var cacheKey = uri.AbsoluteUri;
        var now = _timeProvider.GetUtcNow();
        _cache.TryGetValue(cacheKey, out var cached);
        var cachedMatch = SelectKeys(cached?.Keys, kid);
        if (cached is not null
            && cached.FreshUntilUtc > now
            && cachedMatch.Count > 0)
        {
            return cachedMatch;
        }

        await _refreshLock.WaitAsync(cancellationToken);
        try
        {
            now = _timeProvider.GetUtcNow();
            _cache.TryGetValue(cacheKey, out cached);
            cachedMatch = SelectKeys(cached?.Keys, kid);
            if (cached is not null
                && cached.FreshUntilUtc > now
                && cachedMatch.Count > 0)
            {
                return cachedMatch;
            }

            try
            {
                var fetched = await FetchAsync(uri, cancellationToken);
                var entry = new CacheEntry(
                    fetched,
                    now.AddSeconds(_options.RemoteJwksCacheSeconds),
                    now.AddSeconds(
                        _options.RemoteJwksCacheSeconds
                        + _options.RemoteJwksStaleSeconds),
                    now);
                AddBounded(cacheKey, entry);
                return SelectKeys(fetched, kid);
            }
            catch (Exception exception) when (
                exception is HttpRequestException
                    or TaskCanceledException
                    or JsonException)
            {
                if (cached is not null
                    && cached.StaleUntilUtc > now
                    && cachedMatch.Count > 0)
                {
                    return cachedMatch;
                }
                throw;
            }
        }
        finally
        {
            _refreshLock.Release();
        }
    }

    internal static void ValidateUri(Uri uri)
    {
        ArgumentNullException.ThrowIfNull(uri);
        if (!PublicHttpsUriPolicy.IsAllowed(uri))
        {
            throw new HttpRequestException(
                "Client jwks_uri must be a public absolute HTTPS URI without user-info or fragment.");
        }
    }

    private async Task<IReadOnlyList<Microsoft.IdentityModel.Tokens.JsonWebKey>>
        FetchAsync(Uri uri, CancellationToken cancellationToken)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(
            cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(
            _options.RemoteJwksTimeoutSeconds));
        using var request = new HttpRequestMessage(HttpMethod.Get, uri);
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue(
            "application/jwk-set+json"));
        using var response = await _client.SendAsync(
            request,
            HttpCompletionOption.ResponseHeadersRead,
            timeout.Token);
        if (response.StatusCode is >= HttpStatusCode.MultipleChoices
            and < HttpStatusCode.BadRequest)
        {
            throw new HttpRequestException(
                "Redirects are not allowed for client jwks_uri.");
        }
        response.EnsureSuccessStatusCode();
        if (response.Content.Headers.ContentLength is { } declaredLength
            && declaredLength > _options.RemoteJwksMaxBytes)
        {
            throw new HttpRequestException(
                "Remote JWKS exceeds the configured response-size limit.");
        }

        await using var stream = await response.Content.ReadAsStreamAsync(
            timeout.Token);
        using var buffer = new MemoryStream();
        var chunk = new byte[8192];
        while (true)
        {
            var read = await stream.ReadAsync(chunk, timeout.Token);
            if (read == 0) break;
            if (buffer.Length + read > _options.RemoteJwksMaxBytes)
            {
                throw new HttpRequestException(
                    "Remote JWKS exceeds the configured response-size limit.");
            }
            buffer.Write(chunk, 0, read);
        }

        using var document = JsonDocument.Parse(buffer.ToArray());
        if (document.RootElement.ValueKind != JsonValueKind.Object
            || !document.RootElement.TryGetProperty("keys", out var keys)
            || keys.ValueKind != JsonValueKind.Array
            || keys.GetArrayLength() is < 1 or > MaximumKeys)
        {
            throw new JsonException(
                "Remote JWKS must contain between 1 and 64 keys.");
        }

        var result = new List<Microsoft.IdentityModel.Tokens.JsonWebKey>(
            keys.GetArrayLength());
        var keyIds = new HashSet<string>(StringComparer.Ordinal);
        foreach (var element in keys.EnumerateArray())
        {
            if (element.ValueKind != JsonValueKind.Object
                || ContainsPrivateMaterial(element))
            {
                throw new JsonException(
                    "Remote JWKS contains an invalid or private key.");
            }

            var key = Microsoft.IdentityModel.Tokens.JsonWebKey.Create(
                element.GetRawText());
            if (key.Kty is not ("RSA" or "EC")
                || (!string.IsNullOrWhiteSpace(key.Use)
                    && !string.Equals(key.Use, "sig", StringComparison.Ordinal)))
            {
                continue;
            }
            if (!string.IsNullOrWhiteSpace(key.KeyId)
                && !keyIds.Add(key.KeyId))
            {
                throw new JsonException(
                    "Remote JWKS contains duplicate kid values.");
            }
            result.Add(key);
        }
        if (result.Count == 0)
        {
            throw new JsonException(
                "Remote JWKS contains no supported signing keys.");
        }
        return result;
    }

    private static bool ContainsPrivateMaterial(JsonElement key) =>
        new[] { "d", "p", "q", "dp", "dq", "qi", "oth", "k" }
            .Any(name => key.TryGetProperty(name, out _));

    private static IReadOnlyList<SecurityKey> SelectKeys(
        IReadOnlyList<Microsoft.IdentityModel.Tokens.JsonWebKey>? keys,
        string? kid)
    {
        if (keys is null || keys.Count == 0) return [];
        if (string.IsNullOrWhiteSpace(kid))
        {
            return keys.Count == 1 ? [keys[0]] : [];
        }
        return keys
            .Where(key => string.Equals(
                key.KeyId,
                kid,
                StringComparison.Ordinal))
            .Cast<SecurityKey>()
            .ToArray();
    }

    private void AddBounded(string key, CacheEntry entry)
    {
        var maximum = Math.Clamp(
            _options.RemoteJwksMaxCacheEntries,
            1,
            4096);
        while (_cache.Count >= maximum && !_cache.ContainsKey(key))
        {
            var oldest = _cache.OrderBy(item => item.Value.RefreshedAtUtc)
                .FirstOrDefault();
            if (oldest.Key is null || !_cache.TryRemove(oldest.Key, out _))
            {
                break;
            }
        }
        _cache[key] = entry;
    }

    private sealed record CacheEntry(
        IReadOnlyList<Microsoft.IdentityModel.Tokens.JsonWebKey> Keys,
        DateTimeOffset FreshUntilUtc,
        DateTimeOffset StaleUntilUtc,
        DateTimeOffset RefreshedAtUtc);
}
