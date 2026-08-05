using System.Security.Cryptography;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.IdentityModel.Tokens;

namespace Sufficit.Identity.STS.Dpop;

/// <summary>
/// <see cref="IDistributedCache"/>-backed DPoP nonce store (RFC 9449 §8).
/// Survives process restarts and is visible to every replica when the cache is
/// shared (Redis, SQL Server). The default <c>AddDistributedMemoryCache</c>
/// provides a single-node fallback that is still swappable.
/// </summary>
internal sealed class DistributedDpopNonceStore : IDpopNonceStore
{
    private const string NonceKey = "dpop:nonce:current";

    private readonly Microsoft.Extensions.Caching.Distributed.IDistributedCache _cache;
    private readonly TimeProvider _timeProvider;
    private readonly TimeSpan _ttl;

    public DistributedDpopNonceStore(
        Microsoft.Extensions.Caching.Distributed.IDistributedCache cache,
        TimeSpan? ttl = null,
        TimeProvider? timeProvider = null)
    {
        _cache = cache;
        _ttl = ttl ?? TimeSpan.FromSeconds(60);
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    public string? Current()
    {
        var value = _cache.GetString(FormatKey());
        if (string.IsNullOrEmpty(value)) return null;

        var parts = value.Split('|');
        if (parts.Length != 2) return null;

        if (!DateTimeOffset.TryParse(parts[1], out var expiresAt) ||
            expiresAt < _timeProvider.GetUtcNow())
        {
            return null;
        }

        return parts[0];
    }

    public string Issue()
    {
        var bytes = RandomNumberGenerator.GetBytes(24);
        var nonce = Base64UrlEncoder.Encode(bytes);
        var expiresAt = _timeProvider.GetUtcNow() + _ttl;
        // Store as nonce|expiry so Current() can check TTL without a second key.
        _cache.SetString(FormatKey(), $"{nonce}|{expiresAt:O}",
            new DistributedCacheEntryOptions
            {
                AbsoluteExpirationRelativeToNow = _ttl,
            });
        return nonce;
    }

    public bool IsValid(string? nonce)
    {
        if (string.IsNullOrEmpty(nonce)) return false;
        return string.Equals(nonce, Current(), StringComparison.Ordinal);
    }

    /// <summary>
    /// The cache key is constant (<see cref="NonceKey"/>) so every replica
    /// shares the same nonce. This is the per-AS model described in the
    /// interface remarks.
    /// </summary>
    private static string FormatKey() => NonceKey;
}
