using System.Security.Cryptography;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.IdentityModel.Tokens;
using Sufficit.Identity.Vault;

namespace Sufficit.Identity.STS.Dpop;

/// <summary>
/// <see cref="IDistributedCache"/>-backed DPoP nonce store (RFC 9449 §8).
/// Survives process restarts and is visible to every replica when the cache is
/// shared (Redis, SQL Server). The default <c>AddDistributedMemoryCache</c>
/// provides a single-node fallback that is still swappable.
/// </summary>
internal sealed class DistributedDpopNonceStore : IDpopNonceStore
{
    private const string NonceKeyPrefix = "dpop:nonce:v2:";
    private const string VaultKeyName = "dpop-nonce";

    private readonly Microsoft.Extensions.Caching.Distributed.IDistributedCache _cache;
    private readonly IKeyVault? _keyVault;
    private readonly TimeProvider _timeProvider;
    private readonly TimeSpan _ttl;

    public DistributedDpopNonceStore(
        Microsoft.Extensions.Caching.Distributed.IDistributedCache cache,
        TimeSpan? ttl = null,
        TimeProvider? timeProvider = null,
        IKeyVault? keyVault = null)
    {
        _cache = cache;
        _ttl = ttl ?? TimeSpan.FromSeconds(60);
        _timeProvider = timeProvider ?? TimeProvider.System;
        _keyVault = keyVault;
    }

    private string? Current(string partition)
    {
        var cacheKey = FormatKey(partition);
        var value = _cache.GetString(cacheKey);
        if (string.IsNullOrEmpty(value)) return null;

        var parts = DecryptValue(value, partition).Split('|');
        if (parts.Length != 2) return null;

        if (!DateTimeOffset.TryParse(parts[1], out var expiresAt) ||
            expiresAt < _timeProvider.GetUtcNow())
        {
            return null;
        }

        return parts[0];
    }

    public string Issue(string partition)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(partition);
        var bytes = RandomNumberGenerator.GetBytes(24);
        var nonce = Base64UrlEncoder.Encode(bytes);
        var expiresAt = _timeProvider.GetUtcNow() + _ttl;
        // Store as nonce|expiry so Current() can check TTL without a second key.
        var payload = $"{nonce}|{expiresAt:O}";
        _cache.SetString(FormatKey(partition), EncryptValue(payload, partition),
            new DistributedCacheEntryOptions
            {
                AbsoluteExpirationRelativeToNow = _ttl,
            });
        return nonce;
    }

    public bool IsValid(string? nonce, string partition)
    {
        if (string.IsNullOrEmpty(nonce)) return false;
        return string.Equals(nonce, Current(partition), StringComparison.Ordinal);
    }

    /// <summary>
    /// The partition is hashed before it reaches the cache key to avoid key
    /// injection and disclosure of client identifiers/proof thumbprints.
    /// </summary>
    private static string FormatKey(string partition) =>
        NonceKeyPrefix + Convert.ToHexStringLower(SHA256.HashData(
            System.Text.Encoding.UTF8.GetBytes(partition)));

    // Confidentiality is shared with the database store through
    // DpopNonceProtection so the two backends cannot drift into different
    // encodings of the same value.
    private string EncryptValue(string payload, string partition) =>
        DpopNonceProtection.Encrypt(_keyVault, payload, partition);

    private string DecryptValue(string value, string partition) =>
        DpopNonceProtection.Decrypt(_keyVault, value, partition);
}
