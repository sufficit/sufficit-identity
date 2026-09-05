using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Core.Entities;

namespace Sufficit.Identity.Vault;

public sealed partial class VaultSnapshotCache
{
    private bool IsFresh(DateTimeOffset capturedAtUtc) =>
        DateTimeOffset.UtcNow - capturedAtUtc
            <= TimeSpan.FromSeconds(_options.DistributedLifetimeSeconds);

    private bool TryGetFresh<TKey, TValue>(
        ConcurrentDictionary<TKey, CacheEntry<TValue>> cache,
        TKey key,
        out CacheEntry<TValue> value)
        where TKey : notnull
    {
        if (cache.TryGetValue(key, out value!)
            && DateTimeOffset.UtcNow - value.CapturedAtUtc
                <= TimeSpan.FromSeconds(_options.LocalLifetimeSeconds))
        {
            return true;
        }

        value = default!;
        return false;
    }

    private void SetLocal<TKey, TValue>(
        ConcurrentDictionary<TKey, CacheEntry<TValue>> cache,
        TKey key,
        CacheEntry<TValue> value)
        where TKey : notnull
    {
        cache[key] = value;
        while (cache.Count > _options.MaxEntries)
        {
            var first = cache.Keys.FirstOrDefault();
            if (first is null || !cache.TryRemove(first, out _)) break;
        }
    }

    private async Task<T?> TryReadDistributedAsync<T>(
        string cacheKey,
        CancellationToken cancellationToken)
    {
        if (_distributedCache is null) return default;
        try
        {
            var raw = await _distributedCache.GetStringAsync(cacheKey, cancellationToken);
            return string.IsNullOrWhiteSpace(raw)
                ? default
                : JsonSerializer.Deserialize<T>(raw, JsonOptions);
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            _logger.LogDebug(exception, "Vault snapshot distributed read failed for {CacheKey}; falling back to memory/database.", cacheKey);
            return default;
        }
    }

    private async Task TryWriteDistributedAsync<T>(
        string cacheKey,
        T value,
        CancellationToken cancellationToken)
    {
        if (_distributedCache is null) return;
        try
        {
            await _distributedCache.SetStringAsync(
                cacheKey,
                JsonSerializer.Serialize(value, JsonOptions),
                new DistributedCacheEntryOptions
                {
                    AbsoluteExpirationRelativeToNow = TimeSpan.FromSeconds(_options.DistributedLifetimeSeconds),
                },
                cancellationToken);
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            _logger.LogDebug(exception, "Vault snapshot distributed write failed for {CacheKey}; local snapshot remains active.", cacheKey);
        }
    }

    private async Task TryRemoveDistributedAsync(
        string cacheKey,
        CancellationToken cancellationToken)
    {
        if (_distributedCache is null) return;
        try
        {
            await _distributedCache.RemoveAsync(cacheKey, cancellationToken);
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            _logger.LogDebug(exception, "Vault snapshot distributed invalidation failed for {CacheKey}; TTL remains the safety boundary.", cacheKey);
        }
    }

    private void InvalidateMetadataForContext(string contextId)
    {
        foreach (var key in _metadata.Keys.Where(key => key.StartsWith(contextId + '|', StringComparison.Ordinal)))
        {
            _metadata.TryRemove(key, out _);
        }
    }

    private async Task PublishInvalidationAsync(
        VaultSnapshotInvalidation invalidation,
        CancellationToken cancellationToken)
    {
        if (_invalidationBus is not null)
        {
            await _invalidationBus.PublishAsync(invalidation, cancellationToken);
        }
    }

    private static VaultSecretSnapshotEntry ToEntry(VaultSecret secret) =>
        new(
            secret.Name,
            secret.Namespace,
            new VaultSecretContext(secret.Type, secret.ContextId).ToString(),
            VaultBackedSecretStore.ToSubjectString(secret.OwnerSubject),
            secret.Ciphertext,
            secret.AadJson,
            secret.UpdatedAtUtc,
            secret.UpdatedBy,
            secret.ExpiresAtUtc);

    private static string SigningCacheKey(string keyName) =>
        CachePrefix + "signing:" + Hash(keyName);

    private static string SymmetricCacheKey(string keyName) =>
        CachePrefix + "symmetric:" + Hash(keyName);

    private static string SigningMaterialCacheKey(SigningMaterialKey key) =>
        CachePrefix + "signing-material:" + Hash(
            key.KeyName + "\n" + key.KeyVersion.ToString(
                System.Globalization.CultureInfo.InvariantCulture));

    private static string SecretCacheKey(SecretKey key) =>
        CachePrefix + "secret:" + Hash(key.ContextId + "\n" + key.Name);

    private static string MetadataCacheKey(string key) =>
        CachePrefix + "metadata:" + Hash(key);

    private static string Hash(string value) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(value)));
}
