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

/// <summary>
/// Read-through snapshot for the Vault tables.
///
/// The request path reads immutable encrypted rows/public JWKs from process
/// memory. On a miss it first tries the shared distributed cache and only then
/// queries MariaDB. Mutations explicitly invalidate both layers. A bounded
/// background refresher keeps hot entries warm while preserving a hard
/// freshness limit when the database is unavailable.
/// </summary>
public sealed partial class VaultSnapshotCache
{
    private const string CachePrefix = "sufficit:identity:vault:snapshot:v1:";
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    private readonly IDbContextFactory<AppDbContext> _databaseFactory;
    private readonly IDistributedCache? _distributedCache;
    private readonly IVaultSnapshotInvalidationBus? _invalidationBus;
    private readonly VaultSnapshotOptions _options;
    private readonly ILogger<VaultSnapshotCache> _logger;
    private readonly ConcurrentDictionary<string, CacheEntry<IReadOnlyList<VaultSigningKey>>> _signing = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<SigningMaterialKey, CacheEntry<byte[]?>> _signingMaterials = new();
    private readonly ConcurrentDictionary<string, CacheEntry<SymmetricKeySnapshot?>> _symmetric = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<SecretKey, CacheEntry<VaultSecretSnapshotEntry?>> _secrets = new();
    private readonly ConcurrentDictionary<string, CacheEntry<IReadOnlyList<VaultSecretMetadata>>> _metadata = new(StringComparer.Ordinal);
    private readonly SemaphoreSlim _refreshGate = new(1, 1);

    public VaultSnapshotCache(
        IDbContextFactory<AppDbContext> databaseFactory,
        VaultSnapshotOptions options,
        ILogger<VaultSnapshotCache> logger,
        IDistributedCache? distributedCache = null)
        : this(databaseFactory, options, logger, distributedCache, invalidationBus: null)
    {
    }

    internal VaultSnapshotCache(
        IDbContextFactory<AppDbContext> databaseFactory,
        VaultSnapshotOptions options,
        ILogger<VaultSnapshotCache> logger,
        IDistributedCache? distributedCache,
        IVaultSnapshotInvalidationBus? invalidationBus)
    {
        _databaseFactory = databaseFactory;
        _options = options;
        _logger = logger;
        _distributedCache = distributedCache;
        _invalidationBus = invalidationBus;
    }

    internal async Task<IReadOnlyList<VaultSigningKey>> GetSigningKeysAsync(
        string keyName,
        Func<CancellationToken, Task<IReadOnlyList<VaultSigningKey>>> loader,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(keyName);
        ArgumentNullException.ThrowIfNull(loader);

        if (!_options.Enabled)
        {
            return await loader(cancellationToken);
        }

        if (TryGetFresh(_signing, keyName, out var local))
        {
            return local.Value;
        }

        var distributed = await TryReadDistributedAsync<SigningEnvelope>(
            SigningCacheKey(keyName), cancellationToken);
        if (distributed is not null && IsFresh(distributed.CapturedAtUtc))
        {
            var value = distributed.Keys ?? [];
            SetLocal(_signing, keyName, new CacheEntry<IReadOnlyList<VaultSigningKey>>(
                value, distributed.CapturedAtUtc));
            return value;
        }

        var loaded = await loader(cancellationToken);
        SetLocal(_signing, keyName, new CacheEntry<IReadOnlyList<VaultSigningKey>>(
            loaded, DateTimeOffset.UtcNow));
        await TryWriteDistributedAsync(
            SigningCacheKey(keyName),
            new SigningEnvelope(DateTimeOffset.UtcNow, loaded),
            cancellationToken);
        return loaded;
    }

    internal async Task<SymmetricKeySnapshot> GetLatestSymmetricKeyAsync(
        string keyName,
        Func<CancellationToken, Task<SymmetricKeySnapshot>> loader,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(keyName);
        ArgumentNullException.ThrowIfNull(loader);

        if (!_options.Enabled)
        {
            return await loader(cancellationToken);
        }

        if (TryGetFresh(_symmetric, keyName, out var local)
            && local.Value is not null)
        {
            return local.Value;
        }

        var distributed = await TryReadDistributedAsync<SymmetricEnvelope>(
            SymmetricCacheKey(keyName), cancellationToken);
        if (distributed is not null
            && IsFresh(distributed.CapturedAtUtc)
            && distributed.Key is not null)
        {
            SetLocal(_symmetric, keyName, new CacheEntry<SymmetricKeySnapshot?>(
                distributed.Key, distributed.CapturedAtUtc));
            return distributed.Key;
        }

        var loaded = await loader(cancellationToken);
        SetLocal(_symmetric, keyName, new CacheEntry<SymmetricKeySnapshot?>(
            loaded, DateTimeOffset.UtcNow));
        await TryWriteDistributedAsync(
            SymmetricCacheKey(keyName),
            new SymmetricEnvelope(DateTimeOffset.UtcNow, loaded),
            cancellationToken);
        return loaded;
    }

    internal async Task<byte[]?> GetSigningKeyMaterialAsync(
        string keyName,
        int keyVersion,
        Func<CancellationToken, Task<byte[]?>> loader,
        CancellationToken cancellationToken)
    {
        var cacheKey = new SigningMaterialKey(keyName, keyVersion);
        if (!_options.Enabled)
        {
            return await loader(cancellationToken);
        }

        if (TryGetFresh(_signingMaterials, cacheKey, out var local))
        {
            return local.Value;
        }

        var distributed = await TryReadDistributedAsync<SigningMaterialEnvelope>(
            SigningMaterialCacheKey(cacheKey), cancellationToken);
        if (distributed is not null && IsFresh(distributed.CapturedAtUtc))
        {
            var value = distributed.WrappedKey?.ToArray();
            SetLocal(_signingMaterials, cacheKey, new CacheEntry<byte[]?>(
                value, distributed.CapturedAtUtc));
            return value;
        }

        var loaded = await loader(cancellationToken);
        var snapshot = loaded?.ToArray();
        SetLocal(_signingMaterials, cacheKey, new CacheEntry<byte[]?>(
            snapshot, DateTimeOffset.UtcNow));
        await TryWriteDistributedAsync(
            SigningMaterialCacheKey(cacheKey),
            new SigningMaterialEnvelope(DateTimeOffset.UtcNow, snapshot),
            cancellationToken);
        return snapshot;
    }

    internal async Task<VaultSecretSnapshotEntry?> GetSecretAsync(
        string name,
        string contextId,
        CancellationToken cancellationToken)
    {
        var cacheKey = new SecretKey(name, contextId);
        if (!_options.Enabled)
        {
            return await LoadSecretAsync(cacheKey, cancellationToken);
        }

        if (TryGetFresh(_secrets, cacheKey, out var local))
        {
            return local.Value;
        }

        var distributed = await TryReadDistributedAsync<SecretEnvelope>(
            SecretCacheKey(cacheKey), cancellationToken);
        if (distributed is not null && IsFresh(distributed.CapturedAtUtc))
        {
            SetLocal(_secrets, cacheKey, new CacheEntry<VaultSecretSnapshotEntry?>(
                distributed.Entry, distributed.CapturedAtUtc));
            return distributed.Entry;
        }

        var loaded = await LoadSecretAsync(cacheKey, cancellationToken);
        SetLocal(_secrets, cacheKey, new CacheEntry<VaultSecretSnapshotEntry?>(
            loaded, DateTimeOffset.UtcNow));
        await TryWriteDistributedAsync(
            SecretCacheKey(cacheKey),
            new SecretEnvelope(DateTimeOffset.UtcNow, loaded),
            cancellationToken);
        return loaded;
    }

    internal async Task<IReadOnlyList<VaultSecretMetadata>> ListSecretsAsync(
        string contextId,
        IReadOnlySet<string>? namespaces,
        CancellationToken cancellationToken)
    {
        var namespaceKey = namespaces is null
            ? "*"
            : string.Join(',', namespaces.Order(StringComparer.Ordinal));
        var cacheKey = $"{contextId}|{namespaceKey}";
        if (!_options.Enabled)
        {
            return await LoadMetadataAsync(contextId, namespaces, cancellationToken);
        }

        if (TryGetFresh(_metadata, cacheKey, out var local))
        {
            return local.Value;
        }

        var distributed = await TryReadDistributedAsync<MetadataEnvelope>(
            MetadataCacheKey(cacheKey), cancellationToken);
        if (distributed is not null && IsFresh(distributed.CapturedAtUtc))
        {
            var value = distributed.Items ?? [];
            SetLocal(_metadata, cacheKey, new CacheEntry<IReadOnlyList<VaultSecretMetadata>>(
                value, distributed.CapturedAtUtc));
            return value;
        }

        var loaded = await LoadMetadataAsync(contextId, namespaces, cancellationToken);
        SetLocal(_metadata, cacheKey, new CacheEntry<IReadOnlyList<VaultSecretMetadata>>(
            loaded, DateTimeOffset.UtcNow));
        await TryWriteDistributedAsync(
            MetadataCacheKey(cacheKey),
            new MetadataEnvelope(DateTimeOffset.UtcNow, loaded),
            cancellationToken);
        return loaded;
    }

    internal async Task InvalidateSigningKeysAsync(
        string keyName,
        CancellationToken cancellationToken = default)
    {
        _signing.TryRemove(keyName, out _);
        foreach (var key in _signingMaterials.Keys.Where(
                     key => string.Equals(key.KeyName, keyName, StringComparison.Ordinal)))
        {
            _signingMaterials.TryRemove(key, out _);
        }
        await TryRemoveDistributedAsync(SigningCacheKey(keyName), cancellationToken);
        await PublishInvalidationAsync(
            new VaultSnapshotInvalidation(
                "signing",
                SigningCacheKey(keyName),
                Hash(keyName)),
            cancellationToken);
    }

    internal async Task InvalidateSymmetricKeyAsync(
        string keyName,
        CancellationToken cancellationToken = default)
    {
        _symmetric.TryRemove(keyName, out _);
        await TryRemoveDistributedAsync(SymmetricCacheKey(keyName), cancellationToken);
        await PublishInvalidationAsync(
            new VaultSnapshotInvalidation(
                "symmetric",
                SymmetricCacheKey(keyName),
                null),
            cancellationToken);
    }

    internal async Task InvalidateSecretAsync(
        string name,
        string contextId,
        CancellationToken cancellationToken = default)
    {
        var key = new SecretKey(name, contextId);
        _secrets.TryRemove(key, out _);
        InvalidateMetadataForContext(contextId);
        await TryRemoveDistributedAsync(SecretCacheKey(key), cancellationToken);
        await PublishInvalidationAsync(
            new VaultSnapshotInvalidation(
                "secret",
                SecretCacheKey(key),
                Hash(contextId)),
            cancellationToken);
        // IDistributedCache intentionally has no key enumeration. Other
        // replicas converge through their bounded metadata TTL.
    }

    internal void Flush()
    {
        _signing.Clear();
        _signingMaterials.Clear();
        _symmetric.Clear();
        _secrets.Clear();
        _metadata.Clear();
    }

    /// <summary>
    /// Applies a mutation made by another replica. It only touches local
    /// memory; the publishing replica already removed the distributed entry.
    /// </summary>
    internal void ApplyRemoteInvalidation(VaultSnapshotInvalidation invalidation)
    {
        ArgumentNullException.ThrowIfNull(invalidation);
        switch (invalidation.Kind)
        {
            case "signing":
                foreach (var keyName in _signing.Keys.Where(key =>
                    string.Equals(SigningCacheKey(key), invalidation.CacheKey, StringComparison.Ordinal)))
                {
                    _signing.TryRemove(keyName, out _);
                }
                foreach (var key in _signingMaterials.Keys.Where(key =>
                    invalidation.ScopeHash is not null
                    && string.Equals(Hash(key.KeyName), invalidation.ScopeHash, StringComparison.Ordinal)))
                {
                    _signingMaterials.TryRemove(key, out _);
                }
                break;
            case "symmetric":
                foreach (var keyName in _symmetric.Keys.Where(key =>
                    string.Equals(SymmetricCacheKey(key), invalidation.CacheKey, StringComparison.Ordinal)))
                {
                    _symmetric.TryRemove(keyName, out _);
                }
                break;
            case "secret":
                foreach (var key in _secrets.Keys.Where(key =>
                    string.Equals(SecretCacheKey(key), invalidation.CacheKey, StringComparison.Ordinal)))
                {
                    _secrets.TryRemove(key, out _);
                }
                if (invalidation.ScopeHash is not null)
                {
                    foreach (var key in _metadata.Keys.Where(key =>
                        key.IndexOf('|') >= 0
                        && string.Equals(Hash(key[..key.IndexOf('|')]), invalidation.ScopeHash, StringComparison.Ordinal)))
                    {
                        _metadata.TryRemove(key, out _);
                    }
                }
                break;
        }
    }

    private readonly record struct SecretKey(string Name, string ContextId);
    private readonly record struct SigningMaterialKey(string KeyName, int KeyVersion);
    private sealed record CacheEntry<T>(T Value, DateTimeOffset CapturedAtUtc);
    private sealed record SigningEnvelope(DateTimeOffset CapturedAtUtc, IReadOnlyList<VaultSigningKey>? Keys);
    private sealed record SymmetricEnvelope(DateTimeOffset CapturedAtUtc, SymmetricKeySnapshot? Key);
    private sealed record SigningMaterialEnvelope(DateTimeOffset CapturedAtUtc, byte[]? WrappedKey);
    private sealed record SecretEnvelope(DateTimeOffset CapturedAtUtc, VaultSecretSnapshotEntry? Entry);
    private sealed record MetadataEnvelope(DateTimeOffset CapturedAtUtc, IReadOnlyList<VaultSecretMetadata>? Items);
}

internal sealed record SymmetricKeySnapshot(int Version, byte[] WrappedKey);

/// <summary>Encrypted row snapshot; it never contains a decrypted secret.</summary>
internal sealed record VaultSecretSnapshotEntry(
    string Name,
    string Namespace,
    string ContextId,
    string OwnerSubject,
    string Ciphertext,
    string? AadJson,
    DateTime UpdatedAtUtc,
    string UpdatedBy,
    DateTime? ExpiresAtUtc = null);

internal sealed class VaultSnapshotRefreshService(
    VaultSnapshotCache snapshots,
    VaultSnapshotOptions options,
    ILogger<VaultSnapshotRefreshService> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(options.RefreshIntervalSeconds));
        while (await timer.WaitForNextTickAsync(stoppingToken))
        {
            try
            {
                await snapshots.RefreshLoadedAsync(stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                return;
            }
            catch (Exception exception)
            {
                logger.LogWarning(exception, "Vault snapshot background refresh failed.");
            }
        }
    }
}
