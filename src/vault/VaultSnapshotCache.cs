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
public sealed class VaultSnapshotCache
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

    /// <summary>
    /// Refreshes already-used entries. This is intentionally bounded to one
    /// pass at a time so a busy process cannot create a database query storm.
    /// </summary>
    internal async Task RefreshLoadedAsync(CancellationToken cancellationToken)
    {
        if (!_options.Enabled || !await _refreshGate.WaitAsync(0, cancellationToken))
        {
            return;
        }

        try
        {
            foreach (var keyName in _signing.Keys.Take(_options.MaxEntries))
            {
                cancellationToken.ThrowIfCancellationRequested();
                var loaded = await LoadSigningKeysAsync(keyName, cancellationToken);
                SetLocal(_signing, keyName, new CacheEntry<IReadOnlyList<VaultSigningKey>>(
                    loaded, DateTimeOffset.UtcNow));
                await TryWriteDistributedAsync(
                    SigningCacheKey(keyName),
                    new SigningEnvelope(DateTimeOffset.UtcNow, loaded),
                    cancellationToken);
            }

            foreach (var key in _signingMaterials.Keys.Take(_options.MaxEntries))
            {
                cancellationToken.ThrowIfCancellationRequested();
                var loaded = await LoadSigningKeyMaterialAsync(
                    key.KeyName,
                    key.KeyVersion,
                    cancellationToken);
                SetLocal(_signingMaterials, key, new CacheEntry<byte[]?>(
                    loaded, DateTimeOffset.UtcNow));
                await TryWriteDistributedAsync(
                    SigningMaterialCacheKey(key),
                    new SigningMaterialEnvelope(DateTimeOffset.UtcNow, loaded),
                    cancellationToken);
            }

            foreach (var keyName in _symmetric.Keys.Take(_options.MaxEntries))
            {
                cancellationToken.ThrowIfCancellationRequested();
                var loaded = await LoadLatestSymmetricKeyAsync(keyName, cancellationToken);
                SetLocal(_symmetric, keyName, new CacheEntry<SymmetricKeySnapshot?>(
                    loaded, DateTimeOffset.UtcNow));
                await TryWriteDistributedAsync(
                    SymmetricCacheKey(keyName),
                    new SymmetricEnvelope(DateTimeOffset.UtcNow, loaded),
                    cancellationToken);
            }

            foreach (var key in _secrets.Keys.Take(_options.MaxEntries))
            {
                cancellationToken.ThrowIfCancellationRequested();
                var loaded = await LoadSecretAsync(key, cancellationToken);
                SetLocal(_secrets, key, new CacheEntry<VaultSecretSnapshotEntry?>(
                    loaded, DateTimeOffset.UtcNow));
                await TryWriteDistributedAsync(
                    SecretCacheKey(key),
                    new SecretEnvelope(DateTimeOffset.UtcNow, loaded),
                    cancellationToken);
            }

            foreach (var cacheKey in _metadata.Keys.Take(_options.MaxEntries))
            {
                cancellationToken.ThrowIfCancellationRequested();
                var separator = cacheKey.IndexOf('|');
                if (separator < 0) continue;
                var contextId = cacheKey[..separator];
                var namespaceKey = cacheKey[(separator + 1)..];
                var namespaces = namespaceKey == "*"
                    ? null
                    : namespaceKey.Split(',', StringSplitOptions.RemoveEmptyEntries)
                        .ToHashSet(StringComparer.Ordinal);
                var loaded = await LoadMetadataAsync(contextId, namespaces, cancellationToken);
                SetLocal(_metadata, cacheKey, new CacheEntry<IReadOnlyList<VaultSecretMetadata>>(
                    loaded, DateTimeOffset.UtcNow));
                await TryWriteDistributedAsync(
                    MetadataCacheKey(cacheKey),
                    new MetadataEnvelope(DateTimeOffset.UtcNow, loaded),
                    cancellationToken);
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception)
        {
            _logger.LogWarning(exception, "Vault snapshot refresh failed; request-path entries remain bounded by their freshness window.");
        }
        finally
        {
            _refreshGate.Release();
        }
    }

    private async Task<IReadOnlyList<VaultSigningKey>> LoadSigningKeysAsync(
        string keyName,
        CancellationToken cancellationToken)
    {
        await using var database = await _databaseFactory.CreateDbContextAsync(cancellationToken);
        var now = DateTime.UtcNow;
        return await database.VaultKeys.AsNoTracking()
            .Where(key => key.KeyName == keyName
                && key.Purpose == "signing"
                && (key.SigningState == VaultSigningKeyState.Active
                    || (key.SigningState == VaultSigningKeyState.Retiring
                        && key.RetireAfterUtc > now)))
            .OrderBy(key => key.SigningState == VaultSigningKeyState.Active ? 0 : 1)
            .ThenByDescending(key => key.KeyVersion)
            .Where(key => key.PublicJwk != null)
            .Select(key => new VaultSigningKey(
                key.KeyName,
                key.KeyVersion,
                KeyVault.GetSigningKeyId(key.KeyName, key.KeyVersion),
                key.PublicJwk!,
                key.SigningState == VaultSigningKeyState.Retiring
                    ? VaultSigningKeyStatus.Retiring
                    : VaultSigningKeyStatus.Active,
                key.RetireAfterUtc))
            .ToArrayAsync(cancellationToken);
    }

    private async Task<SymmetricKeySnapshot> LoadLatestSymmetricKeyAsync(
        string keyName,
        CancellationToken cancellationToken)
    {
        await using var database = await _databaseFactory.CreateDbContextAsync(cancellationToken);
        var row = await database.VaultKeys.AsNoTracking()
            .Where(key => key.KeyName == keyName
                && key.Purpose == "symmetric"
                && key.RetiredAtUtc == null)
            .OrderByDescending(key => key.KeyVersion)
            .FirstOrDefaultAsync(cancellationToken)
            ?? throw new CryptographicException(
                $"Vault key '{keyName}' has no active symmetric version.");
        return new SymmetricKeySnapshot(row.KeyVersion, row.WrappedKey);
    }

    private async Task<byte[]?> LoadSigningKeyMaterialAsync(
        string keyName,
        int keyVersion,
        CancellationToken cancellationToken)
    {
        await using var database = await _databaseFactory.CreateDbContextAsync(cancellationToken);
        return await database.VaultKeys.AsNoTracking()
            .Where(key => key.KeyName == keyName
                && key.KeyVersion == keyVersion
                && key.Purpose == "signing"
                && key.SigningState == VaultSigningKeyState.Active)
            .Select(key => key.WrappedKey)
            .SingleOrDefaultAsync(cancellationToken);
    }

    private async Task<VaultSecretSnapshotEntry?> LoadSecretAsync(
        SecretKey cacheKey,
        CancellationToken cancellationToken)
    {
        await using var database = await _databaseFactory.CreateDbContextAsync(cancellationToken);
        var row = await database.VaultSecrets.AsNoTracking()
            .SingleOrDefaultAsync(secret => secret.Name == cacheKey.Name
                && secret.ContextId == cacheKey.ContextId,
                cancellationToken);
        return row is null ? null : ToEntry(row);
    }

    private async Task<IReadOnlyList<VaultSecretMetadata>> LoadMetadataAsync(
        string contextId,
        IReadOnlySet<string>? namespaces,
        CancellationToken cancellationToken)
    {
        await using var database = await _databaseFactory.CreateDbContextAsync(cancellationToken);
        var query = database.VaultSecrets.AsNoTracking()
            .Where(secret => secret.ContextId == contextId);
        if (namespaces is not null)
        {
            query = query.Where(secret => namespaces.Contains(secret.Namespace));
        }

        return await query.OrderBy(secret => secret.Name)
            .Select(secret => new VaultSecretMetadata(
                secret.Name,
                secret.Namespace,
                secret.ContextId,
                secret.OwnerSubject,
                secret.UpdatedAtUtc,
                secret.UpdatedBy,
                true,
                secret.ExpiresAtUtc))
            .ToArrayAsync(cancellationToken);
    }

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
            secret.ContextId,
            secret.OwnerSubject,
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
