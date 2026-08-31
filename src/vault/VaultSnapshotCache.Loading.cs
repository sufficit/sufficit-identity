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
}
