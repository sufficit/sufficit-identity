using System.Collections.Concurrent;
using System.Data;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.Vault.Crypto;

namespace Sufficit.Identity.Vault;

internal sealed partial class KeyVault
{
    private static void EnsureMatchingOperation(
        VaultSigningKeyLifecycleOperation operation,
        string action,
        string keyName)
    {
        if (!string.Equals(operation.Action, action, StringComparison.Ordinal)
            || !string.Equals(operation.KeyName, keyName, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                $"Vault lifecycle operation id '{operation.OperationId}' was already used for a different operation.");
        }
    }

    private static void EnsureMatchingKeyVersion(
        VaultSigningKeyLifecycleOperation operation,
        int keyVersion)
    {
        if (operation.KeyVersion != keyVersion)
        {
            throw new InvalidOperationException(
                $"Vault lifecycle operation id '{operation.OperationId}' was already used for key version {operation.KeyVersion}.");
        }
    }

    private static void ValidateLifecycleArguments(
        string keyName,
        string operationId,
        string? reason)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(keyName);
        ArgumentException.ThrowIfNullOrWhiteSpace(operationId);
        if (keyName.Length > IdentityDatabaseSchema.VaultKeyNameLength)
        {
            throw new ArgumentException("Vault key name is too long.", nameof(keyName));
        }
        if (operationId.Length > IdentityDatabaseSchema.VaultLifecycleOperationIdLength)
        {
            throw new ArgumentException(
                "Vault lifecycle operation id is too long.",
                nameof(operationId));
        }
        if (reason?.Length > IdentityDatabaseSchema.VaultLifecycleReasonLength)
        {
            throw new ArgumentException(
                "Vault lifecycle reason is too long.",
                nameof(reason));
        }
    }

    private static string CreateRetirementOperationId(
        string keyName,
        int keyVersion)
    {
        var nameHash = SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(keyName));
        return $"retire:{WebEncoders.Base64UrlEncode(nameHash)}:{keyVersion}";
    }

    private void AddInitializationJournal(AppDbContext db, string keyName)
    {
        var nameHash = SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(keyName));
        db.VaultSigningKeyLifecycleOperations.Add(
            new VaultSigningKeyLifecycleOperation
            {
                OperationId = $"initialize:{WebEncoders.Base64UrlEncode(nameHash)}",
                KeyName = keyName,
                KeyVersion = 1,
                Action = "initialize",
                OccurredAtUtc = _timeProvider.GetUtcNow().UtcDateTime,
            });
    }

    /// <summary>
    /// Acquires the per-key-name distributed operation lease
    /// (vaultsigningkeylocks). Used by the signing-key lifecycle AND, since
    /// F-7 (eval 2026-08-14), by symmetric DEK first-use creation and
    /// rotation: concurrent replicas racing maxVersion+1 would otherwise
    /// collide on the (KeyName, KeyVersion) unique index with an opaque
    /// DbUpdateException.
    /// </summary>
    private async Task<KeyOperationLease> AcquireKeyOperationLeaseAsync(
        string keyName,
        CancellationToken cancellationToken)
    {
        var ownerId = Guid.NewGuid().ToString("N");
        var now = _timeProvider.GetUtcNow().UtcDateTime;
        var expiresAt = now.AddSeconds(_options.SigningKeyLockSeconds);
        await using (var insertDb = await _dbFactory.CreateDbContextAsync(
            cancellationToken))
        {
            insertDb.VaultSigningKeyLocks.Add(new VaultSigningKeyLock
            {
                KeyName = keyName,
                OwnerId = ownerId,
                ExpiresAtUtc = expiresAt,
            });
            try
            {
                await insertDb.SaveChangesAsync(cancellationToken);
                return new KeyOperationLease(this, keyName, ownerId);
            }
            catch (DbUpdateException)
            {
                // Another replica owns the row or an abandoned lease is
                // waiting to be recovered below.
            }
        }

        await using var updateDb = await _dbFactory.CreateDbContextAsync(
            cancellationToken);
        var recovered = await updateDb.VaultSigningKeyLocks
            .Where(item => item.KeyName == keyName
                && item.ExpiresAtUtc <= now)
            .ExecuteUpdateAsync(update => update
                .SetProperty(item => item.OwnerId, ownerId)
                .SetProperty(item => item.ExpiresAtUtc, expiresAt),
                cancellationToken);
        if (recovered != 1)
        {
            throw new KeyOperationLeaseConflictException(keyName);
        }
        return new KeyOperationLease(this, keyName, ownerId);
    }

    private async ValueTask ReleaseKeyOperationLeaseAsync(
        string keyName,
        string ownerId)
    {
        await using var db = await _dbFactory.CreateDbContextAsync();
        await db.VaultSigningKeyLocks
            .Where(item => item.KeyName == keyName && item.OwnerId == ownerId)
            .ExecuteDeleteAsync();
    }
}
