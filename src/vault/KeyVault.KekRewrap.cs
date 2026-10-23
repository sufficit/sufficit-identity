using System.Security.Cryptography;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Sufficit.Identity.Core.Entities;

namespace Sufficit.Identity.Vault;

/// <summary>Outcome of <see cref="IVaultKekRewrap.RewrapAsync"/>. Counts and key ids only.</summary>
public sealed record VaultKekRewrapResult(
    string OperationId,
    bool AlreadyCompleted,
    int Rewrapped,
    int AlreadyActive,
    IReadOnlyList<KeyId> Failed);

/// <summary>
/// Moves every data key the vault holds to the active KEK (plan C1). A KEK
/// rotation adds the new certificate as <see cref="VaultOptions.CertificatePath"/>
/// and keeps the old one in <see cref="VaultOptions.PreviousCertificatePaths"/>;
/// this is the step after which the old one can go.
/// </summary>
public interface IVaultKekRewrap
{
    /// <summary>
    /// Re-wraps, under the active KEK, every <c>vaultkeys</c> row it does not
    /// already protect, one key name at a time under that name's lifecycle
    /// lease, then checks that the active KEK alone unwraps every row.
    /// Idempotent: rows already under the active KEK are skipped, and an
    /// <paramref name="operationId"/> that completed before returns at once.
    /// </summary>
    Task<VaultKekRewrapResult> RewrapAsync(
        string operationId,
        string reason,
        CancellationToken cancellationToken = default);
}

internal sealed partial class KeyVault : IVaultKekRewrap
{
    internal const string KekRewrapAction = "kek_rewrap";
    private const int KekRewrapLeaseAttempts = 10;
    private static readonly TimeSpan KekRewrapLeaseRetryDelay = TimeSpan.FromSeconds(1);

    public async Task<VaultKekRewrapResult> RewrapAsync(
        string operationId,
        string reason,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(operationId);
        ArgumentException.ThrowIfNullOrWhiteSpace(reason);
        if (_kek is not IVaultRewrappableKeySource source)
        {
            throw new InvalidOperationException(
                "Re-wrapping needs Sufficit:Vault:KeySource=certificate: only the certificate KEK can tell which key protects a wrapped data key.");
        }

        await using (var journal = await _dbFactory.CreateDbContextAsync(cancellationToken))
        {
            var done = await journal.VaultSigningKeyLifecycleOperations.AsNoTracking()
                .SingleOrDefaultAsync(entry => entry.OperationId == operationId, cancellationToken);
            if (done is not null)
            {
                if (done.Action != KekRewrapAction)
                {
                    throw new InvalidOperationException(
                        $"Operation id '{operationId}' already names a '{done.Action}' operation.");
                }

                return new VaultKekRewrapResult(operationId, true, done.KeyVersion, 0, []);
            }
        }

        List<string> keyNames;
        await using (var db = await _dbFactory.CreateDbContextAsync(cancellationToken))
        {
            keyNames = await db.VaultKeys.AsNoTracking()
                .Select(key => key.KeyName).Distinct().OrderBy(name => name)
                .ToListAsync(cancellationToken);
        }

        int rewrapped = 0, alreadyActive = 0;
        var failed = new List<KeyId>();
        foreach (var keyName in keyNames)
        {
            await using var lease = await AcquireRewrapLeaseAsync(keyName, cancellationToken);
            await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);
            var rows = await db.VaultKeys.Where(key => key.KeyName == keyName)
                .ToListAsync(cancellationToken);
            var changed = false;
            foreach (var row in rows)
            {
                if (source.IsWrappedByActiveKey(row.WrappedKey))
                {
                    alreadyActive++;
                    continue;
                }

                byte[] plaintext;
                try
                {
                    plaintext = source.Unwrap(row.WrappedKey);
                }
                catch (CryptographicException)
                {
                    failed.Add(new KeyId(row.KeyName, row.KeyVersion));
                    continue;
                }

                try
                {
                    row.WrappedKey = source.Wrap(plaintext);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(plaintext);
                }

                changed = true;
                rewrapped++;
            }

            if (changed)
            {
                await db.SaveChangesAsync(cancellationToken);
                if (_snapshots is not null)
                {
                    await _snapshots.InvalidateSymmetricKeyAsync(keyName, cancellationToken);
                    await _snapshots.InvalidateSigningKeysAsync(keyName, cancellationToken);
                }
            }
        }

        // The proof the old KEK can go: the active one alone opens every row.
        await using (var db = await _dbFactory.CreateDbContextAsync(cancellationToken))
        {
            var rows = await db.VaultKeys.AsNoTracking()
                .Select(key => new { key.KeyName, key.KeyVersion, key.WrappedKey })
                .ToListAsync(cancellationToken);
            foreach (var row in rows)
            {
                var id = new KeyId(row.KeyName, row.KeyVersion);
                if (!source.IsWrappedByActiveKey(row.WrappedKey) && !failed.Contains(id))
                {
                    failed.Add(id);
                }
            }
        }

        if (failed.Count == 0)
        {
            await using var journal = await _dbFactory.CreateDbContextAsync(cancellationToken);
            journal.VaultSigningKeyLifecycleOperations.Add(new VaultSigningKeyLifecycleOperation
            {
                OperationId = operationId,
                KeyName = "*",
                KeyVersion = rewrapped,
                Action = KekRewrapAction,
                Reason = reason,
                OccurredAtUtc = _timeProvider.GetUtcNow().UtcDateTime,
            });
            await journal.SaveChangesAsync(cancellationToken);
        }

        _logger.LogInformation(
            "Vault KEK re-wrap {OperationId}: {Rewrapped} re-wrapped, {AlreadyActive} already under {KeyIdentifier}, {Failed} failed.",
            operationId, rewrapped, alreadyActive, source.KeyIdentifier, failed.Count);
        return new VaultKekRewrapResult(operationId, false, rewrapped, alreadyActive, failed);
    }

    private async Task<KeyOperationLease> AcquireRewrapLeaseAsync(
        string keyName,
        CancellationToken cancellationToken)
    {
        for (var attempt = 1; ; attempt++)
        {
            try
            {
                return await AcquireKeyOperationLeaseAsync(keyName, cancellationToken);
            }
            catch (KeyOperationLeaseConflictException) when (attempt < KekRewrapLeaseAttempts)
            {
                await Task.Delay(KekRewrapLeaseRetryDelay, _timeProvider, cancellationToken);
            }
        }
    }
}
