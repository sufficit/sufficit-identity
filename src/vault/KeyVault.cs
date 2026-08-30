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

/// <summary>
/// Real <see cref="IKeyVault"/> implementation: envelope encryption with a
/// configured KEK authority wrapping per-name DEKs persisted in
/// <c>vault_keys</c>. Item keys are cached in-memory after unwrap.
/// </summary>
/// <remarks>
/// Singleton — consumes <see cref="IDbContextFactory{AppDbContext}"/> (also
/// singleton) so it is safe from the singleton DPoP/CIBA stores. The in-memory
/// key cache is unbounded (keys are small, count is low); call
/// <see cref="FlushCache"/> to clear it (tests/admin).
/// </remarks>
internal sealed partial class KeyVault : IKeyVault
{
    private readonly IDbContextFactory<AppDbContext> _dbFactory;
    private readonly IVaultKeyEncryptionKeySource _kek;
    private readonly ILogger<KeyVault> _logger;
    private readonly VaultOptions _options;
    private readonly TimeProvider _timeProvider;
    private readonly VaultCryptographyTelemetry _cryptographyTelemetry;
    private readonly VaultSnapshotCache? _snapshots;
    private readonly bool _allowPlaintextReadCompatibility;
    private readonly DateTimeOffset? _plaintextReadCompatibilityExpiresAtUtc;

    // Cache: (keyName, version) → unwrapped item key (256-bit).
    private readonly ConcurrentDictionary<(string Name, int Version), byte[]> _keyCache = new();

    // Cold-start lease contention retry bounds. The winner of a first-use
    // race creates v1 within milliseconds; five 100 ms attempts absorb any
    // realistic replica race without turning a cold encrypt into a failure.
    private const int ColdStartLeaseRetryLimit = 5;
    private static readonly TimeSpan ColdStartLeaseRetryDelay = TimeSpan.FromMilliseconds(100);

    public KeyVault(
        IDbContextFactory<AppDbContext> dbFactory,
        IVaultKeyEncryptionKeySource kek,
        ILogger<KeyVault> logger,
        VaultOptions options,
        TimeProvider? timeProvider = null)
        : this(
            dbFactory,
            kek,
            logger,
            options,
            new VaultCryptographyTelemetry(
                options,
                Microsoft.Extensions.Logging.Abstractions.NullLogger<
                    VaultCryptographyTelemetry>.Instance),
            timeProvider,
            snapshots: null)
    {
    }

    public KeyVault(
        IDbContextFactory<AppDbContext> dbFactory,
        IVaultKeyEncryptionKeySource kek,
        ILogger<KeyVault> logger,
        VaultOptions options,
        VaultCryptographyTelemetry cryptographyTelemetry,
        TimeProvider? timeProvider = null,
        VaultSnapshotCache? snapshots = null,
        bool allowPlaintextReadCompatibility = false,
        DateTimeOffset? plaintextReadCompatibilityExpiresAtUtc = null)
    {
        _dbFactory = dbFactory;
        _kek = kek;
        _logger = logger;
        _options = options;
        _cryptographyTelemetry = cryptographyTelemetry;
        _timeProvider = timeProvider ?? TimeProvider.System;
        _snapshots = snapshots;
        _allowPlaintextReadCompatibility = allowPlaintextReadCompatibility;
        _plaintextReadCompatibilityExpiresAtUtc =
            plaintextReadCompatibilityExpiresAtUtc;
    }

    /// <summary>
    /// Encrypts plaintext under the latest key version for
    /// <paramref name="keyName"/>. Creates the key (and its DEK) on first use.
    /// </summary>
    public async Task<string> EncryptAsync(
        string keyName,
        byte[] plaintext,
        IReadOnlyDictionary<string, string>? additionalAuthenticatedData = null,
        CancellationToken cancellationToken = default)
    {
        var (itemKey, version) = await GetOrCreateLatestKeyAsync(keyName, cancellationToken);

        // The DEK for AAD hashing is the same item key (it is the encryption
        // key for this data).
        var aadHash = SelfDescribingCiphertext.ComputeAadHash(additionalAuthenticatedData, itemKey);
        var aadBytes = SelfDescribingCiphertext.CanonicalizeAad(additionalAuthenticatedData);

        var packed = EnvelopeCrypto.Encrypt(plaintext, itemKey, aadBytes);
        var ciphertext = SelfDescribingCiphertext.Format(keyName, version, packed,
            additionalAuthenticatedData is null || additionalAuthenticatedData.Count == 0 ? null : aadHash);
        _cryptographyTelemetry.RecordEncryption(keyName, version);
        return ciphertext;
    }

    /// <summary>
    /// Decrypts self-describing ciphertext. The embedded key version selects
    /// the right key. Throws on tamper/AAD-mismatch (GCM authentication).
    /// </summary>
    public async Task<ReadOnlyMemory<byte>> DecryptAsync(
        string ciphertext,
        IReadOnlyDictionary<string, string>? additionalAuthenticatedData = null,
        CancellationToken cancellationToken = default)
    {
        if (ciphertext.StartsWith(
                SelfDescribingCiphertext.PassThroughPrefix,
                StringComparison.Ordinal))
        {
            cancellationToken.ThrowIfCancellationRequested();

            // F-2 (eval 2026-08-14): the pt1 pass-through is a compatibility
            // read for values written by the Development-only
            // PassThroughKeyVault. Accepting it unconditionally removes the
            // fail-closed property for tampered rows: an attacker with a
            // database or Redis write could swap a ciphertext for
            // pt1.<base64url> and have the vault resolve attacker-chosen
            // plaintext (e.g. a client-secret reference). Outside Development
            // the marker is only readable through a bounded, attributed
            // Sufficit:Vault:PlaintextReadCompatibility window whose expiry is
            // enforced here, at read time.
            var withinCompatibilityWindow = _allowPlaintextReadCompatibility
                && (_plaintextReadCompatibilityExpiresAtUtc is not { } deadline
                    || _timeProvider.GetUtcNow() <= deadline);
            if (!withinCompatibilityWindow)
            {
                throw new CryptographicException(
                    "Vault ciphertext carries the legacy pt1 plaintext pass-through marker, " +
                    "which is only readable in Development or through a bounded " +
                    "Sufficit:Vault:PlaintextReadCompatibility window. The row was not written " +
                    "by the encrypted vault — treat it as tampered and rewrite it with " +
                    "envelope encryption.");
            }

            _logger.LogWarning(
                "Vault read a legacy plaintext compatibility value. Rewrite or rotate the owning record to migrate it to envelope encryption.");
            var encoded = ciphertext[
                SelfDescribingCiphertext.PassThroughPrefix.Length..];
            return WebEncoders.Base64UrlDecode(encoded);
        }

        var parsed = SelfDescribingCiphertext.Parse(ciphertext);
        var itemKey = await GetKeyAsync(parsed.KeyName, parsed.KeyVersion, cancellationToken);

        // Verify AAD hash before attempting decrypt (fail-fast on field-swap).
        if (parsed.AadHash is not null)
        {
            var expectedHash = SelfDescribingCiphertext.ComputeAadHash(additionalAuthenticatedData, itemKey);
            if (expectedHash.Length != parsed.AadHash.Length
                || !CryptographicOperations.FixedTimeEquals(
                    expectedHash,
                    parsed.AadHash))
            {
                throw new CryptographicException(
                    "AAD mismatch: the ciphertext was encrypted with different " +
                    "additional authenticated data. Possible field-swap tampering.");
            }
        }

        var aadBytes = SelfDescribingCiphertext.CanonicalizeAad(additionalAuthenticatedData);
        return EnvelopeCrypto.Decrypt(parsed.PackedCiphertext, itemKey, aadBytes);
    }

    /// <summary>
    /// Creates a new key version for <paramref name="keyName"/>. New encrypts
    /// use it; old ciphertext still decrypts via the embedded version.
    /// </summary>
    public async Task<KeyId> RotateKeyAsync(
        string keyName,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(keyName);

        // F-7 (eval 2026-08-14): serialize version allocation across replicas.
        // Without the lease, two concurrent rotations race maxVersion+1 and
        // one fails with an opaque unique-index DbUpdateException.
        await using var lease = await AcquireKeyOperationLeaseAsync(
            keyName, cancellationToken);
        await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);
        var nextVersion = await GetNextVersionAsync(db, keyName, cancellationToken);

        var itemKey = EnvelopeCrypto.GenerateKey();
        var wrappedKey = _kek.Wrap(itemKey);

        db.VaultKeys.Add(new VaultKey
        {
            KeyName = keyName,
            KeyVersion = nextVersion,
            Purpose = "symmetric",
            WrappedKey = wrappedKey,
            CreatedAtUtc = DateTime.UtcNow,
        });
        await db.SaveChangesAsync(cancellationToken);

        _keyCache[(keyName, nextVersion)] = itemKey;
        if (_snapshots is not null)
        {
            await _snapshots.InvalidateSymmetricKeyAsync(keyName, cancellationToken);
        }
        _logger.LogInformation("Rotated vault key '{KeyName}' to version {Version}.", keyName, nextVersion);
        return new KeyId(keyName, nextVersion);
    }

    public async Task<string> SignAsync(
        string keyName,
        int keyVersion,
        byte[] payload,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(keyName);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(keyVersion);
        ArgumentNullException.ThrowIfNull(payload);
        var algorithm = await ResolveSigningAlgorithmAsync(
            keyName, keyVersion, cancellationToken);
        var privateKey = await GetSigningPrivateKeyAsync(
            keyName, keyVersion, algorithm, cancellationToken);
        using (privateKey)
        {
            var signature = algorithm switch
            {
                SigningAlgorithms.RsaPssSha256 => ((RSA)privateKey).SignData(
                    payload,
                    HashAlgorithmName.SHA256,
                    RSASignaturePadding.Pss),
                SigningAlgorithms.EcdsaSha256 => ((ECDsa)privateKey).SignData(
                    payload,
                    HashAlgorithmName.SHA256,
                    DSASignatureFormat.IeeeP1363FixedFieldConcatenation),
                _ => ((RSA)privateKey).SignData(
                    payload,
                    HashAlgorithmName.SHA256,
                    RSASignaturePadding.Pkcs1),
            };
            return VaultSignature.Format(keyName, keyVersion, signature);
        }
    }

    public async Task<bool> VerifyAsync(
        string keyName,
        int keyVersion,
        byte[] payload,
        byte[] signature,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(keyName);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(keyVersion);
        ArgumentNullException.ThrowIfNull(payload);
        ArgumentNullException.ThrowIfNull(signature);
        try
        {
            // The snapshot is invalidated locally and through Redis on every
            // lifecycle mutation. Without Redis, the bounded TTL/background
            // refresh is the documented convergence window.
            if (_snapshots is not null)
            {
                var cachedKeys = await _snapshots.GetSigningKeysAsync(
                    keyName,
                    LoadCurrentSigningKeysAsync,
                    cancellationToken);
                var cached = cachedKeys.SingleOrDefault(
                    key => key.KeyVersion == keyVersion);
                if (cached is null) return false;

                // Same algorithm dispatch as the database path below: the
                // version's own JWK decides RSA PKCS#1 / RSA-PSS / ECDSA.
                // Hardcoding RSA+PKCS#1 here silently rejected every valid
                // ES256 and PS256 signature whenever the snapshot cache was
                // enabled (the default), while the database path accepted them.
                return VerifyWithJwk(cached.PublicJwk, payload, signature);
            }

            await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);
            var row = await db.VaultKeys.AsNoTracking()
                .SingleOrDefaultAsync(key => key.KeyName == keyName
                    && key.KeyVersion == keyVersion
                    && key.Purpose == "signing"
                    && (key.SigningState == VaultSigningKeyState.Active
                        || key.SigningState == VaultSigningKeyState.Retiring)
                    && (key.RetireAfterUtc == null
                        || key.RetireAfterUtc > _timeProvider.GetUtcNow().UtcDateTime),
                    cancellationToken);
            if (row is null || string.IsNullOrWhiteSpace(row.PublicJwk)) return false;

            return VerifyWithJwk(row.PublicJwk, payload, signature);

            async Task<IReadOnlyList<VaultSigningKey>> LoadCurrentSigningKeysAsync(
                CancellationToken ct)
            {
                await using var database = await _dbFactory.CreateDbContextAsync(ct);
                var now = _timeProvider.GetUtcNow().UtcDateTime;
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
                        GetSigningKeyId(key.KeyName, key.KeyVersion),
                        key.PublicJwk!,
                        key.SigningState == VaultSigningKeyState.Retiring
                            ? VaultSigningKeyStatus.Retiring
                            : VaultSigningKeyStatus.Active,
                        key.RetireAfterUtc))
                    .ToArrayAsync(ct);
            }
        }
        catch (CryptographicException)
        {
            return false;
        }
        catch (FormatException)
        {
            return false;
        }
        catch (JsonException)
        {
            return false;
        }
    }

    public async Task<KeyId> RotateSigningKeyAsync(
        string keyName,
        string operationId,
        string? reason = null,
        CancellationToken cancellationToken = default)
    {
        ValidateLifecycleArguments(keyName, operationId, reason);
        var existing = await FindLifecycleOperationAsync(
            operationId,
            "rotate",
            keyName,
            cancellationToken);
        if (existing is not null)
        {
            return new KeyId(existing.KeyName, existing.KeyVersion);
        }

        await using var lease = await AcquireKeyOperationLeaseAsync(
            keyName,
            cancellationToken);
        await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);
        await using var transaction = await db.Database.BeginTransactionAsync(
            IsolationLevel.Serializable,
            cancellationToken);

        existing = await db.VaultSigningKeyLifecycleOperations.AsNoTracking()
            .SingleOrDefaultAsync(item => item.OperationId == operationId,
                cancellationToken);
        if (existing is not null)
        {
            EnsureMatchingOperation(existing, "rotate", keyName);
            await transaction.CommitAsync(cancellationToken);
            return new KeyId(existing.KeyName, existing.KeyVersion);
        }

        var active = await db.VaultKeys
            .SingleOrDefaultAsync(key => key.KeyName == keyName
                && key.Purpose == "signing"
                && key.SigningState == VaultSigningKeyState.Active,
                cancellationToken);
        var nextVersion = (await db.VaultKeys.AsNoTracking()
            .Where(key => key.KeyName == keyName && key.Purpose == "signing")
            .Select(key => (int?)key.KeyVersion)
            .MaxAsync(cancellationToken) ?? 0) + 1;
        var now = _timeProvider.GetUtcNow().UtcDateTime;
        var retireAfter = now.AddSeconds(_options.SigningKeyOverlapSeconds);

        await CreateSigningKeyRowAsync(
            db,
            keyName,
            nextVersion,
            VaultSigningKeyState.Active,
            cancellationToken);
        if (active is not null)
        {
            active.SigningState = VaultSigningKeyState.Retiring;
            active.RetireAfterUtc = retireAfter;
            active.LifecycleVersion++;
        }

        db.VaultSigningKeyLifecycleOperations.Add(
            new VaultSigningKeyLifecycleOperation
            {
                OperationId = operationId,
                KeyName = keyName,
                KeyVersion = nextVersion,
                PreviousKeyVersion = active?.KeyVersion,
                Action = "rotate",
                Reason = reason,
                OccurredAtUtc = now,
                RetireAfterUtc = active is null ? null : retireAfter,
            });
        await db.SaveChangesAsync(cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        if (_snapshots is not null)
        {
            await _snapshots.InvalidateSigningKeysAsync(keyName, cancellationToken);
        }
        _logger.LogInformation(
            "Rotated vault signing key '{KeyName}' to version {Version}; previous version {PreviousVersion} retires at {RetireAfterUtc}.",
            keyName,
            nextVersion,
            active?.KeyVersion,
            active is null ? null : retireAfter);
        return new KeyId(keyName, nextVersion);
    }

    /// <summary>Clears the in-memory key cache (tests/admin).</summary>
    public void FlushCache()
    {
        _keyCache.Clear();
        _snapshots?.Flush();
    }

    private async Task<(byte[] Key, int Version)> GetOrCreateLatestKeyAsync(
        string keyName,
        CancellationToken cancellationToken)
    {
        if (_snapshots is not null)
        {
            var material = await _snapshots.GetLatestSymmetricKeyAsync(
                keyName,
                LoadLatestSymmetricKeyMaterialAsync,
                cancellationToken);
            var itemKey = await UnwrapAndCacheAsync(
                keyName,
                material.Version,
                material.WrappedKey);
            return (itemKey, material.Version);
        }

        return await LoadLatestSymmetricKeyAsync(cancellationToken);

        async Task<(byte[] Key, int Version)> LoadLatestSymmetricKeyAsync(
            CancellationToken ct)
        {
            var material = await LoadLatestSymmetricKeyMaterialAsync(ct);
            var itemKey = await UnwrapAndCacheAsync(
                keyName,
                material.Version,
                material.WrappedKey);
            return (itemKey, material.Version);
        }

        async Task<SymmetricKeySnapshot> LoadLatestSymmetricKeyMaterialAsync(
            CancellationToken ct)
        {
            await using var db = await _dbFactory.CreateDbContextAsync(ct);
            var latest = await db.VaultKeys
                .AsNoTracking()
                .Where(k => k.KeyName == keyName
                    && k.Purpose == "symmetric"
                    && k.RetiredAtUtc == null)
                .OrderByDescending(k => k.KeyVersion)
                .FirstOrDefaultAsync(ct);

            if (latest is not null)
            {
                return new SymmetricKeySnapshot(
                    latest.KeyVersion,
                    latest.WrappedKey);
            }

            // First use of this key name — create v1 under the distributed
            // operation lease (F-7, eval 2026-08-14): two replicas hitting a
            // cold key concurrently would otherwise race duplicate v1 inserts.
            // Losing the lease is normal under concurrency, so the loser
            // retries with a bounded re-read until the winner's v1 becomes
            // visible (or the lease frees and the loser creates it itself).
            for (var attempt = 0; ; attempt++)
            {
                try
                {
                    await using (await AcquireKeyOperationLeaseAsync(keyName, ct))
                    {
                        // Re-read under the lease: the previous holder may
                        // have created v1 while we were waiting to acquire.
                        var raced = await db.VaultKeys
                            .AsNoTracking()
                            .Where(k => k.KeyName == keyName
                                && k.Purpose == "symmetric"
                                && k.RetiredAtUtc == null)
                            .OrderByDescending(k => k.KeyVersion)
                            .FirstOrDefaultAsync(ct);
                        if (raced is not null)
                        {
                            return new SymmetricKeySnapshot(
                                raced.KeyVersion,
                                raced.WrappedKey);
                        }

                        var itemKey = EnvelopeCrypto.GenerateKey();
                        var wrappedKey = _kek.Wrap(itemKey);
                        db.VaultKeys.Add(new VaultKey
                        {
                            KeyName = keyName,
                            KeyVersion = 1,
                            Purpose = "symmetric",
                            WrappedKey = wrappedKey,
                            CreatedAtUtc = _timeProvider.GetUtcNow().UtcDateTime,
                        });
                        await db.SaveChangesAsync(ct);
                        _keyCache[(keyName, 1)] = itemKey;
                        _logger.LogInformation("Created vault key '{KeyName}' v1.", keyName);
                        return new SymmetricKeySnapshot(1, wrappedKey);
                    }
                }
                catch (KeyOperationLeaseConflictException) when (attempt < ColdStartLeaseRetryLimit)
                {
                    await Task.Delay(ColdStartLeaseRetryDelay, ct);
                }
            }
        }
    }

    private async Task<VaultSigningKeyLifecycleOperation?>
        FindLifecycleOperationAsync(
            string operationId,
            string action,
            string keyName,
            CancellationToken cancellationToken)
    {
        await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);
        var existing = await db.VaultSigningKeyLifecycleOperations.AsNoTracking()
            .SingleOrDefaultAsync(item => item.OperationId == operationId,
                cancellationToken);
        if (existing is not null)
        {
            EnsureMatchingOperation(existing, action, keyName);
        }
        return existing;
    }

    private sealed class KeyOperationLease(
        KeyVault owner,
        string keyName,
        string ownerId) : IAsyncDisposable
    {
        public ValueTask DisposeAsync() =>
            owner.ReleaseKeyOperationLeaseAsync(keyName, ownerId);
    }

    private async Task<byte[]> GetKeyAsync(string keyName, int version, CancellationToken cancellationToken)
    {
        if (_keyCache.TryGetValue((keyName, version), out var cached))
        {
            return cached;
        }

        await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);
        // Purpose is part of the lookup, not just a convention: the key name
        // and version in a self-describing ciphertext are attacker-influenced
        // input, so without this filter a crafted "v1.oidc-signing:1.…" blob
        // would make the decrypt path unwrap a SIGNING private key and treat
        // it as a symmetric DEK. Keeping the two key spaces disjoint at the
        // query makes that structurally impossible rather than relying on the
        // AES-GCM key-length check to reject it downstream.
        var row = await db.VaultKeys
            .AsNoTracking()
            .Where(k => k.KeyName == keyName
                && k.KeyVersion == version
                && k.Purpose == "symmetric")
            .FirstOrDefaultAsync(cancellationToken)
            ?? throw new CryptographicException(
                $"Vault key '{keyName}' v{version} not found. It may have been retired and deleted.");

        return await UnwrapAndCacheAsync(keyName, version, row.WrappedKey);
    }

    private async Task<byte[]> UnwrapAndCacheAsync(string keyName, int version, byte[] wrappedKey)
    {
        if (_keyCache.TryGetValue((keyName, version), out var cached))
        {
            return cached;
        }

        var itemKey = _kek.Unwrap(wrappedKey);
        _keyCache[(keyName, version)] = itemKey;
        return itemKey;
    }

    private static async Task<int> GetNextVersionAsync(AppDbContext db, string keyName, CancellationToken ct)
    {
        var maxVersion = await db.VaultKeys
            .AsNoTracking()
            .Where(k => k.KeyName == keyName)
            .Select(k => (int?)k.KeyVersion)
            .MaxAsync(ct);
        return (maxVersion ?? 0) + 1;
    }
}
