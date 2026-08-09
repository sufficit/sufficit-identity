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
internal sealed class KeyVault : IKeyVault
{
    private readonly IDbContextFactory<AppDbContext> _dbFactory;
    private readonly IVaultKeyEncryptionKeySource _kek;
    private readonly ILogger<KeyVault> _logger;
    private readonly VaultOptions _options;
    private readonly TimeProvider _timeProvider;
    private readonly VaultCryptographyTelemetry _cryptographyTelemetry;

    // Cache: (keyName, version) → unwrapped item key (256-bit).
    private readonly ConcurrentDictionary<(string Name, int Version), byte[]> _keyCache = new();

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
            timeProvider)
    {
    }

    public KeyVault(
        IDbContextFactory<AppDbContext> dbFactory,
        IVaultKeyEncryptionKeySource kek,
        ILogger<KeyVault> logger,
        VaultOptions options,
        VaultCryptographyTelemetry cryptographyTelemetry,
        TimeProvider? timeProvider = null)
    {
        _dbFactory = dbFactory;
        _kek = kek;
        _logger = logger;
        _options = options;
        _cryptographyTelemetry = cryptographyTelemetry;
        _timeProvider = timeProvider ?? TimeProvider.System;
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
        _logger.LogInformation("Rotated vault key '{KeyName}' to version {Version}.", keyName, nextVersion);
        return new KeyId(keyName, nextVersion);
    }

    public async Task<string> SignAsync(
        string keyName,
        byte[] payload,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(keyName);
        ArgumentNullException.ThrowIfNull(payload);
        var key = await GetOrCreateLatestSigningKeyAsync(keyName, cancellationToken);
        key.Key.Dispose();
        return await SignAsync(keyName, key.KeyVersion, payload, cancellationToken);
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
        var privateKey = await GetSigningPrivateKeyAsync(keyName, keyVersion, cancellationToken);
        using (privateKey)
        {
            var signature = privateKey.SignData(
                payload,
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pkcs1);
            return VaultSignature.Format(keyName, keyVersion, signature);
        }
    }

    public async Task<bool> VerifyAsync(
        string signature,
        byte[] payload,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(payload);
        try
        {
            var parsed = VaultSignature.Parse(signature);
            return await VerifyAsync(
                parsed.KeyName,
                parsed.KeyVersion,
                payload,
                parsed.Signature,
                cancellationToken);
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

            using var rsa = CreatePublicRsa(row.PublicJwk);
            return rsa.VerifyData(
                payload,
                signature,
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pkcs1);
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

    public async Task<IReadOnlyList<VaultSigningKey>> GetSigningKeysAsync(
        string keyName,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(keyName);
        await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);
        var now = _timeProvider.GetUtcNow().UtcDateTime;
        var rows = await db.VaultKeys.AsNoTracking()
            .Where(key => key.KeyName == keyName
                && key.Purpose == "signing"
                && (key.SigningState == VaultSigningKeyState.Active
                    || (key.SigningState == VaultSigningKeyState.Retiring
                        && key.RetireAfterUtc > now)))
            .OrderBy(key => key.SigningState == VaultSigningKeyState.Active ? 0 : 1)
            .ThenByDescending(key => key.KeyVersion)
            .ToListAsync(cancellationToken);
        if (rows.Count == 0)
        {
            var anySigningKey = await db.VaultKeys.AsNoTracking()
                .AnyAsync(key => key.KeyName == keyName
                    && key.Purpose == "signing", cancellationToken);
            if (anySigningKey)
            {
                return [];
            }

            await EnsureSigningKeyInitializedAsync(keyName, cancellationToken);
            rows = await db.VaultKeys.AsNoTracking()
                .Where(key => key.KeyName == keyName
                    && key.Purpose == "signing"
                    && key.SigningState == VaultSigningKeyState.Active)
                .OrderByDescending(key => key.KeyVersion)
                .ToListAsync(cancellationToken);
            _logger.LogInformation("Created vault signing key '{KeyName}' v1 for public-key discovery.", keyName);
        }

        return rows
            .Where(row => !string.IsNullOrWhiteSpace(row.PublicJwk))
            .Select(row => new VaultSigningKey(
                row.KeyName,
                row.KeyVersion,
                GetSigningKeyId(row.KeyName, row.KeyVersion),
                row.PublicJwk!,
                row.SigningState == VaultSigningKeyState.Retiring
                    ? VaultSigningKeyStatus.Retiring
                    : VaultSigningKeyStatus.Active,
                row.RetireAfterUtc))
            .ToArray();
    }

    public Task<KeyId> RotateSigningKeyAsync(
        string keyName,
        CancellationToken cancellationToken = default) =>
        RotateSigningKeyAsync(
            keyName,
            $"rotate:{Guid.NewGuid():N}",
            reason: null,
            cancellationToken);

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

        await using var lease = await AcquireSigningKeyLeaseAsync(
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
        _logger.LogInformation(
            "Rotated vault signing key '{KeyName}' to version {Version}; previous version {PreviousVersion} retires at {RetireAfterUtc}.",
            keyName,
            nextVersion,
            active?.KeyVersion,
            active is null ? null : retireAfter);
        return new KeyId(keyName, nextVersion);
    }

    public async Task<int> RetireSigningKeysAsync(
        string keyName,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(keyName);
        await using var lease = await AcquireSigningKeyLeaseAsync(
            keyName,
            cancellationToken);
        await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);
        var now = _timeProvider.GetUtcNow().UtcDateTime;
        var elapsed = await db.VaultKeys
            .Where(key => key.KeyName == keyName
                && key.Purpose == "signing"
                && key.SigningState == VaultSigningKeyState.Retiring
                && key.RetireAfterUtc <= now)
            .ToListAsync(cancellationToken);
        foreach (var key in elapsed)
        {
            key.SigningState = VaultSigningKeyState.Retired;
            key.RetiredAtUtc = now;
            key.LifecycleVersion++;
            var operationId = CreateRetirementOperationId(keyName, key.KeyVersion);
            if (!await db.VaultSigningKeyLifecycleOperations
                .AnyAsync(item => item.OperationId == operationId,
                    cancellationToken))
            {
                db.VaultSigningKeyLifecycleOperations.Add(
                    new VaultSigningKeyLifecycleOperation
                    {
                        OperationId = operationId,
                        KeyName = keyName,
                        KeyVersion = key.KeyVersion,
                        Action = "retire",
                        OccurredAtUtc = now,
                        RetireAfterUtc = key.RetireAfterUtc,
                    });
            }
        }

        await db.SaveChangesAsync(cancellationToken);
        if (elapsed.Count > 0)
        {
            _logger.LogInformation(
                "Retired {Count} elapsed signing key versions for '{KeyName}'.",
                elapsed.Count,
                keyName);
        }
        return elapsed.Count;
    }

    public async Task<bool> RevokeSigningKeyAsync(
        string keyName,
        int keyVersion,
        string operationId,
        string reason,
        CancellationToken cancellationToken = default)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(keyVersion);
        ValidateLifecycleArguments(keyName, operationId, reason);
        if (string.IsNullOrWhiteSpace(reason))
        {
            throw new ArgumentException(
                "Emergency signing-key revocation requires a reason.",
                nameof(reason));
        }

        var existing = await FindLifecycleOperationAsync(
            operationId,
            "revoke",
            keyName,
            cancellationToken);
        if (existing is not null)
        {
            EnsureMatchingKeyVersion(existing, keyVersion);
            return true;
        }

        await using var lease = await AcquireSigningKeyLeaseAsync(
            keyName,
            cancellationToken);
        await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);
        existing = await db.VaultSigningKeyLifecycleOperations.AsNoTracking()
            .SingleOrDefaultAsync(item => item.OperationId == operationId,
                cancellationToken);
        if (existing is not null)
        {
            EnsureMatchingOperation(existing, "revoke", keyName);
            EnsureMatchingKeyVersion(existing, keyVersion);
            return true;
        }

        var key = await db.VaultKeys.SingleOrDefaultAsync(item =>
            item.KeyName == keyName
            && item.KeyVersion == keyVersion
            && item.Purpose == "signing", cancellationToken);
        if (key is null) return false;

        var now = _timeProvider.GetUtcNow().UtcDateTime;
        key.SigningState = VaultSigningKeyState.Revoked;
        key.RevokedAtUtc = now;
        key.RetireAfterUtc = null;
        key.LifecycleVersion++;
        db.VaultSigningKeyLifecycleOperations.Add(
            new VaultSigningKeyLifecycleOperation
            {
                OperationId = operationId,
                KeyName = keyName,
                KeyVersion = keyVersion,
                Action = "revoke",
                Reason = reason,
                OccurredAtUtc = now,
            });
        await db.SaveChangesAsync(cancellationToken);
        _logger.LogCritical(
            "Emergency-revoked vault signing key '{KeyName}' version {Version}. Tokens signed by this kid are no longer accepted.",
            keyName,
            keyVersion);
        return true;
    }

    /// <summary>Clears the in-memory key cache (tests/admin).</summary>
    public void FlushCache() => _keyCache.Clear();

    private async Task<(byte[] Key, int Version)> GetOrCreateLatestKeyAsync(
        string keyName,
        CancellationToken cancellationToken)
    {
        await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);
        var latest = await db.VaultKeys
            .AsNoTracking()
            .Where(k => k.KeyName == keyName
                && k.Purpose == "symmetric"
                && k.RetiredAtUtc == null)
            .OrderByDescending(k => k.KeyVersion)
            .FirstOrDefaultAsync(cancellationToken);

        if (latest is not null)
        {
            var key = await UnwrapAndCacheAsync(keyName, latest.KeyVersion, latest.WrappedKey);
            return (key, latest.KeyVersion);
        }

        // First use of this key name — create v1.
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
        await db.SaveChangesAsync(cancellationToken);

        _keyCache[(keyName, 1)] = itemKey;
        _logger.LogInformation("Created vault key '{KeyName}' v1.", keyName);
        return (itemKey, 1);
    }

    private async Task<(RSA Key, int KeyVersion)> GetOrCreateLatestSigningKeyAsync(
        string keyName,
        CancellationToken cancellationToken)
    {
        await using var db = await _dbFactory.CreateDbContextAsync(
            cancellationToken);
        var latest = await db.VaultKeys.AsNoTracking()
            .Where(key => key.KeyName == keyName
                && key.Purpose == "signing"
                && key.SigningState == VaultSigningKeyState.Active)
            .SingleOrDefaultAsync(cancellationToken);
        if (latest is not null)
        {
            var privateBytes = _kek.Unwrap(latest.WrappedKey);
            try
            {
                var existingKey = RSA.Create();
                existingKey.ImportPkcs8PrivateKey(privateBytes, out _);
                return (existingKey, latest.KeyVersion);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(privateBytes);
            }
        }

        var anySigningKey = await db.VaultKeys.AsNoTracking()
            .AnyAsync(key => key.KeyName == keyName
                && key.Purpose == "signing", cancellationToken);
        if (anySigningKey)
        {
            throw new CryptographicException(
                $"Vault signing key '{keyName}' has no active issuing version. Rotate a replacement after reviewing its lifecycle journal.");
        }

        await EnsureSigningKeyInitializedAsync(keyName, cancellationToken);
        var created = await db.VaultKeys.AsNoTracking()
            .SingleAsync(key => key.KeyName == keyName
                && key.KeyVersion == 1
                && key.Purpose == "signing"
                && key.SigningState == VaultSigningKeyState.Active,
                cancellationToken);
        var privateKey = RSA.Create();
        var createdPrivateBytes = _kek.Unwrap(created.WrappedKey);
        try
        {
            privateKey.ImportPkcs8PrivateKey(createdPrivateBytes, out _);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(createdPrivateBytes);
        }
        _logger.LogInformation("Created vault signing key '{KeyName}' v1.", keyName);
        return (privateKey, 1);
    }

    private async Task<RSA> GetSigningPrivateKeyAsync(
        string keyName,
        int keyVersion,
        CancellationToken cancellationToken)
    {
        await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);
        var row = await db.VaultKeys.AsNoTracking()
            .SingleOrDefaultAsync(key => key.KeyName == keyName
                && key.KeyVersion == keyVersion
                && key.Purpose == "signing"
                && key.SigningState == VaultSigningKeyState.Active,
                cancellationToken)
            ?? throw new CryptographicException(
                $"Vault signing key '{keyName}' v{keyVersion} is not the active issuing key.");
        var privateBytes = _kek.Unwrap(row.WrappedKey);
        try
        {
            var privateKey = RSA.Create();
            privateKey.ImportPkcs8PrivateKey(privateBytes, out _);
            return privateKey;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(privateBytes);
        }
    }

    private async Task CreateSigningKeyRowAsync(
        AppDbContext db,
        string keyName,
        int version,
        VaultSigningKeyState signingState,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        using var rsa = RSA.Create(3072);
        var privateBytes = rsa.ExportPkcs8PrivateKey();
        var parameters = rsa.ExportParameters(false);
        var publicJwk = JsonSerializer.Serialize(new
        {
            kty = "RSA",
            n = WebEncoders.Base64UrlEncode(parameters.Modulus!),
            e = WebEncoders.Base64UrlEncode(parameters.Exponent!),
            alg = "RS256",
            use = "sig",
            kid = GetSigningKeyId(keyName, version),
        });
        try
        {
            db.VaultKeys.Add(new VaultKey
            {
                KeyName = keyName,
                KeyVersion = version,
                Purpose = "signing",
                WrappedKey = _kek.Wrap(privateBytes),
                PublicJwk = publicJwk,
                CreatedAtUtc = _timeProvider.GetUtcNow().UtcDateTime,
                SigningState = signingState,
            });
        }
        finally
        {
            CryptographicOperations.ZeroMemory(privateBytes);
        }
        await Task.CompletedTask;
    }

    private async Task EnsureSigningKeyInitializedAsync(
        string keyName,
        CancellationToken cancellationToken)
    {
        await using var lease = await AcquireSigningKeyLeaseAsync(
            keyName,
            cancellationToken);
        await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);
        if (await db.VaultKeys.AsNoTracking().AnyAsync(key =>
                key.KeyName == keyName && key.Purpose == "signing",
                cancellationToken))
        {
            return;
        }

        await CreateSigningKeyRowAsync(
            db,
            keyName,
            1,
            VaultSigningKeyState.Active,
            cancellationToken);
        AddInitializationJournal(db, keyName);
        await db.SaveChangesAsync(cancellationToken);
        _logger.LogInformation(
            "Created vault signing key '{KeyName}' v1 under the distributed lifecycle lease.",
            keyName);
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

    private async Task<SigningKeyLease> AcquireSigningKeyLeaseAsync(
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
                return new SigningKeyLease(this, keyName, ownerId);
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
            throw new InvalidOperationException(
                $"Signing-key lifecycle operation for '{keyName}' is already running on another replica.");
        }
        return new SigningKeyLease(this, keyName, ownerId);
    }

    private async ValueTask ReleaseSigningKeyLeaseAsync(
        string keyName,
        string ownerId)
    {
        await using var db = await _dbFactory.CreateDbContextAsync();
        await db.VaultSigningKeyLocks
            .Where(item => item.KeyName == keyName && item.OwnerId == ownerId)
            .ExecuteDeleteAsync();
    }

    private sealed class SigningKeyLease(
        KeyVault owner,
        string keyName,
        string ownerId) : IAsyncDisposable
    {
        public ValueTask DisposeAsync() =>
            owner.ReleaseSigningKeyLeaseAsync(keyName, ownerId);
    }

    private static RSA CreatePublicRsa(string publicJwk)
    {
        using var jwk = JsonDocument.Parse(publicJwk);
        var root = jwk.RootElement;
        if (!root.TryGetProperty("n", out var modulus)
            || !root.TryGetProperty("e", out var exponent))
        {
            throw new FormatException("Signing JWK is missing RSA modulus or exponent.");
        }

        var rsa = RSA.Create();
        rsa.ImportParameters(new RSAParameters
        {
            Modulus = WebEncoders.Base64UrlDecode(modulus.GetString() ?? ""),
            Exponent = WebEncoders.Base64UrlDecode(exponent.GetString() ?? ""),
        });
        return rsa;
    }

    internal static string GetSigningKeyId(string keyName, int version) =>
        $"vault:{keyName}:{version}";

    private async Task<byte[]> GetKeyAsync(string keyName, int version, CancellationToken cancellationToken)
    {
        if (_keyCache.TryGetValue((keyName, version), out var cached))
        {
            return cached;
        }

        await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);
        var row = await db.VaultKeys
            .AsNoTracking()
            .Where(k => k.KeyName == keyName && k.KeyVersion == version)
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

internal static class VaultSignature
{
    private const string Scheme = "sig1";

    public static string Format(string keyName, int version, byte[] signature) =>
        $"{Scheme}.{keyName}:{version}.{WebEncoders.Base64UrlEncode(signature)}";

    public static ParsedVaultSignature Parse(string value)
    {
        var parts = value.Split('.', StringSplitOptions.None);
        if (parts.Length != 3 || parts[0] != Scheme)
            throw new FormatException("Unsupported vault signature format.");
        var key = parts[1].Split(':', 2);
        if (key.Length != 2 || !int.TryParse(key[1], out var version)
            || version < 1 || string.IsNullOrWhiteSpace(key[0]))
            throw new FormatException("Invalid vault signing key identifier.");
        return new ParsedVaultSignature(
            key[0],
            version,
            WebEncoders.Base64UrlDecode(parts[2]));
    }
}

internal sealed record ParsedVaultSignature(
    string KeyName,
    int KeyVersion,
    byte[] Signature);
