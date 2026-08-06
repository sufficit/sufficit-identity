using System.Collections.Concurrent;
using System.Security.Cryptography;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.Vault.Crypto;

namespace Sufficit.Identity.Vault;

/// <summary>
/// Real <see cref="IKeyVault"/> implementation: envelope encryption with a
/// KEK (Data Protection) wrapping per-name DEKs persisted in
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
    private readonly DataProtectionKeySource _kek;
    private readonly ILogger<KeyVault> _logger;

    // Cache: (keyName, version) → unwrapped item key (256-bit).
    private readonly ConcurrentDictionary<(string Name, int Version), byte[]> _keyCache = new();

    public KeyVault(
        IDbContextFactory<AppDbContext> dbFactory,
        DataProtectionKeySource kek,
        ILogger<KeyVault> logger)
    {
        _dbFactory = dbFactory;
        _kek = kek;
        _logger = logger;
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
        return SelfDescribingCiphertext.Format(keyName, version, packed,
            additionalAuthenticatedData is null || additionalAuthenticatedData.Count == 0 ? null : aadHash);
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
        var parsed = SelfDescribingCiphertext.Parse(ciphertext);
        var itemKey = await GetKeyAsync(parsed.KeyName, parsed.KeyVersion, cancellationToken);

        // Verify AAD hash before attempting decrypt (fail-fast on field-swap).
        if (parsed.AadHash is not null)
        {
            var expectedHash = SelfDescribingCiphertext.ComputeAadHash(additionalAuthenticatedData, itemKey);
            if (!expectedHash.SequenceEqual(parsed.AadHash))
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

    /// <summary>Clears the in-memory key cache (tests/admin).</summary>
    public void FlushCache() => _keyCache.Clear();

    private async Task<(byte[] Key, int Version)> GetOrCreateLatestKeyAsync(
        string keyName,
        CancellationToken cancellationToken)
    {
        await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);
        var latest = await db.VaultKeys
            .AsNoTracking()
            .Where(k => k.KeyName == keyName && k.RetiredAtUtc == null)
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
            CreatedAtUtc = DateTime.UtcNow,
        });
        await db.SaveChangesAsync(cancellationToken);

        _keyCache[(keyName, 1)] = itemKey;
        _logger.LogInformation("Created vault key '{KeyName}' v1.", keyName);
        return (itemKey, 1);
    }

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
