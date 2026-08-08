using System.Collections.Concurrent;
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
    private readonly IVaultKeyEncryptionKeySource _kek;
    private readonly ILogger<KeyVault> _logger;

    // Cache: (keyName, version) → unwrapped item key (256-bit).
    private readonly ConcurrentDictionary<(string Name, int Version), byte[]> _keyCache = new();

    public KeyVault(
        IDbContextFactory<AppDbContext> dbFactory,
        IVaultKeyEncryptionKeySource kek,
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

    public async Task<string> SignAsync(
        string keyName,
        byte[] payload,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(keyName);
        ArgumentNullException.ThrowIfNull(payload);
        var key = await GetOrCreateLatestSigningKeyAsync(keyName, cancellationToken);
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
                    && key.Purpose == "signing", cancellationToken);
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
        var rows = await db.VaultKeys.AsNoTracking()
            .Where(key => key.KeyName == keyName
                && key.Purpose == "signing"
                && key.RetiredAtUtc == null)
            .OrderByDescending(key => key.KeyVersion)
            .ToListAsync(cancellationToken);
        if (rows.Count == 0)
        {
            await CreateSigningKeyRowAsync(db, keyName, 1, cancellationToken);
            await db.SaveChangesAsync(cancellationToken);
            rows = await db.VaultKeys.AsNoTracking()
                .Where(key => key.KeyName == keyName
                    && key.Purpose == "signing"
                    && key.RetiredAtUtc == null)
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
                row.PublicJwk!))
            .ToArray();
    }

    public Task<KeyId> RotateSigningKeyAsync(
        string keyName,
        CancellationToken cancellationToken = default) =>
        CreateSigningKeyAsync(keyName, cancellationToken);

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

    private async Task<(RSA Key, int KeyVersion)> GetOrCreateLatestSigningKeyAsync(
        string keyName,
        CancellationToken cancellationToken)
    {
        await using var db = await _dbFactory.CreateDbContextAsync(
            cancellationToken);
        var latest = await db.VaultKeys.AsNoTracking()
            .Where(key => key.KeyName == keyName
                && key.Purpose == "signing"
                && key.RetiredAtUtc == null)
            .OrderByDescending(key => key.KeyVersion)
            .FirstOrDefaultAsync(cancellationToken);
        if (latest is not null)
        {
            var privateBytes = _kek.Unwrap(latest.WrappedKey);
            var existing = RSA.Create();
            existing.ImportPkcs8PrivateKey(privateBytes, out _);
            return (existing, latest.KeyVersion);
        }

        await CreateSigningKeyRowAsync(db, keyName, 1, cancellationToken);
        await db.SaveChangesAsync(cancellationToken);
        var created = await db.VaultKeys.AsNoTracking()
            .SingleAsync(key => key.KeyName == keyName
                && key.KeyVersion == 1
                && key.Purpose == "signing", cancellationToken);
        var privateKey = RSA.Create();
        privateKey.ImportPkcs8PrivateKey(_kek.Unwrap(created.WrappedKey), out _);
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
                && key.Purpose == "signing", cancellationToken)
            ?? throw new CryptographicException(
                $"Vault signing key '{keyName}' v{keyVersion} not found.");
        var privateKey = RSA.Create();
        privateKey.ImportPkcs8PrivateKey(_kek.Unwrap(row.WrappedKey), out _);
        return privateKey;
    }

    private async Task<KeyId> CreateSigningKeyAsync(
        string keyName,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(keyName);
        await using var db = await _dbFactory.CreateDbContextAsync(
            cancellationToken);
        var nextVersion = await db.VaultKeys.AsNoTracking()
            .Where(key => key.KeyName == keyName && key.Purpose == "signing")
            .Select(key => (int?)key.KeyVersion)
            .MaxAsync(cancellationToken) ?? 0;
        nextVersion++;
        await CreateSigningKeyRowAsync(db, keyName, nextVersion,
            cancellationToken);
        await db.SaveChangesAsync(cancellationToken);
        _logger.LogInformation(
            "Rotated vault signing key '{KeyName}' to version {Version}.",
            keyName,
            nextVersion);
        return new KeyId(keyName, nextVersion);
    }

    private async Task CreateSigningKeyRowAsync(
        AppDbContext db,
        string keyName,
        int version,
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
        db.VaultKeys.Add(new VaultKey
        {
            KeyName = keyName,
            KeyVersion = version,
            Purpose = "signing",
            WrappedKey = _kek.Wrap(privateBytes),
            PublicJwk = publicJwk,
            CreatedAtUtc = DateTime.UtcNow,
        });
        await Task.CompletedTask;
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
