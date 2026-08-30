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
    public async Task<string> SignAsync(
        string keyName,
        byte[] payload,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(keyName);
        ArgumentNullException.ThrowIfNull(payload);
        var keyVersion = await GetOrCreateLatestSigningKeyAsync(
            keyName, cancellationToken);
        return await SignAsync(keyName, keyVersion, payload, cancellationToken);
    }

    /// <summary>
    /// Resolves the algorithm a key VERSION was created with, from the
    /// version's stored public JWK (never from current configuration, so a
    /// post-rotation in-flight version still signs with its own family).
    /// </summary>
    private async Task<string> ResolveSigningAlgorithmAsync(
        string keyName,
        int keyVersion,
        CancellationToken cancellationToken)
    {
        var keys = await GetSigningKeysAsync(keyName, cancellationToken);
        return keys.FirstOrDefault(key => key.KeyVersion == keyVersion)
            is { PublicJwk: { } jwk }
                ? SigningAlgorithms.FromJwk(jwk)
                : SigningAlgorithms.RsaSha256;
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

    public async Task<IReadOnlyList<VaultSigningKey>> GetSigningKeysAsync(
        string keyName,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(keyName);
        if (_snapshots is not null)
        {
            return await _snapshots.GetSigningKeysAsync(
                keyName,
                LoadSigningKeysAsync,
                cancellationToken);
        }

        return await LoadSigningKeysAsync(cancellationToken);

        async Task<IReadOnlyList<VaultSigningKey>> LoadSigningKeysAsync(
            CancellationToken ct)
        {
            await using var db = await _dbFactory.CreateDbContextAsync(ct);
            var now = _timeProvider.GetUtcNow().UtcDateTime;
            var rows = await db.VaultKeys.AsNoTracking()
                .Where(key => key.KeyName == keyName
                    && key.Purpose == "signing"
                    && (key.SigningState == VaultSigningKeyState.Active
                        || (key.SigningState == VaultSigningKeyState.Retiring
                            && key.RetireAfterUtc > now)))
                .OrderBy(key => key.SigningState == VaultSigningKeyState.Active ? 0 : 1)
                .ThenByDescending(key => key.KeyVersion)
                .ToListAsync(ct);
            if (rows.Count == 0)
            {
                var anySigningKey = await db.VaultKeys.AsNoTracking()
                    .AnyAsync(key => key.KeyName == keyName
                        && key.Purpose == "signing", ct);
                if (anySigningKey)
                {
                    return [];
                }

                await EnsureSigningKeyInitializedAsync(keyName, ct);
                rows = await db.VaultKeys.AsNoTracking()
                    .Where(key => key.KeyName == keyName
                        && key.Purpose == "signing"
                        && key.SigningState == VaultSigningKeyState.Active)
                    .OrderByDescending(key => key.KeyVersion)
                    .ToListAsync(ct);
                _logger.LogInformation(
                    "Created vault signing key '{KeyName}' v1 for public-key discovery.",
                    keyName);
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
    }

    public Task<KeyId> RotateSigningKeyAsync(
        string keyName,
        CancellationToken cancellationToken = default) =>
        RotateSigningKeyAsync(
            keyName,
            $"rotate:{Guid.NewGuid():N}",
            reason: null,
            cancellationToken);

    public async Task<int> RetireSigningKeysAsync(
        string keyName,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(keyName);
        await using var lease = await AcquireKeyOperationLeaseAsync(
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
        if (_snapshots is not null && elapsed.Count > 0)
        {
            await _snapshots.InvalidateSigningKeysAsync(keyName, cancellationToken);
        }
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

        await using var lease = await AcquireKeyOperationLeaseAsync(
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
        if (_snapshots is not null)
        {
            await _snapshots.InvalidateSigningKeysAsync(keyName, cancellationToken);
        }
        _logger.LogCritical(
            "Emergency-revoked vault signing key '{KeyName}' version {Version}. Tokens signed by this kid are no longer accepted.",
            keyName,
            keyVersion);
        return true;
    }

    /// <summary>
    /// Resolves (creating on first use) the ACTIVE signing-key version. Since
    /// A6 the version's own algorithm drives signing, this returns only the
    /// version number — the previous RSA re-import of the wrapped private key
    /// was discarded by every caller and broke for EC keys.
    /// </summary>
    private async Task<int> GetOrCreateLatestSigningKeyAsync(
        string keyName,
        CancellationToken cancellationToken)
    {
        await using var db = await _dbFactory.CreateDbContextAsync(
            cancellationToken);
        var latest = await db.VaultKeys.AsNoTracking()
            .Where(key => key.KeyName == keyName
                && key.Purpose == "signing"
                && key.SigningState == VaultSigningKeyState.Active)
            .Select(key => (int?)key.KeyVersion)
            .SingleOrDefaultAsync(cancellationToken);
        if (latest is not null)
        {
            return latest.Value;
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
        _logger.LogInformation("Created vault signing key '{KeyName}' v1.", keyName);
        return 1;
    }

    private async Task<AsymmetricAlgorithm> GetSigningPrivateKeyAsync(
        string keyName,
        int keyVersion,
        string algorithm,
        CancellationToken cancellationToken)
    {
        if (_snapshots is not null)
        {
            var wrappedKey = await _snapshots.GetSigningKeyMaterialAsync(
                keyName,
                keyVersion,
                LoadSigningKeyMaterialAsync,
                cancellationToken);
            if (wrappedKey is null)
            {
                throw new CryptographicException(
                    $"Vault signing key '{keyName}' v{keyVersion} is not the active issuing key.");
            }

            return ImportSigningPrivateKey(wrappedKey, algorithm);
        }

        return await LoadSigningPrivateKeyAsync(cancellationToken);

        async Task<byte[]?> LoadSigningKeyMaterialAsync(CancellationToken ct)
        {
            await using var database = await _dbFactory.CreateDbContextAsync(ct);
            return await database.VaultKeys.AsNoTracking()
                .Where(key => key.KeyName == keyName
                    && key.KeyVersion == keyVersion
                    && key.Purpose == "signing"
                    && key.SigningState == VaultSigningKeyState.Active)
                .Select(key => key.WrappedKey)
                .SingleOrDefaultAsync(ct);
        }

        async Task<AsymmetricAlgorithm> LoadSigningPrivateKeyAsync(CancellationToken ct)
        {
            var wrappedKey = await LoadSigningKeyMaterialAsync(ct)
                ?? throw new CryptographicException(
                    $"Vault signing key '{keyName}' v{keyVersion} is not the active issuing key.");
            return ImportSigningPrivateKey(wrappedKey, algorithm);
        }

        AsymmetricAlgorithm ImportSigningPrivateKey(
            byte[] wrappedKey,
            string importAlgorithm)
        {
            var privateBytes = _kek.Unwrap(wrappedKey);
            try
            {
                if (importAlgorithm == SigningAlgorithms.EcdsaSha256)
                {
                    var ec = ECDsa.Create();
                    ec.ImportPkcs8PrivateKey(privateBytes, out _);
                    return ec;
                }

                var privateKey = RSA.Create();
                privateKey.ImportPkcs8PrivateKey(privateBytes, out _);
                return privateKey;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(privateBytes);
            }
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

        // A6 (eval 2026-08-14): the configured algorithm decides the key
        // FAMILY of this version; it is embedded in the stored public JWK so
        // signing, verification and JWKS publication always follow the
        // version's own algorithm, never the current configuration.
        string publicJwk;
        byte[] privateBytes;
        var algorithm = _options.SigningAlgorithm;
        if (algorithm == SigningAlgorithms.EcdsaSha256)
        {
            using var ecdsa = ECDsa.Create(
                System.Security.Cryptography.ECCurve.NamedCurves.nistP256);
            privateBytes = ecdsa.ExportPkcs8PrivateKey();
            var parameters = ecdsa.ExportParameters(false);
            publicJwk = JsonSerializer.Serialize(new
            {
                kty = "EC",
                crv = "P-256",
                x = WebEncoders.Base64UrlEncode(parameters.Q.X!),
                y = WebEncoders.Base64UrlEncode(parameters.Q.Y!),
                alg = SigningAlgorithms.EcdsaSha256,
                use = "sig",
                kid = GetSigningKeyId(keyName, version),
            });
        }
        else
        {
            using var rsa = RSA.Create(3072);
            privateBytes = rsa.ExportPkcs8PrivateKey();
            var parameters = rsa.ExportParameters(false);
            publicJwk = JsonSerializer.Serialize(new
            {
                kty = "RSA",
                n = WebEncoders.Base64UrlEncode(parameters.Modulus!),
                e = WebEncoders.Base64UrlEncode(parameters.Exponent!),
                alg = algorithm,
                use = "sig",
                kid = GetSigningKeyId(keyName, version),
            });
        }
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
        await using var lease = await AcquireKeyOperationLeaseAsync(
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
        if (_snapshots is not null)
        {
            await _snapshots.InvalidateSigningKeysAsync(keyName, cancellationToken);
        }
        _logger.LogInformation(
            "Created vault signing key '{KeyName}' v1 under the distributed lifecycle lease.",
            keyName);
    }

    /// <summary>
    /// Verifies with the algorithm embedded in the version's JWK: RSA with
    /// PKCS#1 v1.5 (RS256) or PSS (PS256) padding, or ECDSA P-256 with the
    /// JOSE R||S (P-1363) signature format — never the current
    /// configuration's algorithm.
    /// </summary>
    private static bool VerifyWithJwk(
        string publicJwk,
        byte[] payload,
        byte[] signature)
    {
        var algorithm = SigningAlgorithms.FromJwk(publicJwk);
        if (algorithm == SigningAlgorithms.EcdsaSha256)
        {
            using var ec = CreatePublicEcdsa(publicJwk);
            return ec.VerifyData(
                payload,
                signature,
                HashAlgorithmName.SHA256,
                DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        }

        using var rsa = CreatePublicRsa(publicJwk);
        return rsa.VerifyData(
            payload,
            signature,
            HashAlgorithmName.SHA256,
            algorithm == SigningAlgorithms.RsaPssSha256
                ? RSASignaturePadding.Pss
                : RSASignaturePadding.Pkcs1);
    }

    private static ECDsa CreatePublicEcdsa(string publicJwk)
    {
        using var document = JsonDocument.Parse(publicJwk);
        var root = document.RootElement;
        if (!root.TryGetProperty("x", out var x)
            || !root.TryGetProperty("y", out var y))
        {
            throw new FormatException("Signing JWK is missing EC coordinates.");
        }

        var ec = ECDsa.Create();
        ec.ImportParameters(new ECParameters
        {
            Curve = System.Security.Cryptography.ECCurve.NamedCurves.nistP256,
            Q = new ECPoint
            {
                X = WebEncoders.Base64UrlDecode(x.GetString() ?? ""),
                Y = WebEncoders.Base64UrlDecode(y.GetString() ?? ""),
            },
        });
        return ec;
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
}
