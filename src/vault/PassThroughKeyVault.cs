using Sufficit.Identity.Vault.Crypto;

namespace Sufficit.Identity.Vault;

/// <summary>
/// No-crypto pass-through <see cref="IKeyVault"/>. When
/// <see cref="VaultOptions.Enabled"/> is false, this is what resolves: encrypt
/// prefixes the plaintext with a marker (<c>pt1.</c>), decrypt strips it.
/// This lets every consumer wire <see cref="IKeyVault"/> unconditionally
/// without forcing encryption on in dev, while keeping a correct round-trip.
/// </summary>
internal sealed class PassThroughKeyVault :
    IKeyVault,
    IKeyVaultPlaintextReferenceCompatibility
{
    public bool AcceptsPlaintextClientSecretReferences => true;

    public Task<string> EncryptAsync(
        string keyName,
        byte[] plaintext,
        IReadOnlyDictionary<string, string>? additionalAuthenticatedData = null,
        CancellationToken cancellationToken = default)
    {
        // Marker prefix so DecryptAsync knows this is pass-through, not real
        // ciphertext. Base64 the plaintext so the marker is unambiguous
        // (can't collide with the "v1." real scheme prefix).
        var encoded = Microsoft.AspNetCore.WebUtilities.WebEncoders.Base64UrlEncode(plaintext);
        return Task.FromResult(SelfDescribingCiphertext.PassThroughPrefix + encoded);
    }

    public Task<ReadOnlyMemory<byte>> DecryptAsync(
        string ciphertext,
        IReadOnlyDictionary<string, string>? additionalAuthenticatedData = null,
        CancellationToken cancellationToken = default)
    {
        if (!ciphertext.StartsWith(SelfDescribingCiphertext.PassThroughPrefix, StringComparison.Ordinal))
        {
            throw new FormatException(
                "Ciphertext does not have the pass-through marker prefix; it may be " +
                "real ciphertext produced while vault encryption was enabled. Enable " +
                "Sufficit:Vault:Enabled=true to decrypt it.");
        }

        var encoded = ciphertext[SelfDescribingCiphertext.PassThroughPrefix.Length..];
        return Task.FromResult<ReadOnlyMemory<byte>>(
            Microsoft.AspNetCore.WebUtilities.WebEncoders.Base64UrlDecode(encoded));
    }

    public Task<KeyId> RotateKeyAsync(
        string keyName,
        CancellationToken cancellationToken = default)
        => Task.FromResult(new KeyId(keyName, Version: 1));

    public Task<string> SignAsync(
        string keyName,
        byte[] payload,
        CancellationToken cancellationToken = default) =>
        throw new NotSupportedException(
            "Signing keys require Sufficit:Vault:Enabled=true.");

    public Task<string> SignAsync(
        string keyName,
        int keyVersion,
        byte[] payload,
        CancellationToken cancellationToken = default) =>
        throw new NotSupportedException(
            "Signing keys require Sufficit:Vault:Enabled=true.");

    public Task<bool> VerifyAsync(
        string signature,
        byte[] payload,
        CancellationToken cancellationToken = default) =>
        throw new NotSupportedException(
            "Signing keys require Sufficit:Vault:Enabled=true.");

    public Task<bool> VerifyAsync(
        string keyName,
        int keyVersion,
        byte[] payload,
        byte[] signature,
        CancellationToken cancellationToken = default) =>
        throw new NotSupportedException(
            "Signing keys require Sufficit:Vault:Enabled=true.");

    public Task<IReadOnlyList<VaultSigningKey>> GetSigningKeysAsync(
        string keyName,
        CancellationToken cancellationToken = default) =>
        throw new NotSupportedException(
            "Signing keys require Sufficit:Vault:Enabled=true.");

    public Task<KeyId> RotateSigningKeyAsync(
        string keyName,
        CancellationToken cancellationToken = default) =>
        throw new NotSupportedException(
            "Signing keys require Sufficit:Vault:Enabled=true.");
}
