using System.Security.Cryptography;

namespace Sufficit.Identity.Vault.Crypto;

/// <summary>
/// AES-256-GCM data encryption under an item key. GCM provides authenticated
/// encryption (confidentiality + integrity in one primitive); no separate
/// HMAC is needed. KEK wrapping is owned by <c>IVaultKeyEncryptionKeySource</c>
/// and may use RSA, Data Protection or an external KMS/HSM backend.
/// </summary>
/// <remarks>
/// Nonce/IV is 12 bytes (GCM standard), tag is 16 bytes (full). Both are
/// CSPRNG-generated per encrypt and prepended to the ciphertext output:
/// <c>iv ‖ ciphertext ‖ tag</c>.
/// </remarks>
internal static class EnvelopeCrypto
{
    public const int KeySize = 32;   // AES-256
    public const int NonceSize = 12; // GCM standard
    public const int TagSize = 16;   // full tag

    /// <summary>
    /// Generates a fresh 256-bit key.
    /// </summary>
    public static byte[] GenerateKey() => RandomNumberGenerator.GetBytes(KeySize);

    /// <summary>
    /// Encrypts <paramref name="plaintext"/> with <paramref name="key"/> and
    /// optional <paramref name="aad"/>. Returns <c>nonce ‖ ciphertext ‖ tag</c>.
    /// </summary>
    public static byte[] Encrypt(ReadOnlySpan<byte> plaintext, byte[] key, ReadOnlySpan<byte> aad)
    {
        var nonce = RandomNumberGenerator.GetBytes(NonceSize);
        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[TagSize];

        using var gcm = new AesGcm(key, TagSize);
        gcm.Encrypt(nonce, plaintext, ciphertext, tag, aad);

        // Pack: nonce ‖ ciphertext ‖ tag
        var output = new byte[NonceSize + ciphertext.Length + TagSize];
        Buffer.BlockCopy(nonce, 0, output, 0, NonceSize);
        Buffer.BlockCopy(ciphertext, 0, output, NonceSize, ciphertext.Length);
        Buffer.BlockCopy(tag, 0, output, NonceSize + ciphertext.Length, TagSize);
        return output;
    }

    /// <summary>
    /// Decrypts a blob produced by <see cref="Encrypt"/>. Throws
    /// <see cref="CryptographicException"/> on tamper or AAD mismatch (GCM
    /// authentication failure).
    /// </summary>
    public static byte[] Decrypt(ReadOnlySpan<byte> packed, byte[] key, ReadOnlySpan<byte> aad)
    {
        if (packed.Length < NonceSize + TagSize)
        {
            throw new CryptographicException("Ciphertext too short for GCM overhead.");
        }

        var nonce = packed[..NonceSize].ToArray();
        var tag = packed[(packed.Length - TagSize)..].ToArray();
        var ciphertext = packed[NonceSize..(packed.Length - TagSize)].ToArray();
        var plaintext = new byte[ciphertext.Length];

        using var gcm = new AesGcm(key, TagSize);
        gcm.Decrypt(nonce, ciphertext, tag, plaintext, aad);
        return plaintext;
    }
}
