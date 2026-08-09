using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Sufficit.Identity.Vault;

/// <summary>
/// Wraps vault DEKs with a dedicated RSA certificate. The private key remains
/// outside the database and is required only for unwrap operations.
/// </summary>
internal sealed class CertificateKeySource : IVaultKeyEncryptionKeySource, IDisposable
{
    private readonly X509Certificate2 _certificate;

    public CertificateKeySource(VaultOptions options)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(options.CertificatePath);
        _certificate = X509CertificateLoader.LoadPkcs12FromFile(
            options.CertificatePath,
            options.CertificatePassword);
        Validate(_certificate);
    }

    public string KeyIdentifier => $"certificate:{_certificate.Thumbprint}";

    public byte[] Wrap(ReadOnlyMemory<byte> dek)
    {
        using var rsa = _certificate.GetRSAPublicKey()
            ?? throw new CryptographicException(
                "The vault KEK certificate does not expose an RSA public key.");
        return rsa.Encrypt(dek.Span, RSAEncryptionPadding.OaepSHA256);
    }

    public byte[] Unwrap(ReadOnlyMemory<byte> wrappedDek)
    {
        using var rsa = _certificate.GetRSAPrivateKey()
            ?? throw new CryptographicException(
                "The vault KEK certificate private key is unavailable.");
        return rsa.Decrypt(wrappedDek.Span, RSAEncryptionPadding.OaepSHA256);
    }

    public void Dispose() => _certificate.Dispose();

    internal static void Validate(X509Certificate2 certificate)
    {
        if (!certificate.HasPrivateKey)
        {
            throw new InvalidOperationException(
                "The vault KEK certificate must contain an RSA private key.");
        }

        using var rsa = certificate.GetRSAPrivateKey();
        if (rsa is null || rsa.KeySize < 3072)
        {
            throw new InvalidOperationException(
                "The vault KEK certificate must contain an RSA key of at least 3072 bits.");
        }

        var now = DateTime.UtcNow;
        if (certificate.NotBefore.ToUniversalTime() > now
            || certificate.NotAfter.ToUniversalTime() <= now)
        {
            throw new InvalidOperationException(
                "The vault KEK certificate is not currently valid.");
        }
    }
}
