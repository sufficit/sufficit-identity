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

    public CertificateKeySource(
        VaultOptions options,
        ISecretStore? secretStore = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(options.CertificatePath);
        _certificate = VaultKeyEncryptionCertificate.Load(options, secretStore);
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

}
