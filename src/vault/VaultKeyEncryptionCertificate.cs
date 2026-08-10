using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Sufficit.Identity.Vault;

/// <summary>Loads and validates the dedicated certificate shared by the vault
/// KEK and Data Protection key-ring configuration.</summary>
public static class VaultKeyEncryptionCertificate
{
    public static X509Certificate2 Load(
        VaultOptions options,
        ISecretStore? secretStore = null)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentException.ThrowIfNullOrWhiteSpace(options.CertificatePath);
        var password = secretStore is null
            ? options.CertificatePassword
            : secretStore.GetSecretAsync("vault/kek-certificate-password")
                .GetAwaiter()
                .GetResult() ?? options.CertificatePassword;
        var certificate = X509CertificateLoader.LoadPkcs12FromFile(
            options.CertificatePath,
            password);
        try
        {
            Validate(certificate);
            return certificate;
        }
        catch
        {
            certificate.Dispose();
            throw;
        }
    }

    public static void Validate(X509Certificate2 certificate)
    {
        ArgumentNullException.ThrowIfNull(certificate);
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
