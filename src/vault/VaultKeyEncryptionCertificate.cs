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
        var password = ResolvePassword(options, secretStore);
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

    /// <summary>
    /// Loads the decrypt-only certificates of <see cref="VaultOptions.PreviousCertificatePaths"/>
    /// with the active certificate's password. Validity dates are not
    /// checked: an expired KEK still has to unwrap what it protected.
    /// </summary>
    public static IReadOnlyList<X509Certificate2> LoadPrevious(
        VaultOptions options,
        ISecretStore? secretStore = null)
    {
        ArgumentNullException.ThrowIfNull(options);
        var paths = options.PreviousCertificatePaths
            .Where(path => !string.IsNullOrWhiteSpace(path))
            .ToArray();
        if (paths.Length == 0)
        {
            return [];
        }

        var password = ResolvePassword(options, secretStore);
        var loaded = new List<X509Certificate2>(paths.Length);
        try
        {
            foreach (var path in paths)
            {
                var certificate = X509CertificateLoader.LoadPkcs12FromFile(path, password);
                loaded.Add(certificate);
                using var rsa = certificate.GetRSAPrivateKey();
                if (!certificate.HasPrivateKey || rsa is null)
                {
                    throw new InvalidOperationException(
                        $"The previous vault KEK certificate '{Path.GetFileName(path)}' must contain an RSA private key.");
                }
            }

            return loaded;
        }
        catch
        {
            foreach (var certificate in loaded)
            {
                certificate.Dispose();
            }

            throw;
        }
    }

    private static string? ResolvePassword(VaultOptions options, ISecretStore? secretStore) =>
        secretStore is null
            ? options.CertificatePassword
            : secretStore.GetSecretAsync("vault/kek-certificate-password")
                .GetAwaiter()
                .GetResult() ?? options.CertificatePassword;

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
