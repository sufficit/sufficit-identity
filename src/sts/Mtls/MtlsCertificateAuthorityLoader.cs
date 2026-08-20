using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Sufficit.Identity.STS.Mtls;

internal static class MtlsCertificateAuthorityLoader
{
    public static X509Certificate2Collection Load(IEnumerable<string> paths)
    {
        ArgumentNullException.ThrowIfNull(paths);

        var result = new X509Certificate2Collection();
        foreach (var configuredPath in paths)
        {
            if (string.IsNullOrWhiteSpace(configuredPath))
            {
                throw new InvalidOperationException(
                    "mTLS trusted certificate authority paths cannot be empty.");
            }

            var path = Path.GetFullPath(configuredPath.Trim());
            if (!File.Exists(path))
            {
                throw new InvalidOperationException(
                    $"mTLS trusted certificate authority file '{path}' was not found.");
            }

            var certificates = new X509Certificate2Collection();
            try
            {
                var text = File.ReadAllText(path);
                if (text.Contains("-----BEGIN CERTIFICATE-----", StringComparison.Ordinal))
                {
                    if (text.Contains("PRIVATE KEY-----", StringComparison.Ordinal))
                    {
                        throw new InvalidOperationException(
                            $"mTLS trusted certificate authority file '{path}' contains private key material.");
                    }

                    certificates.ImportFromPem(text);
                }
                else
                {
                    certificates.Add(X509CertificateLoader.LoadCertificateFromFile(path));
                }
            }
            catch (CryptographicException exception)
            {
                throw new InvalidOperationException(
                    $"mTLS trusted certificate authority file '{path}' is not a valid public certificate collection.",
                    exception);
            }

            if (certificates.Count == 0)
            {
                throw new InvalidOperationException(
                    $"mTLS trusted certificate authority file '{path}' contains no certificates.");
            }

            foreach (var certificate in certificates)
            {
                if (certificate.HasPrivateKey)
                {
                    throw new InvalidOperationException(
                        $"mTLS trusted certificate authority file '{path}' contains private key material.");
                }
            }

            result.AddRange(certificates);
        }

        return result;
    }

    public static void ConfigurePolicy(
        X509ChainPolicy policy,
        MtlsOptions options)
    {
        ArgumentNullException.ThrowIfNull(policy);
        ArgumentNullException.ThrowIfNull(options);

        policy.RevocationMode = options.RevocationMode switch
        {
            MtlsCertificateRevocationMode.NoCheck => X509RevocationMode.NoCheck,
            MtlsCertificateRevocationMode.Online => X509RevocationMode.Online,
            MtlsCertificateRevocationMode.Offline => X509RevocationMode.Offline,
            _ => throw new ArgumentOutOfRangeException(nameof(options)),
        };
        policy.RevocationFlag = X509RevocationFlag.EntireChain;
        policy.UrlRetrievalTimeout = TimeSpan.FromSeconds(
            options.RevocationTimeoutSeconds);
        policy.DisableCertificateDownloads =
            options.RevocationMode == MtlsCertificateRevocationMode.Offline;

        if (options.RevocationFailureMode ==
            MtlsRevocationFailureMode.AllowWhenUnavailable)
        {
            policy.VerificationFlags |=
                X509VerificationFlags.IgnoreEndRevocationUnknown
                | X509VerificationFlags.IgnoreCertificateAuthorityRevocationUnknown
                | X509VerificationFlags.IgnoreRootRevocationUnknown;
        }
    }
}
