using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Sufficit.Identity.STS;
using Xunit;

namespace Sufficit.Identity.Tests;

public sealed class CertificateRotationTests
{
    [Fact]
    public void Ordered_certificate_sets_load_active_and_retiring_keys()
    {
        var directory = Directory.CreateTempSubdirectory("identity-cert-rotation-");
        try
        {
            const string password = "test-only-password";
            var active = WriteCertificate(directory.FullName, "active", password);
            var retiring = WriteCertificate(directory.FullName, "retiring", password);
            var material = Load(new CertificatesOptions
            {
                SigningPath = active.Path,
                SigningPassword = password,
                SigningPaths = [active.Path, retiring.Path],
                EncryptionPath = active.Path,
                EncryptionPassword = password,
            });

            Assert.Equal(2, material.Signing.Count);
            Assert.Equal(active.Thumbprint, material.Signing[0].Thumbprint);
            Assert.Equal(retiring.Thumbprint, material.Signing[1].Thumbprint);
            // The first entry is the active certificate the STS signs with.
            Assert.Equal(active.Thumbprint, material.PrimarySigning?.Thumbprint);
        }
        finally
        {
            directory.Delete(recursive: true);
        }
    }

    [Fact]
    public void Purpose_separation_rejects_the_same_active_certificate()
    {
        var directory = Directory.CreateTempSubdirectory("identity-cert-purpose-");
        try
        {
            const string password = "test-only-password";
            var certificate = WriteCertificate(directory.FullName, "shared", password);
            var exception = Assert.Throws<InvalidOperationException>(() =>
                Load(new CertificatesOptions
                {
                    SigningPath = certificate.Path,
                    SigningPassword = password,
                    EncryptionPath = certificate.Path,
                    EncryptionPassword = password,
                    RequirePurposeSeparation = true,
                }));

            Assert.Contains(
                "purpose separation",
                exception.Message,
                StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            directory.Delete(recursive: true);
        }
    }

    // The loader used to be a private method reached by reflection through a
    // stub ISecretStore. It is now a named internal type taking the resolved
    // passwords directly, so the test calls it as the compiler sees it —
    // no TargetInvocationException unwrapping, no string method name to rot.
    private static CertificateMaterial Load(CertificatesOptions options) =>
        IdentityCertificateMaterial.Load(
            options,
            isDevelopmentEnvironment: true,
            options.SigningPassword,
            options.EncryptionPassword);

    private static (string Path, string Thumbprint) WriteCertificate(
        string directory,
        string name,
        string password)
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest(
            $"CN={name}.tests.local",
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        using var certificate = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddMinutes(-5),
            DateTimeOffset.UtcNow.AddDays(90));
        var path = Path.Combine(directory, name + ".pfx");
        File.WriteAllBytes(
            path,
            certificate.Export(X509ContentType.Pfx, password));
        return (path, certificate.Thumbprint);
    }
}
