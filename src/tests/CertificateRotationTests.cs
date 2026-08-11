using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Sufficit.Identity.STS;
using Sufficit.Identity.Vault;
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

            var signing = ReadCertificates(material, "Signing");
            Assert.Equal(2, signing.Count);
            Assert.Equal(active.Thumbprint, signing[0].Thumbprint);
            Assert.Equal(retiring.Thumbprint, signing[1].Thumbprint);
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
            var exception = Assert.Throws<TargetInvocationException>(() =>
                Load(new CertificatesOptions
                {
                    SigningPath = certificate.Path,
                    SigningPassword = password,
                    EncryptionPath = certificate.Path,
                    EncryptionPassword = password,
                    RequirePurposeSeparation = true,
                }));

            Assert.IsType<InvalidOperationException>(exception.InnerException);
        }
        finally
        {
            directory.Delete(recursive: true);
        }
    }

    private static object Load(CertificatesOptions options)
    {
        var method = typeof(Sufficit.Identity.STS.ServiceCollectionExtensions).GetMethod(
            "LoadCertificateMaterial",
            BindingFlags.NonPublic | BindingFlags.Static)
            ?? throw new InvalidOperationException("Certificate loader not found.");
        var store = new OptionsSecretStore(
            options.SigningPassword,
            options.EncryptionPassword);
        return method.Invoke(null, [options, true, store])
            ?? throw new InvalidOperationException("Certificate material was null.");
    }

    private sealed class OptionsSecretStore(
        string? signingPassword,
        string? encryptionPassword) : ISecretStore
    {
        public Task<string?> GetSecretAsync(
            string name,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult<string?>(name switch
            {
                "identity/certificates/signing-password" => signingPassword,
                "identity/certificates/encryption-password" => encryptionPassword,
                _ => null,
            });
        }
    }

    private static IReadOnlyList<X509Certificate2> ReadCertificates(
        object material,
        string propertyName) =>
        (IReadOnlyList<X509Certificate2>)(material.GetType().GetProperty(
            propertyName)?.GetValue(material)
            ?? throw new InvalidOperationException(
                $"Certificate property {propertyName} not found."));

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
