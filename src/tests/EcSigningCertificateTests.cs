using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Server;
using Sufficit.Identity.STS;
using Xunit;

namespace Sufficit.Identity.Tests;

/// <summary>
/// A deployment that signs tokens with an elliptic-curve certificate could not
/// start: OpenIddict infers the algorithm from the key, and its inference does
/// not cover an X.509 certificate holding an EC key, so
/// <c>AddSigningCertificate</c> threw "a signature algorithm cannot be
/// automatically inferred from the signing key" while the services were being
/// composed. EC keys are what a FAPI-grade deployment uses — the profile does
/// not accept RS256 — and the conformance suite's FAPI 2 plan needs one.
/// </summary>
public sealed class EcSigningCertificateTests
{
    [Theory]
    [InlineData(256, SecurityAlgorithms.EcdsaSha256)]
    [InlineData(384, SecurityAlgorithms.EcdsaSha384)]
    [InlineData(521, SecurityAlgorithms.EcdsaSha512)]
    public void An_elliptic_curve_certificate_signs_with_the_algorithm_of_its_curve(
        int keySize,
        string expectedAlgorithm)
    {
        var curve = keySize switch
        {
            384 => ECCurve.NamedCurves.nistP384,
            521 => ECCurve.NamedCurves.nistP521,
            _ => ECCurve.NamedCurves.nistP256,
        };

        using var certificate = CreateEllipticCurveCertificate(curve);

        var credentials = ResolveSigningCredentials(certificate);

        Assert.Equal(expectedAlgorithm, credentials.Algorithm);
        // Announcing the algorithm is not enough: Microsoft.IdentityModel
        // refuses to build a signature provider for an X509SecurityKey with
        // ES256, which is how the first attempt at this failed — at runtime,
        // on the first token, rather than at composition time.
        Assert.True(credentials.Key.CryptoProviderFactory.IsSupportedAlgorithm(
            credentials.Algorithm,
            credentials.Key));
    }

    [Fact]
    public void An_rsa_certificate_keeps_the_algorithm_OpenIddict_infers()
    {
        using var certificate = CreateRsaCertificate();

        var credentials = ResolveSigningCredentials(certificate);

        Assert.Equal(SecurityAlgorithms.RsaSha256, credentials.Algorithm);
    }

    [Fact]
    public void Only_an_rsa_certificate_can_wrap_the_data_protection_key_ring()
    {
        // XML encryption cannot encrypt to an EC certificate; using one threw
        // on the first key the ring created, which is the first cookie the
        // server issued — not at startup.
        using var elliptic = CreateEllipticCurveCertificate(ECCurve.NamedCurves.nistP256);
        using var rsa = CreateRsaCertificate();

        Assert.False(ServiceCollectionExtensions.CanProtectDataProtectionKeys(elliptic));
        Assert.True(ServiceCollectionExtensions.CanProtectDataProtectionKeys(rsa));
        Assert.False(ServiceCollectionExtensions.CanProtectDataProtectionKeys(null));
    }

    private static SigningCredentials ResolveSigningCredentials(
        X509Certificate2 certificate)
    {
        var services = new ServiceCollection();
        services.AddOpenIddict().AddServer(server =>
        {
            // OpenIddict validates its options on build; the flow and the
            // encryption key are the minimum a server needs to be valid, and
            // neither takes part in what this test is about.
            server.AllowClientCredentialsFlow();
            server.SetTokenEndpointUris("/connect/token");
            server.AddEphemeralEncryptionKey();
            ServiceCollectionExtensions.AddSigningCertificate(server, certificate);
        });

        using var provider = services.BuildServiceProvider();
        var options = provider
            .GetRequiredService<IOptionsMonitor<OpenIddictServerOptions>>()
            .CurrentValue;

        return Assert.Single(options.SigningCredentials);
    }

    private static X509Certificate2 CreateEllipticCurveCertificate(ECCurve curve)
    {
        using var key = ECDsa.Create(curve);
        return new CertificateRequest("CN=Signing", key, HashAlgorithmName.SHA256)
            .CreateSelfSigned(
                DateTimeOffset.UtcNow.AddMinutes(-5),
                DateTimeOffset.UtcNow.AddYears(1));
    }

    private static X509Certificate2 CreateRsaCertificate()
    {
        using var key = RSA.Create(2048);
        return new CertificateRequest(
                "CN=Signing",
                key,
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pkcs1)
            .CreateSelfSigned(
                DateTimeOffset.UtcNow.AddMinutes(-5),
                DateTimeOffset.UtcNow.AddYears(1));
    }
}
