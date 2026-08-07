using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Http;
using Sufficit.Identity.STS;
using Sufficit.Identity.STS.Mtls;
using Sufficit.Identity.Tests.Infrastructure;
using Xunit;

namespace Sufficit.Identity.Tests;

public sealed class MtlsPolicyTests
{
    [Fact]
    public void Certificate_must_be_explicitly_bound_to_the_requesting_client()
    {
        using var certificate = CreateCertificate();
        var thumbprint = certificate.GetCertHashString(HashAlgorithmName.SHA256);
        var policy = new MtlsClientCertificatePolicy(new MtlsOptions
        {
            Enabled = true,
            DeploymentMode = MtlsDeploymentMode.DirectTls,
            RequireValidCertificateChain = false,
            ClientCertificateThumbprints = new Dictionary<string, HashSet<string>>
            {
                ["bound-client"] = new(StringComparer.Ordinal) { thumbprint },
            },
        });
        var context = new DefaultHttpContext();
        context.Connection.ClientCertificate = certificate;

        var bound = policy.Evaluate(context, "bound-client");
        var other = policy.Evaluate(context, "other-client");

        Assert.True(bound.Allowed);
        Assert.False(other.Allowed);
        Assert.Equal("certificate_not_bound_to_client", other.ReasonCode);
    }

    [Fact]
    public async Task Enabling_mtls_without_deployment_attestation_fails_startup()
    {
        using var factory = SufficitIdentityTestFactory.CreateIsolated(
            new Dictionary<string, string?>
            {
                ["Sufficit:Identity:Mtls:Enabled"] = "true",
            });

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(
            () => ((IAsyncLifetime)factory).InitializeAsync());

        Assert.Contains("DeploymentMode", exception.ToString(), StringComparison.Ordinal);
    }

    private static X509Certificate2 CreateCertificate()
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest(
            "CN=mtls-policy-test",
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        return request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddMinutes(-1),
            DateTimeOffset.UtcNow.AddHours(1));
    }
}
