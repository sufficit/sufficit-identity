using Sufficit.Identity.STS;
using Xunit;

namespace Sufficit.Identity.Tests;

public sealed class DeploymentTopologyTests
{
    [Theory]
    [InlineData("https://localhost:5001/")]
    [InlineData("https://127.0.0.1/")]
    [InlineData("https://[::1]:5001/")]
    [InlineData("https://identity.localhost/")]
    [InlineData("https://sts.tests.local/")]
    [InlineData("https://identity.test/")]
    public void Development_accepts_local_hosts(string issuer)
    {
        var tolerated = DeploymentTopologyPolicy.ValidateDevelopmentHost(
            new SufficitIdentityOptions { Issuer = issuer, PublicUrl = issuer },
            vaultCertificatePath: null,
            isDevelopment: true);

        Assert.False(tolerated);
    }

    [Fact]
    public void Development_refuses_a_public_issuer()
    {
        var error = Assert.Throws<InvalidOperationException>(() =>
            DeploymentTopologyPolicy.ValidateDevelopmentHost(
                new SufficitIdentityOptions { Issuer = "https://identity.example.com/" },
                vaultCertificatePath: null,
                isDevelopment: true));

        Assert.Contains("identity.example.com", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Development_refuses_production_certificate_material()
    {
        Assert.Throws<InvalidOperationException>(() =>
            DeploymentTopologyPolicy.ValidateDevelopmentHost(
                new SufficitIdentityOptions
                {
                    Issuer = "https://localhost:5001/",
                    Certificates = new CertificatesOptions { SigningPath = "/etc/identity/signing.pfx" },
                },
                vaultCertificatePath: null,
                isDevelopment: true));

        Assert.Throws<InvalidOperationException>(() =>
            DeploymentTopologyPolicy.ValidateDevelopmentHost(
                new SufficitIdentityOptions { Issuer = "https://localhost:5001/" },
                vaultCertificatePath: "/run/secrets/vault-kek.pfx",
                isDevelopment: true));
    }

    [Fact]
    public void Explicit_override_tolerates_a_public_development_host()
    {
        var tolerated = DeploymentTopologyPolicy.ValidateDevelopmentHost(
            new SufficitIdentityOptions
            {
                Issuer = "https://identity-dev.example.com/",
                AllowDevelopmentOnPublicHost = true,
            },
            vaultCertificatePath: null,
            isDevelopment: true);

        Assert.True(tolerated);
    }

    [Fact]
    public void Non_development_environments_are_not_affected()
    {
        var tolerated = DeploymentTopologyPolicy.ValidateDevelopmentHost(
            new SufficitIdentityOptions
            {
                Issuer = "https://identity.example.com/",
                Certificates = new CertificatesOptions { SigningPath = "/etc/identity/signing.pfx" },
            },
            vaultCertificatePath: "/run/secrets/vault-kek.pfx",
            isDevelopment: false);

        Assert.False(tolerated);
    }

    [Fact]
    public void Single_replica_keeps_compatibility_defaults()
    {
        DeploymentTopologyPolicy.Validate(
            new SufficitIdentityOptions(),
            trustedProxyCount: 0,
            isDevelopment: false);
    }

    [Theory]
    [InlineData(DeploymentTopology.Clustered)]
    [InlineData(DeploymentTopology.ClusteredBehindTrustedProxy)]
    public void Clustered_topology_requires_shared_state(
        DeploymentTopology topology)
    {
        var options = new SufficitIdentityOptions
        {
            DeploymentTopology = topology,
            Issuer = "https://identity.example.test/",
            DistributedCache = new DistributedCacheOptions { RequireShared = false },
            RateLimit = new RateLimitOptions { FailOnUntrustedProxy = true },
        };

        var exception = Assert.Throws<InvalidOperationException>(() =>
            DeploymentTopologyPolicy.Validate(options, trustedProxyCount: 1, isDevelopment: false));

        Assert.Contains("RequireShared=true", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Trusted_proxy_topology_requires_explicit_proxy_boundary()
    {
        var options = new SufficitIdentityOptions
        {
            DeploymentTopology = DeploymentTopology.BehindTrustedProxy,
            Issuer = "https://identity.example.test/",
            RateLimit = new RateLimitOptions { FailOnUntrustedProxy = false },
        };

        var exception = Assert.Throws<InvalidOperationException>(() =>
            DeploymentTopologyPolicy.Validate(options, trustedProxyCount: 1, isDevelopment: false));

        Assert.Contains("FailOnUntrustedProxy=true", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Clustered_proxy_topology_accepts_coherent_production_contract()
    {
        DeploymentTopologyPolicy.Validate(
            new SufficitIdentityOptions
            {
                DeploymentTopology = DeploymentTopology.ClusteredBehindTrustedProxy,
                Issuer = "https://identity.example.test/",
                DistributedCache = new DistributedCacheOptions { RequireShared = true },
                RateLimit = new RateLimitOptions { FailOnUntrustedProxy = true },
            },
            trustedProxyCount: 2,
            isDevelopment: false);
    }

    [Fact]
    public void Clustered_topology_accepts_shared_state_and_stable_issuer()
    {
        DeploymentTopologyPolicy.Validate(
            new SufficitIdentityOptions
            {
                DeploymentTopology = DeploymentTopology.Clustered,
                Issuer = "https://identity.example.test/",
                DistributedCache = new DistributedCacheOptions { RequireShared = true },
            },
            trustedProxyCount: 0,
            isDevelopment: false);
    }

    [Fact]
    public void Trusted_proxy_topology_accepts_explicit_forwarding_boundary()
    {
        DeploymentTopologyPolicy.Validate(
            new SufficitIdentityOptions
            {
                DeploymentTopology = DeploymentTopology.BehindTrustedProxy,
                Issuer = "https://identity.example.test/",
                RateLimit = new RateLimitOptions { FailOnUntrustedProxy = true },
            },
            trustedProxyCount: 1,
            isDevelopment: false);
    }
}
