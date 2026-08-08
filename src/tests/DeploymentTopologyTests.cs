using Sufficit.Identity.STS;
using Xunit;

namespace Sufficit.Identity.Tests;

public sealed class DeploymentTopologyTests
{
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
