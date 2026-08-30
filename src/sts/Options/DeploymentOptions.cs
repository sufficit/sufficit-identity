using Sufficit.Identity.Application.Security;

namespace Sufficit.Identity.STS;

/// <summary>
/// Distributed-cache policy for multi-replica deployments. Several security-
/// critical stores (DPoP replay cache + nonce store, CIBA pending requests,
/// front-channel logout context, passkey ceremony tickets) depend on
/// <c>IDistributedCache</c>. The default registration is
/// <c>AddDistributedMemoryCache</c> (single-node, in-process) — correct for a
/// single replica, but in a multi-replica deployment each replica has its own
/// isolated cache, so DPoP replay detection, CIBA cross-replica polling and
/// nonce challenges silently break. This option lets an operator make the
/// requirement explicit so the process fails fast instead of running with a
/// degraded security posture.
/// </summary>
public sealed class DistributedCacheOptions
{
    /// <summary>
    /// When <c>true</c> outside Development, the STS fails to start if the
    /// registered <c>IDistributedCache</c> is the in-memory fallback
    /// (<c>MemoryDistributedCache</c>), because that backend is not shared
    /// across replicas. Default <c>false</c> (warning only) — flip to
    /// <c>true</c> before deploying more than one replica so a missing Redis
    /// (or other shared cache) cannot silently disable DPoP replay protection
    /// and CIBA cross-replica flows.
    /// </summary>
    public bool RequireShared { get; init; } = false;
}
/// <summary>
/// Supported hosting shapes for security-sensitive state and forwarded
/// headers.  This is deliberately an enum so configuration cannot silently
/// invent a fourth topology with incompatible assumptions.
/// </summary>
public enum DeploymentTopology
{
    SingleReplica,
    Clustered,
    BehindTrustedProxy,
    ClusteredBehindTrustedProxy,
}
/// <summary>
/// Startup contract for the selected deployment topology.
/// </summary>
public static class DeploymentTopologyPolicy
{
    public static void Validate(
        SufficitIdentityOptions options,
        int trustedProxyCount,
        bool isDevelopment)
    {
        ArgumentNullException.ThrowIfNull(options);

        var clustered = options.DeploymentTopology is
            DeploymentTopology.Clustered or
            DeploymentTopology.ClusteredBehindTrustedProxy;
        var behindProxy = options.DeploymentTopology is
            DeploymentTopology.BehindTrustedProxy or
            DeploymentTopology.ClusteredBehindTrustedProxy;

        if (clustered && !options.DistributedCache.RequireShared)
        {
            throw new InvalidOperationException(
                $"Sufficit:Identity:DeploymentTopology={options.DeploymentTopology} " +
                "requires Sufficit:Identity:DistributedCache:RequireShared=true " +
                "because DPoP, CIBA, logout and passkey state must be shared.");
        }

        if (behindProxy)
        {
            if (!isDevelopment && trustedProxyCount == 0)
            {
                throw new InvalidOperationException(
                    $"Sufficit:Identity:DeploymentTopology={options.DeploymentTopology} " +
                    "requires at least one configured Sufficit:Identity:TrustedProxies entry.");
            }

            if (!options.RateLimit.FailOnUntrustedProxy)
            {
                throw new InvalidOperationException(
                    $"Sufficit:Identity:DeploymentTopology={options.DeploymentTopology} " +
                    "requires RateLimit:FailOnUntrustedProxy=true so a missing proxy " +
                    "trust boundary cannot degrade into a shared rate-limit bucket.");
            }

            if (!Uri.TryCreate(options.Issuer, UriKind.Absolute, out var issuer) ||
                issuer.Scheme != Uri.UriSchemeHttps)
            {
                throw new InvalidOperationException(
                    $"Sufficit:Identity:DeploymentTopology={options.DeploymentTopology} " +
                    "requires an explicit HTTPS Sufficit:Identity:Issuer.");
            }
        }

        if (clustered && !Uri.TryCreate(options.Issuer, UriKind.Absolute, out _))
        {
            throw new InvalidOperationException(
                $"Sufficit:Identity:DeploymentTopology={options.DeploymentTopology} " +
                "requires an explicit absolute Sufficit:Identity:Issuer for stable " +
                "cross-replica discovery and token validation.");
        }
    }
}
