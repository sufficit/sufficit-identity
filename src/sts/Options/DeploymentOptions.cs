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
    /// <summary>
    /// Refuses to start a Development-environment host that looks like a real
    /// deployment: a public issuer or public URL, or production certificate
    /// material configured.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <c>ASPNETCORE_ENVIRONMENT=Development</c> unlocks ephemeral signing and
    /// encryption certificates, plaintext vault reads, cookies without the
    /// Secure flag, anonymous API documentation and a relaxed security posture
    /// check. A single environment variable copied from a staging unit file
    /// should not be able to turn all of that on for a server with a public
    /// issuer. Two independent signals that contradict each other fail the
    /// start instead of producing a warning nobody reads.
    /// </para>
    /// <para>
    /// A developer who genuinely runs Development on a public host sets
    /// <c>Sufficit:Identity:AllowDevelopmentOnPublicHost=true</c>. The method
    /// then returns <see langword="true"/> so the caller can log it.
    /// </para>
    /// </remarks>
    /// <returns>
    /// <see langword="true"/> when a contradiction was tolerated only because
    /// of the explicit override; otherwise <see langword="false"/>.
    /// </returns>
    public static bool ValidateDevelopmentHost(
        SufficitIdentityOptions options,
        string? vaultCertificatePath,
        bool isDevelopment)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (!isDevelopment)
        {
            return false;
        }

        var contradictions = new List<string>();
        foreach (var (name, value) in new[]
                 {
                     ("Sufficit:Identity:Issuer", options.Issuer),
                     ("Sufficit:Identity:PublicUrl", options.PublicUrl),
                 })
        {
            if (!string.IsNullOrWhiteSpace(value)
                && Uri.TryCreate(value, UriKind.Absolute, out var uri)
                && !IsLocalDevelopmentHost(uri.Host))
            {
                contradictions.Add($"{name} points at the public host '{uri.Host}'");
            }
        }

        var certificates = options.Certificates;
        if (!string.IsNullOrWhiteSpace(certificates.SigningPath)
            || certificates.SigningPaths.Any(path => !string.IsNullOrWhiteSpace(path))
            || !string.IsNullOrWhiteSpace(certificates.EncryptionPath)
            || certificates.EncryptionPaths.Any(path => !string.IsNullOrWhiteSpace(path)))
        {
            contradictions.Add("token signing or encryption certificates are configured");
        }

        if (!string.IsNullOrWhiteSpace(vaultCertificatePath))
        {
            contradictions.Add("a vault key-encryption certificate is configured");
        }

        if (contradictions.Count == 0)
        {
            return false;
        }

        if (options.AllowDevelopmentOnPublicHost)
        {
            return true;
        }

        throw new InvalidOperationException(
            "ASPNETCORE_ENVIRONMENT=Development is set, but this host is configured like a "
            + "real deployment: " + string.Join("; ", contradictions) + ". Development enables "
            + "ephemeral certificates and relaxed security checks, so the process refuses to "
            + "start. Use the correct environment name, or set "
            + "Sufficit:Identity:AllowDevelopmentOnPublicHost=true if this is intentional.");
    }

    /// <summary>
    /// Loopback addresses and the special-use names reserved for local and
    /// test use (RFC 6761, RFC 6762): localhost, *.localhost, *.local, *.test,
    /// *.invalid and *.example.
    /// </summary>
    internal static bool IsLocalDevelopmentHost(string host)
    {
        if (string.IsNullOrWhiteSpace(host))
        {
            return true;
        }

        var normalized = host.Trim().TrimEnd('.').Trim('[', ']').ToLowerInvariant();
        if (System.Net.IPAddress.TryParse(normalized, out var address))
        {
            return System.Net.IPAddress.IsLoopback(address);
        }

        if (normalized == "localhost")
        {
            return true;
        }

        return new[] { ".localhost", ".local", ".test", ".invalid", ".example" }
            .Any(suffix => normalized.EndsWith(suffix, StringComparison.Ordinal));
    }

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
