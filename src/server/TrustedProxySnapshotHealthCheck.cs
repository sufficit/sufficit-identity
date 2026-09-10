using Microsoft.Extensions.Diagnostics.HealthChecks;
using Sufficit.Identity.Core.Networking;

namespace Sufficit.Identity.Server;

internal sealed class TrustedProxySnapshotHealthCheck(TrustedProxySnapshotStore snapshots) : IHealthCheck
{
    public Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context,
        CancellationToken cancellationToken = default) => Task.FromResult(snapshots.IsFresh
            ? HealthCheckResult.Healthy()
            : HealthCheckResult.Unhealthy("Trusted proxy configuration has not been confirmed within its freshness limit."));
}
