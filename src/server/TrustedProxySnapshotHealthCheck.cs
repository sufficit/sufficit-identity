using Microsoft.Extensions.Diagnostics.HealthChecks;
using Sufficit.Identity.Core.Networking;

namespace Sufficit.Identity.Server;

/// <summary>
/// Readiness signal for the trusted proxy list.
/// </summary>
/// <remarks>
/// A stale list that is being served from the file baseline is Degraded, which
/// readiness reports with 200: every replica shares the same database, so
/// failing readiness here would take all of them out of the load balancer at
/// once and turn a degraded state into an outage. Unhealthy is reserved for
/// Reject mode, where the node really is refusing traffic.
/// </remarks>
internal sealed class TrustedProxySnapshotHealthCheck(TrustedProxySnapshotStore snapshots) : IHealthCheck
{
    public Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context,
        CancellationToken cancellationToken = default) => Task.FromResult(snapshots.State switch
        {
            TrustedProxySnapshotState.Fresh => HealthCheckResult.Healthy(),
            TrustedProxySnapshotState.StaleFileBaseline => HealthCheckResult.Degraded(
                "Trusted proxy configuration has not been confirmed within its freshness limit; "
                + "forwarding trusts only the file-configured proxies."),
            _ => HealthCheckResult.Unhealthy(
                "Trusted proxy configuration has not been confirmed within its freshness limit; "
                + "traffic is refused (StaleSnapshotMode=Reject)."),
        });
}
