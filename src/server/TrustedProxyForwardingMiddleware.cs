using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.Extensions.Options;
using Sufficit.Identity.Core.Networking;

namespace Sufficit.Identity.Server;

/// <summary>
/// Applies X-Forwarded-* from the proxies the snapshot store currently trusts.
/// Replaces the framework's fixed startup options with a middleware instance
/// per immutable snapshot, without mutating options used by concurrent requests.
/// </summary>
/// <remarks>
/// Which list is trusted is decided by
/// <see cref="TrustedProxySnapshotStore.ResolveForwarding"/>; this type only
/// applies the decision. When the database list is stale the store answers
/// with the file-configured baseline, or — in Reject mode — with no snapshot,
/// in which case traffic is refused but liveness is still answered.
/// </remarks>
internal sealed class TrustedProxyForwardingMiddleware(
    RequestDelegate next, TrustedProxySnapshotStore snapshots, ILoggerFactory loggerFactory)
{
    private readonly object gate = new();
    private readonly ILogger logger =
        loggerFactory.CreateLogger<TrustedProxyForwardingMiddleware>();
    private Forwarder? current;
    private int lastState = (int)TrustedProxySnapshotState.Fresh;

    public Task InvokeAsync(HttpContext context)
    {
        var forwarding = snapshots.ResolveForwarding();
        ReportTransition(forwarding.State);

        if (forwarding.Snapshot is not { } snapshot)
        {
            // Refusing liveness would make an orchestrator restart a process
            // whose only problem is a database it cannot fix by restarting.
            if (HealthEndpoints.IsLiveness(context.Request.Path))
                return next(context);

            context.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
            return Task.CompletedTask;
        }

        var forwarder = Volatile.Read(ref current);
        if (forwarder is null || !ReferenceEquals(forwarder.Snapshot, snapshot))
        {
            lock (gate)
            {
                forwarder = current;
                if (forwarder is null || !ReferenceEquals(forwarder.Snapshot, snapshot))
                {
                    var options = new ForwardedHeadersOptions
                    {
                        ForwardedHeaders = ForwardedHeaders.XForwardedFor
                            | ForwardedHeaders.XForwardedProto | ForwardedHeaders.XForwardedHost,
                        ForwardLimit = snapshot.ForwardLimit,
                    };
                    // Preserve framework loopback trust when no proxies are configured.
                    if (!snapshot.EffectiveNetworks.IsEmpty)
                    {
                        options.KnownProxies.Clear();
                        options.KnownIPNetworks.Clear();
                        foreach (var cidr in snapshot.EffectiveNetworks)
                            options.KnownIPNetworks.Add(System.Net.IPNetwork.Parse(cidr));
                    }
                    forwarder = new(snapshot, new ForwardedHeadersMiddleware(next,
                        loggerFactory, Options.Create(options)));
                    Volatile.Write(ref current, forwarder);
                }
            }
        }
        return forwarder.Middleware.Invoke(context);
    }

    /// <summary>Logs state changes once, not once per request.</summary>
    private void ReportTransition(TrustedProxySnapshotState state)
    {
        var previous = (TrustedProxySnapshotState)Interlocked.Exchange(
            ref lastState,
            (int)state);
        if (previous == state)
            return;

        switch (state)
        {
            case TrustedProxySnapshotState.StaleFileBaseline:
                logger.LogWarning(
                    "Trusted proxy configuration is stale; forwarding now trusts only the file-configured proxies until the database confirms the list again.");
                break;
            case TrustedProxySnapshotState.StaleRejected:
                logger.LogError(
                    "Trusted proxy configuration is stale and StaleSnapshotMode=Reject; refusing traffic until the database confirms the list again.");
                break;
            default:
                logger.LogInformation(
                    "Trusted proxy configuration confirmed again; forwarding restored to the full list.");
                break;
        }
    }

    private sealed record Forwarder(TrustedProxySnapshot Snapshot, ForwardedHeadersMiddleware Middleware);
}
