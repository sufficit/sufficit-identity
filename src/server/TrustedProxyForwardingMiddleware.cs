using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.Extensions.Options;
using Sufficit.Identity.Core.Networking;

namespace Sufficit.Identity.Server;

/// <summary>Replaces the framework's fixed startup options with a middleware
/// instance per immutable snapshot, without mutating options used by concurrent requests.</summary>
internal sealed class TrustedProxyForwardingMiddleware(
    RequestDelegate next, TrustedProxySnapshotStore snapshots, ILoggerFactory loggerFactory)
{
    private readonly object gate = new();
    private Forwarder? current;

    public Task InvokeAsync(HttpContext context)
    {
        if (!snapshots.IsFresh)
        {
            context.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
            return Task.CompletedTask;
        }
        var snapshot = snapshots.Current;
        var forwarder = Volatile.Read(ref current);
        if (forwarder is null || !ReferenceEquals(forwarder.Snapshot, snapshot))
        {
            lock (gate)
            {
                snapshot = snapshots.Current;
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

    private sealed record Forwarder(TrustedProxySnapshot Snapshot, ForwardedHeadersMiddleware Middleware);
}
