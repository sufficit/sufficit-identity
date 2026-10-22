using System.Collections.Concurrent;
using System.Diagnostics.Metrics;
using Sufficit.Identity.Core.Metrics;

namespace Sufficit.Identity.STS.Metrics;

/// <summary>
/// Usage metrics as in-memory counters per UTC day and dimension. Recording
/// is a dictionary increment: no I/O, no waiting, so it never extends
/// authentication. The worker drains the counters periodically into the
/// daily aggregate and the optional export.
/// </summary>
/// <remarks>
/// The client id of a failed request comes from the caller, so the number of
/// distinct keys is capped (<see cref="MaximumKeys"/>): past it new
/// combinations are dropped and counted as such, never allowed to grow memory.
/// </remarks>
internal sealed class IdentityUsageCounters : IIdentityUsageMetricSink
{
    internal const int MaximumKeys = 10_000;
    private static readonly Meter Meter = new("Sufficit.Identity.Metrics", "1.0.0");
    private static readonly Counter<long> UsageCounter = Meter.CreateCounter<long>(
        "identity.application.usage", description: "Uses of OAuth/OIDC applications by client, endpoint, grant and outcome.");
    private static readonly Counter<long> DroppedCounter = Meter.CreateCounter<long>("identity.metrics.dropped");
    private readonly IdentityMetricsRuntimeState _runtime;
    private ConcurrentDictionary<IdentityUsageKey, IdentityUsageTally> _current = new();

    public IdentityUsageCounters(IdentityMetricsRuntimeState runtime) => _runtime = runtime;

    public bool TryRecord(IdentityUsageMetric metric)
    {
        var key = IdentityUsageKey.From(metric);
        var counters = Volatile.Read(ref _current);
        if (!counters.TryGetValue(key, out var tally))
        {
            if (counters.Count >= MaximumKeys)
            {
                _runtime.DroppedOne();
                DroppedCounter.Add(1);
                return false;
            }

            tally = counters.GetOrAdd(key, _ => new IdentityUsageTally());
        }

        tally.Add(metric.OccurredAtUtc);
        _runtime.AcceptedOne();
        _runtime.SetQueueDepth(counters.Count);
        UsageCounter.Add(1,
            new KeyValuePair<string, object?>("client_id", key.ClientId),
            new KeyValuePair<string, object?>("event_type", key.EventType),
            new KeyValuePair<string, object?>("endpoint_type", key.EndpointType),
            new KeyValuePair<string, object?>("grant_type", key.GrantType),
            new KeyValuePair<string, object?>("outcome", key.Outcome));
        return true;
    }

    /// <summary>Takes everything counted so far and starts over.</summary>
    internal IReadOnlyList<(IdentityUsageKey Key, long Count, DateTime LastOccurredAtUtc)> Drain()
    {
        var drained = Interlocked.Exchange(ref _current, new ConcurrentDictionary<IdentityUsageKey, IdentityUsageTally>());
        _runtime.SetQueueDepth(0);
        return drained.Select(item => (item.Key, item.Value.Count, item.Value.LastOccurredAtUtc))
            .Where(item => item.Count > 0)
            .ToArray();
    }

    /// <summary>Puts back what could not be persisted, so a failed flush loses nothing.</summary>
    internal void Restore(IEnumerable<(IdentityUsageKey Key, long Count, DateTime LastOccurredAtUtc)> items)
    {
        var counters = Volatile.Read(ref _current);
        foreach (var (key, count, last) in items)
            counters.GetOrAdd(key, _ => new IdentityUsageTally()).Add(last, count);
        _runtime.SetQueueDepth(counters.Count);
    }
}

internal readonly record struct IdentityUsageKey(
    DateTime Day, string ClientId, string EventType, string EndpointType, string GrantType, string Outcome)
{
    public static IdentityUsageKey From(IdentityUsageMetric metric) => new(
        metric.OccurredAtUtc.Date,
        metric.ClientId,
        metric.EventType,
        metric.EndpointType,
        metric.GrantType ?? string.Empty,
        metric.Outcome);
}

internal sealed class IdentityUsageTally
{
    private long _count;
    private long _lastTicks;

    public long Count => Interlocked.Read(ref _count);
    public DateTime LastOccurredAtUtc => new(Interlocked.Read(ref _lastTicks), DateTimeKind.Utc);

    public void Add(DateTime occurredAtUtc, long count = 1)
    {
        Interlocked.Add(ref _count, count);
        var ticks = occurredAtUtc.Ticks;
        long seen;
        while (ticks > (seen = Interlocked.Read(ref _lastTicks))
            && Interlocked.CompareExchange(ref _lastTicks, ticks, seen) != seen)
        {
        }
    }
}
