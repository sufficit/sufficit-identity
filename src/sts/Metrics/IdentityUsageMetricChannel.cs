using System.Diagnostics.Metrics;
using System.Threading.Channels;
using Sufficit.Identity.Core.Metrics;

namespace Sufficit.Identity.STS.Metrics;

internal sealed class IdentityUsageMetricChannel : IIdentityUsageMetricSink
{
    internal const int Capacity = 50_000;
    private static readonly Meter Meter = new("Sufficit.Identity.Metrics", "1.0.0");
    private static readonly Counter<long> AcceptedCounter = Meter.CreateCounter<long>("identity.metrics.accepted");
    private static readonly Counter<long> DroppedCounter = Meter.CreateCounter<long>("identity.metrics.dropped");
    private readonly IdentityMetricsRuntimeState _runtime;

    public IdentityUsageMetricChannel(IdentityMetricsRuntimeState runtime)
    {
        _runtime = runtime;
        Channel = System.Threading.Channels.Channel.CreateBounded<IdentityUsageMetric>(
            new BoundedChannelOptions(Capacity)
            {
                SingleReader = true,
                SingleWriter = false,
                FullMode = BoundedChannelFullMode.Wait,
                AllowSynchronousContinuations = false
            });
    }

    internal Channel<IdentityUsageMetric> Channel { get; }

    public bool TryRecord(IdentityUsageMetric metric)
    {
        if (Channel.Writer.TryWrite(metric))
        {
            _runtime.AcceptedOne();
            _runtime.SetQueueDepth(Channel.Reader.Count);
            AcceptedCounter.Add(1);
            return true;
        }

        _runtime.DroppedOne();
        DroppedCounter.Add(1);
        return false;
    }
}
