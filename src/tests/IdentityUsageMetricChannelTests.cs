using System.Diagnostics;
using Sufficit.Identity.Core.Metrics;
using Sufficit.Identity.STS.Metrics;
using Xunit;

namespace Sufficit.Identity.Tests;

public sealed class IdentityUsageMetricChannelTests
{
    [Fact]
    public void Full_collector_drops_without_blocking_authentication()
    {
        var runtime = new IdentityMetricsRuntimeState();
        var channel = new IdentityUsageMetricChannel(runtime);
        var metric = new IdentityUsageMetric(
            DateTime.UtcNow, "client", "token_issued", "token",
            "client_credentials", "succeeded", null);

        for (var index = 0; index < IdentityUsageMetricChannel.Capacity; index++)
            Assert.True(channel.TryRecord(metric));

        var stopwatch = Stopwatch.StartNew();
        Assert.False(channel.TryRecord(metric));
        stopwatch.Stop();

        Assert.True(stopwatch.Elapsed < TimeSpan.FromMilliseconds(50));
        Assert.Equal(IdentityUsageMetricChannel.Capacity, runtime.Accepted);
        Assert.Equal(1, runtime.Dropped);
        Assert.Equal(IdentityUsageMetricChannel.Capacity, runtime.QueueDepth);
    }
}
