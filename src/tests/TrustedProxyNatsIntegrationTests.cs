using System.Diagnostics;
using Microsoft.Extensions.Logging.Abstractions;
using Sufficit.Identity.Server;
using Xunit;
using static Sufficit.Identity.Tests.TrustedProxySynchronizationTests;

namespace Sufficit.Identity.Tests;

public sealed class TrustedProxyNatsIntegrationTests
{
    [LocalBrokerFact]
    public async Task Three_nodes_recover_initial_failure_delayed_replication_and_lost_notification_after_reconnect()
    {
        var container = Environment.GetEnvironmentVariable("IDENTITY_TEST_NATS_CONTAINER")!;
        Assert.StartsWith("identity-proxy-sync-tests-", container);
        var url = Environment.GetEnvironmentVariable("IDENTITY_TEST_NATS_URL")!;
        var subject = "sufficit.testing.identity.trusted-proxies.changed." + Guid.NewGuid().ToString("N");
        var signals = Enumerable.Range(0, 3).Select(_ => new TrustedProxyRefreshSignal()).ToArray();
        var bridgeLogs = signals.Select(_ => new SignalingLogger<TrustedProxyNatsBridge>()).ToArray();
        var workerLogs = signals.Select(_ => new SignalingLogger<TrustedProxyRefreshWorker>()).ToArray();
        var bridges = signals.Select((s, i) => Bridge(s, new TrustedProxyNatsOptions
        { Enabled = true, Url = url, Token = "identity-test-token", Subject = subject }, bridgeLogs[i])).ToArray();
        var nodes = new[] { await Node.Create(bridges[0], 60), await Node.Create(bridges[1], 60), await Node.Create(bridges[2], 60) };
        var workers = nodes.Select((n, i) => new TrustedProxyRefreshWorker(n.Store, signals[i], workerLogs[i])).ToArray();
        try
        {
            await Docker("stop", container); // Start subscriptions with broker unavailable.
            foreach (var worker in workers) await worker.StartAsync(CancellationToken.None);
            foreach (var bridge in bridges) await bridge.StartAsync(CancellationToken.None);
            foreach (var log in bridgeLogs) await log.WaitForMessage("unavailable");
            Assert.All(bridges, bridge => Assert.False(bridge.Connected));
            await Docker("start", container);
            await Task.WhenAll(bridges.Select((b, i) => bridgeLogs[i].WaitFor(() => b.Connected)));
            await Task.WhenAll(nodes.Select((n, i) => workerLogs[i].WaitFor(() => n.Store.Diagnostics.RevisionReads >= 2)));

            var revision = Guid.NewGuid().ToString("N");
            var reads = nodes[1].Store.Diagnostics.RevisionReads;
            await nodes[0].Store.CommitAsync(async _ => { await nodes[0].SetRow(revision); return Row(revision); });
            await workerLogs[1].WaitFor(() => nodes[1].Store.Diagnostics.RevisionReads > reads);
            Assert.Equal("initial", nodes[1].Store.Current.Revision); // Message never supplies authoritative content.
            await nodes[1].SetRow(revision);
            await nodes[2].SetRow(revision); // Simulated independent replica visibility after notification.
            await Task.WhenAll(nodes.Select((n, i) => workerLogs[i].WaitFor(() => n.Store.Current.Revision == revision)));
            Assert.All(nodes, n => Assert.Equal(2, n.Store.Current.ForwardLimit));

            await Docker("stop", container);
            await Task.WhenAll(bridges.Select((b, i) => bridgeLogs[i].WaitFor(() => !b.Connected)));
            var lostRevision = Guid.NewGuid().ToString("N");
            await nodes[0].Store.CommitAsync(async _ => { await nodes[0].SetRow(lostRevision); return Row(lostRevision); });
            Assert.True(nodes[0].Store.Diagnostics.NotificationPending);
            await nodes[1].SetRow(lostRevision);
            await nodes[2].SetRow(lostRevision);
            await Docker("start", container);
            await Task.WhenAll(bridges.Select((b, i) => bridgeLogs[i].WaitFor(() => b.Connected)));
            await Task.WhenAll(nodes.Select((n, i) => workerLogs[i].WaitFor(() => n.Store.Current.Revision == lostRevision)));
            Assert.All(nodes, n => Assert.True(n.Store.IsFresh));

            var generation = nodes[1].Store.Diagnostics.Generation;
            reads = nodes[1].Store.Diagnostics.RevisionReads;
            Assert.True(await bridges[0].PublishAsync(revision, CancellationToken.None)); // Old hint after newer commit.
            await workerLogs[1].WaitFor(() => nodes[1].Store.Diagnostics.RevisionReads > reads);
            Assert.Equal(lostRevision, nodes[1].Store.Current.Revision);
            Assert.Equal(generation, nodes[1].Store.Diagnostics.Generation);
        }
        finally
        {
            foreach (var worker in workers) { await worker.StopAsync(CancellationToken.None); worker.Dispose(); }
            foreach (var bridge in bridges) { await bridge.StopAsync(CancellationToken.None); bridge.Dispose(); }
            foreach (var node in nodes) await node.DisposeAsync();
        }
    }

    private static async Task Docker(string action, string container)
    {
        var info = new ProcessStartInfo("docker") { RedirectStandardOutput = true, RedirectStandardError = true };
        info.ArgumentList.Add(action);
        info.ArgumentList.Add(container);
        using var process = Process.Start(info)!;
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(20));
        await stdout;
        Assert.True(process.ExitCode == 0, await stderr);
    }
}

public sealed class LocalBrokerFactAttribute : FactAttribute
{
    public LocalBrokerFactAttribute()
    {
        if (Environment.GetEnvironmentVariable("IDENTITY_TEST_NATS_URL") is null
            || Environment.GetEnvironmentVariable("IDENTITY_TEST_NATS_CONTAINER") is null)
            Skip = "Requires a dedicated local identity-proxy-sync-tests-* NATS container (auth: identity-test-token).";
    }
}
