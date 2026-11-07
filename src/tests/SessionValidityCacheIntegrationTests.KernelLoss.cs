using System.Diagnostics;
using Microsoft.Extensions.Options;
using Sufficit.Identity.Server;
using Xunit;
using static Sufficit.Identity.Tests.TrustedProxySynchronizationTests;

namespace Sufficit.Identity.Tests;

public sealed partial class SessionValidityCacheIntegrationTests
{
    public sealed class KernelBrokerFactAttribute : FactAttribute
    {
        public KernelBrokerFactAttribute()
        {
            if (Environment.GetEnvironmentVariable("IDENTITY_TEST_NATS_NETNS_PID") is null)
                Skip = "Requires scripts/check-nats-kernel-loss.py and its owned broker network namespace.";
        }
    }

    [KernelBrokerFact]
    public async Task Kernel_packet_loss_preserves_cache_bound_then_heartbeat_disconnects_and_delivery_recovers()
    {
        var container = Environment.GetEnvironmentVariable("IDENTITY_TEST_NATS_CONTAINER")!;
        Assert.StartsWith("identity-proxy-sync-tests-", container);
        var pid = Environment.GetEnvironmentVariable("IDENTITY_TEST_NATS_NETNS_PID")!;
        Assert.True(int.TryParse(pid, out var parsed) && parsed > 1);
        Assert.Equal(pid, (await Run("docker", "inspect", "--format", "{{.State.Pid}}", container)).Trim());
        var url = Environment.GetEnvironmentVariable("IDENTITY_TEST_NATS_URL")!;
        Assert.True(new Uri(url).IsLoopback);
        var now = DateTimeOffset.UtcNow;
        var clock = new CacheClock(now);
        var caches = Enumerable.Range(0, 2).Select(_ => new NotifyingCache(clock)).ToArray();
        var logs = caches.Select(_ => new SignalingLogger<UserSecurityNatsBridge>()).ToArray();
        var subject = "identity.tests.kernel-loss." + Guid.NewGuid().ToString("N");
        var bridges = caches.Select((cache, i) => new UserSecurityNatsBridge(
            Options.Create(new UserSecurityNatsOptions { Enabled = true, Url = url,
                Token = "identity-test-token", Subject = subject }), cache, new NatsEnvironment(), logs[i])).ToArray();
        var impaired = false;
        try
        {
            foreach (var bridge in bridges) await bridge.StartAsync(default);
            await Task.WhenAll(bridges.Select((b, i) => logs[i].WaitFor(() => b.Connected))).WaitAsync(TimeSpan.FromSeconds(45));
            var initial = await IssueTicketAsync(now);
            var initialUser = await SubjectOfAsync(initial);
            caches[1].MarkVerified(initialUser);
            Assert.True(await bridges[0].PublishAsync(initialUser, default));
            await caches[1].WaitForInvalidation(initialUser);

            var missed = await IssueTicketAsync(now);
            var user = await SubjectOfAsync(missed);
            caches[1].MarkVerified(user);
            await Run("sudo", "-n", "nsenter", "-t", pid, "-n", "--", "tc", "qdisc", "add", "dev", "eth0", "root", "netem", "loss", "100%");
            impaired = true;
            Assert.Contains("loss 100%", await Run("sudo", "-n", "nsenter", "-t", pid, "-n", "--", "tc", "qdisc", "show", "dev", "eth0"));
            await RotateSecurityStampAsync(missed);
            await bridges[0].PublishAsync(user, default); // Transport acceptance is not delivery acknowledgement.
            clock.Now = now.AddSeconds(30);
            Assert.Null((await ValidateAsync(missed, caches[1], bridges[1])).Principal);
            // Production client heartbeat defaults, with a hang guard rather than a latency assertion.
            await Task.WhenAll(bridges.Select((b, i) => logs[i].WaitFor(() => !b.Connected, TimeSpan.FromMinutes(8)))).WaitAsync(TimeSpan.FromMinutes(8));
            Assert.False(await bridges[0].PublishAsync(user, default));
            Assert.Null((await ValidateAsync(missed, caches[1], bridges[1])).Principal);
            var statistics = await Run("sudo", "-n", "nsenter", "-t", pid, "-n", "--", "tc", "-s", "qdisc", "show", "dev", "eth0");
            var drops = System.Text.RegularExpressions.Regex.Match(statistics, @"dropped (\d+)");
            Assert.True(drops.Success && long.Parse(drops.Groups[1].Value) > 0, statistics);
            await Run("sudo", "-n", "nsenter", "-t", pid, "-n", "--", "tc", "qdisc", "del", "dev", "eth0", "root");
            impaired = false;
            await Task.WhenAll(bridges.Select((b, i) => logs[i].WaitFor(() => b.Connected))).WaitAsync(TimeSpan.FromSeconds(45));
            var recovered = await IssueTicketAsync(clock.Now);
            var recoveredUser = await SubjectOfAsync(recovered);
            caches[1].MarkVerified(recoveredUser);
            await RotateSecurityStampAsync(recovered);
            Assert.True(await bridges[0].PublishAsync(recoveredUser, default));
            await caches[1].WaitForInvalidation(recoveredUser);
            Assert.Null((await ValidateAsync(recovered, caches[1], bridges[1])).Principal);
        }
        finally
        {
            if (impaired) await Run("sudo", "-n", "nsenter", "-t", pid, "-n", "--", "tc", "qdisc", "del", "dev", "eth0", "root");
            foreach (var bridge in bridges) { await bridge.StopAsync(default); bridge.Dispose(); }
        }
    }

    private static async Task<string> Run(string executable, params string[] arguments)
    {
        var info = new ProcessStartInfo(executable) { RedirectStandardOutput = true, RedirectStandardError = true };
        foreach (var argument in arguments) info.ArgumentList.Add(argument);
        using var process = Process.Start(info)!;
        var output = process.StandardOutput.ReadToEndAsync();
        var error = process.StandardError.ReadToEndAsync();
        await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(30));
        Assert.True(process.ExitCode == 0, await error);
        return await output;
    }
}
