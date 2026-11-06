using System.Diagnostics;
using System.Threading.Channels;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using Sufficit.Identity.Core.Sessions;
using Sufficit.Identity.Server;
using Xunit;
using static Sufficit.Identity.Tests.TrustedProxySynchronizationTests;

namespace Sufficit.Identity.Tests;

public sealed partial class SessionValidityCacheIntegrationTests
{
    [LocalBrokerFact]
    public async Task Real_notifications_resume_after_broker_outage_without_extending_missed_revocation_window()
    {
        var container = Environment.GetEnvironmentVariable("IDENTITY_TEST_NATS_CONTAINER")!;
        Assert.StartsWith("identity-proxy-sync-tests-", container);
        var url = Environment.GetEnvironmentVariable("IDENTITY_TEST_NATS_URL")!;
        var endpoint = new Uri(url);
        Assert.True(endpoint.IsLoopback, "The fault-injection broker must be local.");
        var verifiedAt = DateTimeOffset.UtcNow;
        var clock = new CacheClock(verifiedAt);
        var caches = Enumerable.Range(0, 2).Select(_ => new NotifyingCache(clock)).ToArray();
        var logs = caches.Select(_ => new SignalingLogger<UserSecurityNatsBridge>()).ToArray();
        var subject = "identity.tests.user-security." + Guid.NewGuid().ToString("N");
        var bridges = caches.Select((cache, i) => new UserSecurityNatsBridge(
            Options.Create(new UserSecurityNatsOptions
            {
                Enabled = true, Url = url, Token = "identity-test-token", Subject = subject,
            }), cache, new NatsEnvironment(), logs[i])).ToArray();
        try
        {
            foreach (var bridge in bridges) await bridge.StartAsync(default);
            await Task.WhenAll(bridges.Select((b, i) => logs[i].WaitFor(() => b.Connected))).WaitAsync(TimeSpan.FromSeconds(45));

            var delivered = await IssueTicketAsync(verifiedAt);
            var deliveredUser = await SubjectOfAsync(delivered);
            foreach (var cache in caches) cache.MarkVerified(deliveredUser);
            await RotateSecurityStampAsync(delivered);
            Assert.True(await bridges[0].PublishAsync(deliveredUser, default));
            await caches[1].WaitForInvalidation(deliveredUser);
            Assert.Null((await ValidateAsync(delivered, caches[1], bridges[1])).Principal);

            var missed = await IssueTicketAsync(verifiedAt);
            var missedUser = await SubjectOfAsync(missed);
            foreach (var cache in caches) cache.MarkVerified(missedUser);
            await Broker("stop", container);
            await Task.WhenAll(bridges.Select((b, i) => logs[i].WaitFor(() => !b.Connected))).WaitAsync(TimeSpan.FromSeconds(45));
            await RotateSecurityStampAsync(missed);
            Assert.False(await bridges[0].PublishAsync(missedUser, default));
            Assert.Null((await ValidateAsync(missed, caches[1], bridges[1])).Principal);

            await Broker("start", container);
            await Task.WhenAll(bridges.Select((b, i) => logs[i].WaitFor(() => b.Connected))).WaitAsync(TimeSpan.FromSeconds(45));
            // Core notifications are best effort: no missed invalidation was queued.
            clock.Now = verifiedAt.AddSeconds(29);
            Assert.NotNull((await ValidateAsync(missed, caches[1], bridges[1])).Principal);
            clock.Now = verifiedAt.AddSeconds(30);
            Assert.Null((await ValidateAsync(missed, caches[1], bridges[1])).Principal);

            // A newly subscribed bridge must also deliver subsequent messages.
            var recovered = await IssueTicketAsync(clock.Now);
            var recoveredUser = await SubjectOfAsync(recovered);
            foreach (var cache in caches) cache.MarkVerified(recoveredUser);
            await RotateSecurityStampAsync(recovered);
            Assert.True(await bridges[0].PublishAsync(recoveredUser, default));
            await caches[1].WaitForInvalidation(recoveredUser);
            Assert.Null((await ValidateAsync(recovered, caches[1], bridges[1])).Principal);
        }
        finally
        {
            foreach (var bridge in bridges)
            {
                await bridge.StopAsync(CancellationToken.None);
                bridge.Dispose();
            }
        }
    }

    [LocalBrokerFact]
    public async Task Isolated_node_misses_invalidation_while_peers_remain_connected_and_recovers_with_bounded_staleness()
    {
        var endpoint = new Uri(Environment.GetEnvironmentVariable("IDENTITY_TEST_NATS_URL")!);
        Assert.True(endpoint.IsLoopback);
        await using var relay = new Infrastructure.InterruptibleTcpRelay(endpoint);
        var verifiedAt = DateTimeOffset.UtcNow;
        var clock = new CacheClock(verifiedAt);
        var caches = Enumerable.Range(0, 3).Select(_ => new NotifyingCache(clock)).ToArray();
        var logs = caches.Select(_ => new SignalingLogger<UserSecurityNatsBridge>()).ToArray();
        var subject = "identity.tests.isolated-user-security." + Guid.NewGuid().ToString("N");
        var bridges = caches.Select((cache, i) => new UserSecurityNatsBridge(
            Options.Create(new UserSecurityNatsOptions
            {
                Enabled = true,
                Url = i == 1 ? $"nats://127.0.0.1:{relay.Port}" : endpoint.ToString(),
                Token = "identity-test-token", Subject = subject,
            }), cache, new NatsEnvironment(), logs[i])).ToArray();
        try
        {
            foreach (var bridge in bridges) await bridge.StartAsync(default);
            await Task.WhenAll(bridges.Select((b, i) => logs[i].WaitFor(() => b.Connected)))
                .WaitAsync(TimeSpan.FromSeconds(45));
            var ticket = await IssueTicketAsync(verifiedAt);
            var user = await SubjectOfAsync(ticket);
            foreach (var cache in caches) cache.MarkVerified(user);

            relay.Cut();
            await logs[1].WaitFor(() => !bridges[1].Connected).WaitAsync(TimeSpan.FromSeconds(45));
            await RotateSecurityStampAsync(ticket);
            Assert.True(await bridges[0].PublishAsync(user, default));
            await caches[2].WaitForInvalidation(user);
            Assert.True(bridges[0].Connected);
            Assert.True(bridges[2].Connected);
            Assert.False(bridges[1].Connected);
            Assert.False(caches[1].IsRevalidationNeeded(user, verifiedAt));
            Assert.Null((await ValidateAsync(ticket, caches[2], bridges[2])).Principal);
            Assert.Null((await ValidateAsync(ticket, caches[1], bridges[1])).Principal);

            relay.Restore();
            await logs[1].WaitFor(() => bridges[1].Connected).WaitAsync(TimeSpan.FromSeconds(45));
            clock.Now = verifiedAt.AddSeconds(29);
            Assert.NotNull((await ValidateAsync(ticket, caches[1], bridges[1])).Principal);
            clock.Now = verifiedAt.AddSeconds(30);
            Assert.Null((await ValidateAsync(ticket, caches[1], bridges[1])).Principal);

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
            foreach (var bridge in bridges)
            {
                await bridge.StopAsync(CancellationToken.None);
                bridge.Dispose();
            }
        }
    }

    private sealed class NotifyingCache(TimeProvider clock) : ISessionValidityCache
    {
        private readonly InMemorySessionValidityCache inner = new(TimeSpan.FromSeconds(30), clock);
        private readonly Channel<string> invalidations = Channel.CreateUnbounded<string>();
        public bool IsRevalidationNeeded(string userId, DateTimeOffset verifiedAt) => inner.IsRevalidationNeeded(userId, verifiedAt);
        public void MarkVerified(string userId) => inner.MarkVerified(userId);
        public void Invalidate(string userId)
        {
            inner.Invalidate(userId);
            invalidations.Writer.TryWrite(userId);
        }
        public async Task WaitForInvalidation(string userId)
        {
            while (await invalidations.Reader.ReadAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(30)) != userId) { }
        }
    }

    private static async Task Broker(string action, string container)
    {
        var info = new ProcessStartInfo("docker") { RedirectStandardOutput = true, RedirectStandardError = true };
        info.ArgumentList.Add(action);
        info.ArgumentList.Add(container);
        using var process = Process.Start(info)!;
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(30));
        await stdout;
        Assert.True(process.ExitCode == 0, await stderr);
    }

    private sealed class NatsEnvironment : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = "Testing";
        public string ApplicationName { get; set; } = "Identity.Tests";
        public string ContentRootPath { get; set; } = "/tmp";
        public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
    }
}
