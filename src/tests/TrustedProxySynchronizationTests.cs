using System.Data.Common;
using System.Threading.Channels;
using Microsoft.Extensions.Logging;
using System.Net;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.Core.Networking;
using Sufficit.Identity.Server;
using Xunit;

namespace Sufficit.Identity.Tests;

public sealed class TrustedProxySynchronizationTests
{
    [Fact]
    public async Task Unchanged_revision_reads_only_scalar_and_renews_freshness()
    {
        await using var node = await Node.Create();
        var snapshot = node.Store.Current;
        node.Commands.Sql.Clear();
        // Unchanged revision must not download or deserialize the content.
        await node.SetRow("initial", "invalid-json");
        node.Commands.Sql.Clear();
        node.Clock.Advance(60);
        await node.Store.RefreshAsync();
        Assert.Same(snapshot, node.Store.Current);
        var sql = Assert.Single(node.Commands.Sql);
        Assert.Contains("SELECT", sql);
        Assert.Contains("revision", sql);
        Assert.DoesNotContain("networksjson", sql);
        Assert.Equal(1, node.Store.Diagnostics.ContentReads);
        Assert.Equal(node.Clock.GetUtcNow(), node.Store.Diagnostics.LastConfirmedAtUtc);
    }

    [Fact]
    public async Task Local_commit_applies_without_read_and_publishes_only_after_persistence()
    {
        var publisher = new Publisher();
        await using var node = await Node.Create(publisher);
        var revision = Guid.NewGuid().ToString("N");
        publisher.OnPublish = value =>
        {
            Assert.Equal(revision, value);
            Assert.Equal(revision, node.Store.Current.Revision);
            Assert.Empty(node.Commands.Sql);
        };
        await node.Store.CommitAsync(async ct =>
        {
            await node.SetRow(revision);
            node.Commands.Sql.Clear();
            return Row(revision);
        });
        Assert.Equal(1, publisher.Calls);
        Assert.Equal(revision, node.Store.Current.Revision);
        Assert.False(node.Store.Diagnostics.NotificationPending);
    }

    [Fact]
    public async Task Failed_commit_neither_changes_snapshot_nor_emits_event()
    {
        var publisher = new Publisher();
        await using var node = await Node.Create(publisher);
        var before = node.Store.Current;
        await Assert.ThrowsAsync<InvalidOperationException>(() => node.Store.CommitAsync(
            _ => throw new InvalidOperationException("transaction rolled back")));
        Assert.Same(before, node.Store.Current);
        Assert.Equal(0, publisher.Calls);
    }

    [Fact]
    public async Task Notification_failure_does_not_turn_successful_commit_into_failed_save()
    {
        var publisher = new Publisher { Fail = true };
        await using var node = await Node.Create(publisher);
        var revision = Guid.NewGuid().ToString("N");
        await node.Store.CommitAsync(async _ => { await node.SetRow(revision); return Row(revision); });
        Assert.Equal(revision, node.Store.Current.Revision);
        Assert.True(node.Store.Diagnostics.NotificationPending);
        await node.Store.RefreshAsync();
        Assert.Equal(revision, node.Store.Current.Revision);
    }

    [Fact]
    public async Task Concurrent_refresh_cannot_replace_a_later_local_commit()
    {
        await using var node = await Node.Create();
        node.Commands.BlockNext = true;
        var refresh = node.Store.RefreshAsync();
        await node.Commands.Entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
        var enteredCommit = false;
        var revision = Guid.NewGuid().ToString("N");
        var commit = node.Store.CommitAsync(async _ =>
        {
            enteredCommit = true;
            await node.SetRow(revision);
            return Row(revision);
        });
        Assert.False(enteredCommit);
        node.Commands.Release.TrySetResult();
        await Task.WhenAll(refresh, commit);
        Assert.Equal(revision, node.Store.Current.Revision);
        Assert.True(enteredCommit);
    }

    [Fact]
    public async Task Stale_snapshot_in_reject_mode_refuses_traffic_but_not_liveness_until_recovered()
    {
        await using var node = await Node.Create(staleMode: TrustedProxyStaleSnapshotMode.Reject);
        var before = node.Store.Current;
        await node.SetRow(Guid.NewGuid().ToString("N"), "invalid-json");
        await Assert.ThrowsAsync<JsonException>(() => node.Store.RefreshAsync());
        Assert.Same(before, node.Store.Current);
        node.Clock.Advance(121);
        var called = 0;
        var middleware = new TrustedProxyForwardingMiddleware(_ => { called++; return Task.CompletedTask; },
            node.Store, NullLoggerFactory.Instance);

        var traffic = new DefaultHttpContext();
        traffic.Request.Path = "/connect/token";
        await middleware.InvokeAsync(traffic);
        Assert.Equal(503, traffic.Response.StatusCode);
        Assert.Equal(0, called);

        // Refusing liveness would make an orchestrator restart a process whose
        // only problem is the database.
        var liveness = new DefaultHttpContext();
        liveness.Request.Path = "/health";
        await middleware.InvokeAsync(liveness);
        Assert.Equal(1, called);

        await node.SetRow(Guid.NewGuid().ToString("N"));
        await node.Store.RefreshAsync();
        await middleware.InvokeAsync(new DefaultHttpContext());
        Assert.Equal(2, called);
        Assert.Equal(0, node.Store.Diagnostics.ConsecutiveFailures);
    }

    [Fact]
    public async Task Stale_snapshot_degrades_to_file_proxies_instead_of_refusing_traffic()
    {
        // The database is where operators add proxies at runtime; the file is
        // the deployment's own baseline. When the database cannot confirm the
        // list, trusting fewer peers keeps the node serving without trusting a
        // proxy an operator may have just removed.
        await using var node = await Node.Create();
        var middleware = new TrustedProxyForwardingMiddleware(_ => Task.CompletedTask,
            node.Store, NullLoggerFactory.Instance);

        var viaDatabaseProxy = Forwarded("172.16.2.0", "198.51.100.7");
        await middleware.InvokeAsync(viaDatabaseProxy);
        Assert.Equal("198.51.100.7", viaDatabaseProxy.Connection.RemoteIpAddress!.ToString());

        node.Clock.Advance(121);
        Assert.Equal(TrustedProxySnapshotState.StaleFileBaseline, node.Store.State);

        var staleViaDatabaseProxy = Forwarded("172.16.2.0", "198.51.100.7");
        await middleware.InvokeAsync(staleViaDatabaseProxy);
        Assert.NotEqual(503, staleViaDatabaseProxy.Response.StatusCode);
        Assert.Equal("172.16.2.0", staleViaDatabaseProxy.Connection.RemoteIpAddress!.ToString());

        var staleViaFileProxy = Forwarded("127.0.0.1", "198.51.100.7");
        await middleware.InvokeAsync(staleViaFileProxy);
        Assert.Equal("198.51.100.7", staleViaFileProxy.Connection.RemoteIpAddress!.ToString());

        await node.SetRow(Guid.NewGuid().ToString("N"));
        await node.Store.RefreshAsync();
        var recovered = Forwarded("172.16.2.0", "198.51.100.7");
        await middleware.InvokeAsync(recovered);
        Assert.Equal("198.51.100.7", recovered.Connection.RemoteIpAddress!.ToString());
    }

    [Theory]
    [InlineData(TrustedProxyStaleSnapshotMode.FileBaseline, HealthStatus.Degraded)]
    [InlineData(TrustedProxyStaleSnapshotMode.Reject, HealthStatus.Unhealthy)]
    public async Task Readiness_reports_a_stale_list_by_mode(
        TrustedProxyStaleSnapshotMode mode,
        HealthStatus expectedWhenStale)
    {
        await using var node = await Node.Create(staleMode: mode);
        var check = new TrustedProxySnapshotHealthCheck(node.Store);

        Assert.Equal(
            HealthStatus.Healthy,
            (await check.CheckHealthAsync(new HealthCheckContext())).Status);

        node.Clock.Advance(121);

        Assert.Equal(
            expectedWhenStale,
            (await check.CheckHealthAsync(new HealthCheckContext())).Status);
    }

    [Fact]
    public async Task Bounded_notifications_reject_invalid_envelopes_and_never_accept_network_payload_as_authority()
    {
        var signal = new TrustedProxyRefreshSignal();
        using var bridge = Bridge(signal, new TrustedProxyNatsOptions());
        bridge.Receive("bad-json"u8.ToArray());
        bridge.Receive(new byte[2049]);
        bridge.Receive(JsonSerializer.SerializeToUtf8Bytes(new { schemaVersion = 1, networks = new[] { "0.0.0.0/0" } }));
        Assert.False(signal.Reader.TryRead(out _));
        var revision = Guid.NewGuid().ToString("N");
        for (var i = 0; i < 100; i++) bridge.Receive(Message(revision));
        Assert.True(signal.Reader.TryRead(out var value));
        Assert.Equal(revision, value);
        Assert.False(signal.Reader.TryRead(out _));
        await Task.CompletedTask;
    }

    [Fact]
    public async Task Periodic_revision_check_recovers_an_unnotified_change()
    {
        await using var node = await Node.Create(reconcileSeconds: 1);
        var signal = new TrustedProxyRefreshSignal();
        var logs = new SignalingLogger<TrustedProxyRefreshWorker>();
        using var worker = new TrustedProxyRefreshWorker(node.Store, signal, logs);
        await worker.StartAsync(CancellationToken.None);
        try
        {
            var revision = Guid.NewGuid().ToString("N");
            await node.SetRow(revision);
            await logs.WaitFor(() => node.Store.Current.Revision == revision);
        }
        finally { await worker.StopAsync(CancellationToken.None); }
    }

    [Fact]
    public async Task Event_before_replication_retries_and_out_of_order_hint_does_not_roll_back_content()
    {
        await using var node = await Node.Create(reconcileSeconds: 60);
        var signal = new TrustedProxyRefreshSignal();
        var logs = new SignalingLogger<TrustedProxyRefreshWorker>();
        using var worker = new TrustedProxyRefreshWorker(node.Store, signal, logs);
        await worker.StartAsync(CancellationToken.None);
        try
        {
            var revision = Guid.NewGuid().ToString("N");
            signal.Request(revision);
            await logs.WaitFor(() => node.Store.Diagnostics.RevisionReads >= 2);
            Assert.Equal("initial", node.Store.Current.Revision);
            await node.SetRow(revision);
            await logs.WaitFor(() => node.Store.Current.Revision == revision);
            var generation = node.Store.Diagnostics.Generation;
            signal.Request(Guid.NewGuid().ToString("N")); // obsolete/unobservable hint
            await logs.WaitFor(() => node.Store.Diagnostics.RevisionReads >= 4);
            Assert.Equal(revision, node.Store.Current.Revision);
            Assert.Equal(generation, node.Store.Diagnostics.Generation);
        }
        finally { await worker.StopAsync(CancellationToken.None); }
    }

    internal static byte[] Message(string revision) => JsonSerializer.SerializeToUtf8Bytes(
        new TrustedProxyChanged(1, Guid.NewGuid(), "remote-process", "trusted-proxies", "global", revision, DateTimeOffset.UtcNow),
        new JsonSerializerOptions(JsonSerializerDefaults.Web));

    internal static TrustedProxyNatsBridge Bridge(TrustedProxyRefreshSignal signal, TrustedProxyNatsOptions options,
        ILogger<TrustedProxyNatsBridge>? logger = null) =>
        new(Options.Create(options), signal, new EnvironmentStub(), logger ?? NullLogger<TrustedProxyNatsBridge>.Instance);

    internal sealed class SignalingLogger<T> : ILogger<T>
    {
        private readonly Channel<string> events = Channel.CreateUnbounded<string>();
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => true;
        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter) => events.Writer.TryWrite(formatter(state, exception));
        // Await actual work notifications; timeout only guards a broken test from hanging.
        public async Task WaitFor(Func<bool> predicate)
        {
            while (!predicate()) await events.Reader.ReadAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(30));
        }
        public async Task WaitForMessage(string text)
        {
            while (!(await events.Reader.ReadAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(30))).Contains(text)) { }
        }
    }

    private static DefaultHttpContext Forwarded(string peer, string forwardedFor)
    {
        var context = new DefaultHttpContext();
        context.Connection.RemoteIpAddress = IPAddress.Parse(peer);
        context.Request.Headers["X-Forwarded-For"] = forwardedFor;
        return context;
    }

    internal static TrustedProxyConfiguration Row(string revision, string networks = "[\"172.16.2.0/32\"]") =>
        new() { Revision = revision, NetworksJson = networks, UpdatedAtUtc = DateTime.UtcNow };

    internal sealed class Clock : TimeProvider
    {
        private DateTimeOffset now = DateTimeOffset.UtcNow;
        public override DateTimeOffset GetUtcNow() => now;
        public void Advance(int seconds) => now = now.AddSeconds(seconds);
    }

    internal sealed class Node : IAsyncDisposable
    {
        private readonly SqliteConnection connection;
        private readonly ServiceProvider services;
        public TrustedProxySnapshotStore Store { get; }
        public Commands Commands { get; }
        public Clock Clock { get; } = new();
        private Node(SqliteConnection connection, ServiceProvider services, Commands commands,
            ITrustedProxyChangePublisher? publisher, int reconcileSeconds, TrustedProxyStaleSnapshotMode staleMode)
        {
            this.connection = connection; this.services = services; Commands = commands;
            Store = new(services.GetRequiredService<IServiceScopeFactory>(), Options.Create(new TrustedProxyOptions
            { TrustedProxies = ["127.0.0.1/32"], ProxySynchronization = new()
                { ReconcileSeconds = reconcileSeconds, StaleSnapshotMode = staleMode } }),
                NullLogger<TrustedProxySnapshotStore>.Instance, publisher, Clock);
        }
        public static async Task<Node> Create(ITrustedProxyChangePublisher? publisher = null, int reconcileSeconds = 30,
            TrustedProxyStaleSnapshotMode staleMode = TrustedProxyStaleSnapshotMode.FileBaseline)
        {
            var connection = new SqliteConnection("Data Source=:memory:");
            await connection.OpenAsync();
            var commands = new Commands();
            var services = new ServiceCollection().AddDbContext<AppDbContext>(o =>
                o.UseSqlite(connection).UseOpenIddict().AddInterceptors(commands)).BuildServiceProvider();
            var node = new Node(connection, services, commands, publisher, reconcileSeconds, staleMode);
            using var scope = services.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
            await db.Database.ExecuteSqlRawAsync("CREATE TABLE trustedproxyconfiguration (id INTEGER PRIMARY KEY, networksjson TEXT NOT NULL, forwardlimit INTEGER NULL, revision TEXT NOT NULL, updatedatutc TEXT NOT NULL)");
            db.TrustedProxyConfigurations.Add(Row("initial"));
            await db.SaveChangesAsync();
            await node.Store.RefreshAsync();
            return node;
        }
        public async Task SetRow(string revision, string networks = "[\"172.16.2.0/32\"]")
        {
            using var scope = services.CreateScope();
            await scope.ServiceProvider.GetRequiredService<AppDbContext>().Database.ExecuteSqlInterpolatedAsync(
                $"UPDATE trustedproxyconfiguration SET revision={revision}, networksjson={networks}");
        }
        public async ValueTask DisposeAsync() { await services.DisposeAsync(); await connection.DisposeAsync(); }
    }

    internal sealed class Commands : DbCommandInterceptor
    {
        public List<string> Sql { get; } = [];
        public bool BlockNext;
        public TaskCompletionSource Entered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource Release { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public override async ValueTask<InterceptionResult<DbDataReader>> ReaderExecutingAsync(DbCommand command,
            CommandEventData eventData, InterceptionResult<DbDataReader> result, CancellationToken cancellationToken = default)
        {
            Sql.Add(command.CommandText);
            if (BlockNext)
            {
                BlockNext = false; Entered.TrySetResult();
                await Release.Task.WaitAsync(cancellationToken);
            }
            return result;
        }
    }

    private sealed class Publisher : ITrustedProxyChangePublisher
    {
        public bool Enabled => true;
        public bool Connected => !Fail;
        public int Calls;
        public bool Fail;
        public Action<string>? OnPublish;
        public Task<bool> PublishAsync(string revision, CancellationToken cancellationToken)
        {
            Calls++; OnPublish?.Invoke(revision);
            if (Fail) throw new IOException("broker unavailable");
            return Task.FromResult(true);
        }
    }
    private sealed class EnvironmentStub : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = "Testing";
        public string ApplicationName { get; set; } = "Identity.Tests";
        public string ContentRootPath { get; set; } = "/tmp";
        public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
    }
}
