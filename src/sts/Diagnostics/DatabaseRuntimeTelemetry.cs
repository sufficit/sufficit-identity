using System.Collections.Concurrent;
using System.Data;
using System.Data.Common;
using System.Diagnostics.Metrics;
using System.Globalization;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Channels;
using Sufficit.Identity.Application.Diagnostics;

namespace Sufficit.Identity.STS.Diagnostics;

/// <summary>
/// Observes logical database leases and commands through EF Core, and consumes
/// provider pool instruments that follow the OpenTelemetry database metric
/// conventions. No SQL text, parameters or connection strings are retained.
/// </summary>
internal sealed class DatabaseRuntimeTelemetry : IDatabaseRuntimeTelemetry,
    IDisposable
{
    private static readonly string[] PhysicalIdPropertyNames =
        ["ServerThread", "ProcessID", "ServerProcessId", "ClientConnectionId"];
    private static readonly TimeSpan UpdateCoalescingWindow =
        TimeSpan.FromMilliseconds(100);
    private static readonly TimeSpan DefaultIdleLeasePruneAfter =
        TimeSpan.FromMinutes(15);

    private readonly ConcurrentDictionary<DbConnection, ActiveLease> connections =
        new(ReferenceEqualityComparer.Instance);
    private readonly ConcurrentDictionary<string, PhysicalCounters> physicalConnections =
        new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<(string Provider, string Pool), PoolCounters> pools = new();
    private readonly ConcurrentDictionary<Type, Func<DbConnection, string?>> physicalIdReaders = new();
    private readonly ConcurrentDictionary<long, Channel<byte>> subscribers = new();
    private readonly MeterListener meterListener;
    private readonly TimeSpan idleLeasePruneAfter;
    private DatabaseWatchdogSnapshot watchdog =
        new(false, "disabled", 0, null, null, null);
    private long nextConnectionId;
    private long nextSubscriberId;
    private long totalCommands;
    private long failedCommands;
    private int disposed;

    internal DatabaseRuntimeTelemetry(TimeSpan? idleLeasePruneAfter = null)
    {
        this.idleLeasePruneAfter = idleLeasePruneAfter ?? DefaultIdleLeasePruneAfter;
        meterListener = new MeterListener
        {
            InstrumentPublished = static (instrument, listener) =>
            {
                if (instrument.Name.StartsWith(
                        "db.client.connections.",
                        StringComparison.Ordinal))
                {
                    listener.EnableMeasurementEvents(instrument);
                }
            }
        };
        meterListener.SetMeasurementEventCallback<long>(RecordMeasurement);
        meterListener.SetMeasurementEventCallback<int>(RecordMeasurement);
        meterListener.SetMeasurementEventCallback<double>(RecordMeasurement);
        meterListener.Start();
    }

    public DatabaseRuntimeSnapshot GetSnapshot()
    {
        var now = DateTimeOffset.UtcNow;
        PruneIdleLeases(now);
        PruneClosedConnections();
        PrunePhysicalCounters(now);

        var active = connections.Values
            .Select(lease => lease.ToSnapshot())
            .OrderByDescending(connection => connection.ActiveCommands)
            .ThenBy(connection => connection.OpenedAtUtc)
            .ThenBy(connection => connection.Id, StringComparer.Ordinal)
            .ToArray();
        var poolSnapshots = pools
            .Select(item => item.Value.ToSnapshot(item.Key.Provider, item.Key.Pool))
            .OrderBy(pool => pool.Provider, StringComparer.Ordinal)
            .ThenBy(pool => pool.Name, StringComparer.Ordinal)
            .ToArray();

        return new DatabaseRuntimeSnapshot(
            now,
            Interlocked.Read(ref totalCommands),
            Interlocked.Read(ref failedCommands),
            poolSnapshots,
            active,
            Volatile.Read(ref watchdog));
    }

    private void PruneClosedConnections()
    {
        foreach (var item in connections)
        {
            if (IsOpen(item.Key))
            {
                continue;
            }

            if (connections.TryRemove(item.Key, out var lease))
            {
                lease.MarkReturned();
            }
        }
    }

    private void PruneIdleLeases(DateTimeOffset now)
    {
        foreach (var item in connections)
        {
            if (!item.Value.IsIdle(now, idleLeasePruneAfter))
            {
                continue;
            }

            if (connections.TryRemove(item.Key, out var lease))
            {
                // A provider can leave a logical DbConnection object open
                // while its pool has already returned the physical lease.
                // Do not let that bookkeeping object live forever in the
                // management view: this page reports currently leased
                // connections, not every object ever observed by EF Core.
                lease.MarkReturned();
            }
        }
    }

    private static bool IsOpen(DbConnection connection)
    {
        try
        {
            return connection.State is ConnectionState.Open;
        }
        catch (InvalidOperationException)
        {
            return false;
        }
    }

    public async IAsyncEnumerable<DatabaseRuntimeSnapshot> WatchAsync(
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(
            Volatile.Read(ref disposed) is not 0,
            this);

        var channel = Channel.CreateBounded<byte>(
            new BoundedChannelOptions(1)
            {
                SingleReader = true,
                SingleWriter = false,
                FullMode = BoundedChannelFullMode.DropOldest,
                AllowSynchronousContinuations = false
            });
        var subscriberId = Interlocked.Increment(ref nextSubscriberId);
        if (!subscribers.TryAdd(subscriberId, channel))
        {
            throw new InvalidOperationException(
                "The database telemetry subscription could not be registered.");
        }

        try
        {
            yield return GetSnapshot();

            while (await channel.Reader.WaitToReadAsync(cancellationToken))
            {
                while (channel.Reader.TryRead(out _))
                {
                }

                // Database commands can arrive in large bursts. Waiting for a
                // short quiet window keeps the stream event-driven while
                // bounding Blazor render work to at most ten updates/second.
                await Task.Delay(UpdateCoalescingWindow, cancellationToken);
                while (channel.Reader.TryRead(out _))
                {
                }

                yield return GetSnapshot();
            }
        }
        finally
        {
            subscribers.TryRemove(subscriberId, out _);
            channel.Writer.TryComplete();
        }
    }

    internal void ConfigureWatchdog(bool enabled)
    {
        Volatile.Write(
            ref watchdog,
            new DatabaseWatchdogSnapshot(
                enabled,
                enabled ? "starting" : "disabled",
                0,
                null,
                null,
                null));
        PublishChanged();
    }

    internal void RecordWatchdogProbe(
        bool healthy,
        int consecutiveFailures,
        TimeSpan duration,
        string? failureCode = null)
    {
        Volatile.Write(
            ref watchdog,
            new DatabaseWatchdogSnapshot(
                Enabled: true,
                healthy ? "healthy" : "degraded",
                consecutiveFailures,
                DateTimeOffset.UtcNow,
                duration.TotalMilliseconds,
                healthy ? null : failureCode ?? "database_probe_failed"));
        PublishChanged();
    }

    internal void RecordWatchdogStopping(int consecutiveFailures)
    {
        var current = Volatile.Read(ref watchdog);
        Volatile.Write(
            ref watchdog,
            current with
            {
                Status = "restarting",
                ConsecutiveFailures = consecutiveFailures
            });
        PublishChanged();
    }

    internal void TrackOpened(DbConnection connection)
    {
        ArgumentNullException.ThrowIfNull(connection);
        connections.AddOrUpdate(
            connection,
            CreateLease,
            (_, existing) => existing.Reopen(
                DateTimeOffset.UtcNow,
                ResolvePhysicalCounters(connection)));
        PublishChanged();
    }

    internal void TrackClosed(DbConnection connection)
    {
        ArgumentNullException.ThrowIfNull(connection);
        if (connections.TryRemove(connection, out var lease))
        {
            lease.MarkReturned();
            PublishChanged();
        }
    }

    internal void TrackCommandStarted(DbConnection? connection)
    {
        if (connection is null)
        {
            return;
        }

        var lease = connections.GetOrAdd(connection, CreateLease);
        lease.CommandStarted();
        Interlocked.Increment(ref totalCommands);
        PublishChanged();
    }

    internal void TrackCommandCompleted(
        DbConnection? connection,
        TimeSpan duration,
        bool failed)
    {
        if (connection is null || !connections.TryGetValue(connection, out var lease))
        {
            if (failed)
            {
                Interlocked.Increment(ref failedCommands);
                PublishChanged();
            }
            return;
        }

        lease.CommandCompleted(duration, failed);
        if (failed)
        {
            Interlocked.Increment(ref failedCommands);
        }
        PublishChanged();
    }

    private ActiveLease CreateLease(DbConnection connection)
    {
        var now = DateTimeOffset.UtcNow;
        return new ActiveLease(
            $"db-{Interlocked.Increment(ref nextConnectionId):D4}",
            ProviderLabel(connection.GetType()),
            SafeConnectionValue(() => connection.DataSource),
            SafeConnectionValue(() => connection.Database),
            now,
            ResolvePhysicalCounters(connection));
    }

    private PhysicalCounters ResolvePhysicalCounters(DbConnection connection)
    {
        var physicalId = physicalIdReaders
            .GetOrAdd(connection.GetType(), CreatePhysicalIdReader)(connection);
        var provider = ProviderLabel(connection.GetType());
        var dataSource = SafeConnectionValue(() => connection.DataSource);
        var database = SafeConnectionValue(() => connection.Database);
        var key = physicalId is null
            ? $"logical|{provider}|{Interlocked.Increment(ref nextConnectionId):D8}"
            : $"physical|{provider}|{dataSource}|{database}|{physicalId}";

        return physicalConnections.GetOrAdd(
            key,
            _ => new PhysicalCounters(physicalId));
    }

    private static Func<DbConnection, string?> CreatePhysicalIdReader(Type type)
    {
        var property = PhysicalIdPropertyNames
            .Select(name => type.GetProperty(
                name,
                BindingFlags.Instance | BindingFlags.Public))
            .FirstOrDefault(candidate => candidate is not null && candidate.CanRead);
        if (property is null)
        {
            return _ => null;
        }

        return connection =>
        {
            try
            {
                return Convert.ToString(
                    property.GetValue(connection),
                    CultureInfo.InvariantCulture);
            }
            catch (TargetInvocationException)
            {
                return null;
            }
            catch (InvalidOperationException)
            {
                return null;
            }
        };
    }

    private void RecordMeasurement<T>(
        Instrument instrument,
        T measurement,
        ReadOnlySpan<KeyValuePair<string, object?>> tags,
        object? state)
        where T : struct
    {
        _ = state;
        string? poolName = null;
        string? usageState = null;
        foreach (var tag in tags)
        {
            if (string.Equals(tag.Key, "pool.name", StringComparison.Ordinal))
            {
                poolName = Convert.ToString(tag.Value, CultureInfo.InvariantCulture);
            }
            else if (string.Equals(tag.Key, "state", StringComparison.Ordinal))
            {
                usageState = Convert.ToString(tag.Value, CultureInfo.InvariantCulture);
            }
        }

        var provider = ProviderLabel(instrument.Meter.Name);
        var safePoolName = SafePoolName(poolName);
        var counters = pools.GetOrAdd(
            (provider, safePoolName),
            static _ => new PoolCounters());
        var delta = Convert.ToInt64(measurement, CultureInfo.InvariantCulture);
        counters.Record(instrument.Name, usageState, delta);
        PublishChanged();
    }

    private void PublishChanged()
    {
        if (Volatile.Read(ref disposed) is not 0)
        {
            return;
        }

        foreach (var subscriber in subscribers.Values)
        {
            subscriber.Writer.TryWrite(0);
        }
    }

    private void PrunePhysicalCounters(DateTimeOffset now)
    {
        var cutoff = now.AddMinutes(-15).ToUnixTimeMilliseconds();
        var activeCounters = connections.Values
            .Select(connection => connection.Counters)
            .ToHashSet(ReferenceEqualityComparer.Instance);

        foreach (var item in physicalConnections)
        {
            if (!activeCounters.Contains(item.Value)
                && item.Value.LastSeenUnixMilliseconds < cutoff)
            {
                physicalConnections.TryRemove(item.Key, out _);
            }
        }
    }

    private static string ProviderLabel(Type connectionType) =>
        ProviderLabel(connectionType.Namespace ?? connectionType.Name);

    private static string ProviderLabel(string source) => source switch
    {
        "MySqlConnector" => "MySQL/MariaDB",
        "Microsoft.Data.SqlClient" => "SQL Server",
        "Npgsql" => "PostgreSQL",
        "Microsoft.Data.Sqlite" => "SQLite",
        _ => source
    };

    private static string SafeConnectionValue(Func<string> valueFactory)
    {
        try
        {
            var value = valueFactory();
            return string.IsNullOrWhiteSpace(value) ? "não informado" : value;
        }
        catch (InvalidOperationException)
        {
            return "não informado";
        }
    }

    private static string SafePoolName(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return "default";
        }
        if (!value.Contains('=') && !value.Contains(';') && value.Length <= 80)
        {
            return value;
        }

        var digest = SHA256.HashData(Encoding.UTF8.GetBytes(value));
        return $"pool-{Convert.ToHexString(digest)[..8].ToLowerInvariant()}";
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref disposed, 1) is 0)
        {
            foreach (var subscriber in subscribers.Values)
            {
                subscriber.Writer.TryComplete();
            }
            subscribers.Clear();
            connections.Clear();
            physicalConnections.Clear();
            pools.Clear();
            physicalIdReaders.Clear();
            meterListener.Dispose();
        }
    }

    private sealed class ActiveLease(
        string id,
        string provider,
        string dataSource,
        string database,
        DateTimeOffset openedAtUtc,
        PhysicalCounters counters)
    {
        private long openedAtUnixMilliseconds = openedAtUtc.ToUnixTimeMilliseconds();
        private long leaseCommandCount;
        private int activeCommands;
        private long failedCommands;
        private long lastCommandUnixMilliseconds;
        private long lastDurationMicroseconds = -1;

        public PhysicalCounters Counters { get; private set; } = counters;

        public ActiveLease Reopen(
            DateTimeOffset openedAt,
            PhysicalCounters physicalCounters)
        {
            Interlocked.Exchange(
                ref openedAtUnixMilliseconds,
                openedAt.ToUnixTimeMilliseconds());
            Interlocked.Exchange(ref leaseCommandCount, 0);
            Interlocked.Exchange(ref activeCommands, 0);
            Interlocked.Exchange(ref failedCommands, 0);
            Interlocked.Exchange(ref lastCommandUnixMilliseconds, 0);
            Interlocked.Exchange(ref lastDurationMicroseconds, -1);
            Counters = physicalCounters;
            return this;
        }

        public void CommandStarted()
        {
            var now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            Interlocked.Increment(ref leaseCommandCount);
            Interlocked.Increment(ref activeCommands);
            Interlocked.Exchange(ref lastCommandUnixMilliseconds, now);
            Counters.CommandStarted(now);
        }

        public void CommandCompleted(TimeSpan duration, bool failed)
        {
            if (Interlocked.Decrement(ref activeCommands) < 0)
            {
                Interlocked.Exchange(ref activeCommands, 0);
            }
            Interlocked.Exchange(
                ref lastDurationMicroseconds,
                (long)Math.Max(0, duration.TotalMicroseconds));
            if (failed)
            {
                Interlocked.Increment(ref failedCommands);
                Counters.CommandFailed();
            }
            Counters.Touch();
        }

        public void MarkReturned() => Counters.Touch();

        public bool IsIdle(DateTimeOffset now, TimeSpan idleAfter)
        {
            if (Volatile.Read(ref activeCommands) is not 0)
            {
                return false;
            }

            var lastCommand = Interlocked.Read(ref lastCommandUnixMilliseconds);
            var lastActivity = lastCommand is 0
                ? Interlocked.Read(ref openedAtUnixMilliseconds)
                : lastCommand;
            var elapsed = now.ToUnixTimeMilliseconds() - lastActivity;
            return elapsed >= idleAfter.TotalMilliseconds;
        }

        public DatabaseConnectionSnapshot ToSnapshot()
        {
            var lastCommand = Interlocked.Read(ref lastCommandUnixMilliseconds);
            var lastDuration = Interlocked.Read(ref lastDurationMicroseconds);
            return new DatabaseConnectionSnapshot(
                id,
                Counters.PhysicalId,
                provider,
                dataSource,
                database,
                DateTimeOffset.FromUnixTimeMilliseconds(
                    Interlocked.Read(ref openedAtUnixMilliseconds)),
                lastCommand is 0
                    ? null
                    : DateTimeOffset.FromUnixTimeMilliseconds(lastCommand),
                Interlocked.Read(ref Counters.CommandCount),
                Interlocked.Read(ref leaseCommandCount),
                Math.Max(0, Volatile.Read(ref activeCommands)),
                Interlocked.Read(ref failedCommands),
                lastDuration < 0 ? null : lastDuration / 1000d);
        }
    }

    private sealed class PhysicalCounters(string? physicalId)
    {
        public readonly string? PhysicalId = physicalId;
        public long CommandCount;
        private long failedCommands;
        private long lastSeenUnixMilliseconds =
            DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

        public long LastSeenUnixMilliseconds =>
            Interlocked.Read(ref lastSeenUnixMilliseconds);

        public void CommandStarted(long nowUnixMilliseconds)
        {
            Interlocked.Increment(ref CommandCount);
            Interlocked.Exchange(ref lastSeenUnixMilliseconds, nowUnixMilliseconds);
        }

        public void CommandFailed() => Interlocked.Increment(ref failedCommands);

        public void Touch() => Interlocked.Exchange(
            ref lastSeenUnixMilliseconds,
            DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());
    }

    private sealed class PoolCounters
    {
        private long used;
        private long idle;
        private long maximum;
        private long maximumIdle;
        private long minimumIdle;
        private long pending;
        private long timeouts;
        private int hasUsage;
        private int hasMaximum;
        private int hasMinimum;
        private int hasPending;

        public void Record(string instrument, string? state, long delta)
        {
            switch (instrument)
            {
                case "db.client.connections.usage":
                    if (string.Equals(state, "used", StringComparison.OrdinalIgnoreCase))
                    {
                        Interlocked.Add(ref used, delta);
                    }
                    else if (string.Equals(state, "idle", StringComparison.OrdinalIgnoreCase))
                    {
                        Interlocked.Add(ref idle, delta);
                    }
                    Volatile.Write(ref hasUsage, 1);
                    break;
                case "db.client.connections.pending_requests":
                    Interlocked.Add(ref pending, delta);
                    Volatile.Write(ref hasPending, 1);
                    break;
                case "db.client.connections.timeouts":
                    Interlocked.Add(ref timeouts, delta);
                    break;
                case "db.client.connections.max":
                    Interlocked.Add(ref maximum, delta);
                    Volatile.Write(ref hasMaximum, 1);
                    break;
                case "db.client.connections.idle.max":
                    Interlocked.Add(ref maximumIdle, delta);
                    break;
                case "db.client.connections.idle.min":
                    Interlocked.Add(ref minimumIdle, delta);
                    Volatile.Write(ref hasMinimum, 1);
                    break;
            }
        }

        public DatabasePoolSnapshot ToSnapshot(string provider, string name) =>
            new(
                name,
                provider,
                Volatile.Read(ref hasUsage) is 1
                    ? Math.Max(0, Interlocked.Read(ref used))
                    : null,
                Volatile.Read(ref hasUsage) is 1
                    ? Math.Max(0, Interlocked.Read(ref idle))
                    : null,
                Volatile.Read(ref hasMaximum) is 1
                    ? Math.Max(0, Interlocked.Read(ref maximum))
                    : Math.Max(0, Interlocked.Read(ref maximumIdle)) is var idleMaximum
                        && idleMaximum > 0
                            ? idleMaximum
                            : null,
                Volatile.Read(ref hasMinimum) is 1
                    ? Math.Max(0, Interlocked.Read(ref minimumIdle))
                    : null,
                Volatile.Read(ref hasPending) is 1
                    ? Math.Max(0, Interlocked.Read(ref pending))
                    : null,
                Math.Max(0, Interlocked.Read(ref timeouts)),
                Volatile.Read(ref hasUsage) is 1
                    || Volatile.Read(ref hasMaximum) is 1
                    || Volatile.Read(ref hasPending) is 1);
    }
}
