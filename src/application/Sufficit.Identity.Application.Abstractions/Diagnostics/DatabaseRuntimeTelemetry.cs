namespace Sufficit.Identity.Application.Diagnostics;

/// <summary>
/// Provider-neutral, read-only view of database activity observed by the
/// identity runtime. Provider adapters may enrich pool metrics, while command
/// and connection telemetry remains available through the EF Core interceptor.
/// </summary>
public interface IDatabaseRuntimeTelemetry
{
    DatabaseRuntimeSnapshot GetSnapshot();
}

public sealed record DatabaseRuntimeSnapshot(
    DateTimeOffset CapturedAtUtc,
    long TotalCommands,
    long FailedCommands,
    IReadOnlyList<DatabasePoolSnapshot> Pools,
    IReadOnlyList<DatabaseConnectionSnapshot> ActiveConnections,
    DatabaseWatchdogSnapshot Watchdog);

public sealed record DatabasePoolSnapshot(
    string Name,
    string Provider,
    long? UsedConnections,
    long? IdleConnections,
    long? MaximumConnections,
    long? MinimumIdleConnections,
    long? PendingRequests,
    long ConnectionTimeouts,
    bool MetricsAvailable);

public sealed record DatabaseConnectionSnapshot(
    string Id,
    string? PhysicalId,
    string Provider,
    string DataSource,
    string Database,
    DateTimeOffset OpenedAtUtc,
    DateTimeOffset? LastCommandAtUtc,
    long CommandCount,
    long LeaseCommandCount,
    int ActiveCommands,
    long FailedCommands,
    double? LastDurationMilliseconds);

public sealed record DatabaseWatchdogSnapshot(
    bool Enabled,
    string Status,
    int ConsecutiveFailures,
    DateTimeOffset? LastProbeAtUtc,
    double? LastLatencyMilliseconds,
    string? LastFailureCode);
