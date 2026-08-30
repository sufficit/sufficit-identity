using Sufficit.Identity.Management.Authorization;

namespace Sufficit.Identity.Management.Metrics;

public interface IMetricsManagementService
{
    Task<ManagementMetricsOverview> GetOverviewAsync(
        DateTime? fromUtc,
        DateTime? toUtc,
        string? clientId,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default);

    Task<ManagementMetricsConfiguration> GetConfigurationAsync(
        ManagementRequestContext context,
        CancellationToken cancellationToken = default);

    Task<ManagementMetricsConfiguration> UpdateConfigurationAsync(
        SaveManagementMetricsConfiguration command,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default);
}

public sealed record ManagementMetricsOverview(
    DateTime FromUtc,
    DateTime ToUtc,
    long TotalEvents,
    long SuccessfulEvents,
    long FailedEvents,
    int ActiveApplications,
    IReadOnlyList<ManagementMetricsDailyPoint> Daily,
    IReadOnlyList<ManagementMetricsApplication> Applications,
    IReadOnlyList<ManagementMetricsDimension> GrantTypes,
    ManagementMetricsCollectorStatus Collector);

public sealed record ManagementMetricsDailyPoint(DateTime DateUtc, long Count);

public sealed record ManagementMetricsApplication(
    string ClientId,
    string DisplayName,
    long Count,
    DateTime LastUsedAtUtc);

public sealed record ManagementMetricsDimension(string Name, long Count);

public sealed record ManagementMetricsCollectorStatus(
    long QueueDepth,
    long Accepted,
    long Dropped,
    long Persisted,
    long Exported,
    long Failures,
    DateTime? LastPersistedAtUtc,
    DateTime? LastExportedAtUtc);

public sealed record ManagementMetricsConfiguration(
    bool Enabled,
    int RetentionDays,
    bool ExportEnabled,
    string Provider,
    string? Endpoint,
    string? Database,
    string? AuthorizationScheme,
    string? Username,
    bool HasSecret,
    int TimeoutSeconds,
    int BatchSize,
    DateTime UpdatedAtUtc);

public sealed record SaveManagementMetricsConfiguration(
    bool Enabled,
    int RetentionDays,
    bool ExportEnabled,
    string Provider,
    string? Endpoint,
    string? Database,
    string? AuthorizationScheme,
    string? Username,
    string? Secret,
    bool ClearSecret,
    int TimeoutSeconds,
    int BatchSize);
