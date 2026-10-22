using System.Globalization;
using System.Net.Http.Headers;
using System.Text;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.Core.Metrics;
using Sufficit.Identity.Vault;

namespace Sufficit.Identity.STS.Metrics;

/// <summary>
/// Drains the in-memory usage counters once a minute (and on shutdown) into
/// this node's rows of the daily aggregate, and optionally exports the counts
/// per application (never per user). Authentication never waits for any of it.
/// </summary>
/// <remarks>
/// The node is part of the aggregate's key: in a multi-master cluster, nodes
/// incrementing the same row would collide on certification; each node owning
/// its rows means no contention at all, and readers sum the nodes.
/// </remarks>
internal sealed class IdentityUsageMetricsWorker(
    IdentityUsageCounters counters,
    IDbContextFactory<AppDbContext> databaseFactory,
    IHttpClientFactory httpClientFactory,
    IKeyVault keyVault,
    IdentityMetricsRuntimeState runtime,
    IConfiguration configuration,
    ILogger<IdentityUsageMetricsWorker> logger) : BackgroundService
{
    internal static readonly TimeSpan FlushInterval = TimeSpan.FromMinutes(1);
    private int _consecutiveExportFailures;
    private DateTime _exportCircuitOpenUtc;
    private DateTime _nextRetentionUtc = DateTime.MinValue;

    /// <summary>Stable name of this node in the aggregate (configurable; the machine name otherwise).</summary>
    internal string Node { get; } = Truncate(
        configuration["Sufficit:Identity:Metrics:NodeName"] is { Length: > 0 } name ? name : Environment.MachineName,
        IdentityDatabaseSchema.MetricsNodeLength);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(FlushInterval);
        try
        {
            while (await timer.WaitForNextTickAsync(stoppingToken))
                await FlushAsync(stoppingToken);
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
        }

        // Counted since the last tick: keep it across a deploy.
        using var shutdown = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        await FlushAsync(shutdown.Token);
    }

    internal async Task FlushAsync(CancellationToken cancellationToken)
    {
        var configuration = await LoadConfigurationAsync(cancellationToken);
        var drained = counters.Drain();
        if (drained.Count == 0 || !configuration.Enabled) return;

        try
        {
            await PersistAsync(drained, cancellationToken);
            runtime.PersistedMany(drained.Count);
        }
        catch (Exception exception) when (!cancellationToken.IsCancellationRequested)
        {
            counters.Restore(drained);
            runtime.FailedOne();
            logger.LogError(exception, "Identity usage counters could not be persisted; kept in memory for the next flush.");
            return;
        }

        if (configuration.ExportEnabled && configuration.Provider == "victoria_metrics")
            await TryExportAsync(configuration, drained, cancellationToken);

        if (DateTime.UtcNow >= _nextRetentionUtc)
            await TryApplyRetentionAsync(configuration.RetentionDays, cancellationToken);
    }

    private async Task<IdentityMetricsConfiguration> LoadConfigurationAsync(CancellationToken cancellationToken)
    {
        try
        {
            await using var database = await databaseFactory.CreateDbContextAsync(cancellationToken);
            return await database.IdentityMetricsConfigurations.AsNoTracking()
                .SingleOrDefaultAsync(item => item.Id == IdentityMetricsConfiguration.SingletonId, cancellationToken)
                ?? new IdentityMetricsConfiguration { UpdatedAtUtc = DateTime.UtcNow };
        }
        catch (Exception exception) when (!cancellationToken.IsCancellationRequested)
        {
            runtime.FailedOne();
            logger.LogWarning(exception, "Identity metrics configuration could not be loaded; using safe local defaults.");
            return new IdentityMetricsConfiguration { UpdatedAtUtc = DateTime.UtcNow };
        }
    }

    /// <summary>Adds the drained counts to this node's rows; only this node ever writes them.</summary>
    private async Task PersistAsync(
        IReadOnlyList<(IdentityUsageKey Key, long Count, DateTime LastOccurredAtUtc)> drained,
        CancellationToken cancellationToken)
    {
        await using var database = await databaseFactory.CreateDbContextAsync(cancellationToken);
        var days = drained.Select(item => item.Key.Day).Distinct().ToArray();
        var existing = await database.IdentityApplicationUsageDaily
            .Where(row => row.Node == Node && days.Contains(row.Day))
            .ToListAsync(cancellationToken);
        var byKey = existing.ToDictionary(row => new IdentityUsageKey(
            row.Day, row.ClientId, row.EventType, row.EndpointType, row.GrantType, row.Outcome, row.UserId));

        foreach (var (key, count, last) in drained)
        {
            var normalized = Normalize(key);
            if (byKey.TryGetValue(normalized, out var row))
            {
                row.Count += count;
                if (last > row.LastOccurredAtUtc) row.LastOccurredAtUtc = last;
                continue;
            }

            row = new IdentityApplicationUsageDaily
            {
                Day = normalized.Day,
                Node = Node,
                ClientId = normalized.ClientId,
                EventType = normalized.EventType,
                EndpointType = normalized.EndpointType,
                GrantType = normalized.GrantType,
                Outcome = normalized.Outcome,
                UserId = normalized.UserId,
                Count = count,
                LastOccurredAtUtc = last,
            };
            database.IdentityApplicationUsageDaily.Add(row);
            byKey[normalized] = row;
        }

        await database.SaveChangesAsync(cancellationToken);
    }

    private static IdentityUsageKey Normalize(IdentityUsageKey key) => key with
    {
        ClientId = Truncate(key.ClientId, IdentityDatabaseSchema.MetricsClientIdLength),
        EventType = Truncate(key.EventType, IdentityDatabaseSchema.MetricsEventTypeLength),
        EndpointType = Truncate(key.EndpointType, IdentityDatabaseSchema.MetricsEndpointTypeLength),
        GrantType = Truncate(key.GrantType, IdentityDatabaseSchema.MetricsGrantTypeLength),
        Outcome = Truncate(key.Outcome, IdentityDatabaseSchema.MetricsOutcomeLength),
    };

    private async Task TryExportAsync(
        IdentityMetricsConfiguration configuration,
        IReadOnlyList<(IdentityUsageKey Key, long Count, DateTime LastOccurredAtUtc)> drained,
        CancellationToken cancellationToken)
    {
        if (DateTime.UtcNow < _exportCircuitOpenUtc || string.IsNullOrWhiteSpace(configuration.Endpoint)) return;
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Post, BuildWriteUri(configuration));
            // Users never leave the identity: the export is per application only.
            var perApplication = drained
                .GroupBy(item => item.Key.WithoutUser())
                .Select(group => (group.Key, group.Sum(item => item.Count), group.Max(item => item.LastOccurredAtUtc)))
                .ToArray();
            request.Content = new StringContent(BuildLineProtocol(perApplication, Node), Encoding.UTF8, "application/x-line-protocol");
            await ApplyAuthorizationAsync(request, configuration, cancellationToken);
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(TimeSpan.FromSeconds(configuration.TimeoutSeconds));
            using var response = await httpClientFactory.CreateClient("identity-metrics-export").SendAsync(request, timeout.Token);
            response.EnsureSuccessStatusCode();
            _consecutiveExportFailures = 0;
            runtime.ExportedMany(drained.Count);
        }
        catch (Exception exception) when (!cancellationToken.IsCancellationRequested)
        {
            runtime.FailedOne();
            if (++_consecutiveExportFailures >= 3)
            {
                _exportCircuitOpenUtc = DateTime.UtcNow.AddMinutes(5);
                _consecutiveExportFailures = 0;
            }
            logger.LogWarning(exception, "Identity metrics export failed; local aggregation and authentication remain available.");
        }
    }

    private async Task ApplyAuthorizationAsync(HttpRequestMessage request, IdentityMetricsConfiguration configuration, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(configuration.SecretCiphertext)) return;
        var secret = await keyVault.DecryptStringAsync(configuration.SecretCiphertext,
            new Dictionary<string, string> { ["configuration"] = "identity-metrics" }, cancellationToken);
        var scheme = configuration.AuthorizationScheme?.Trim();
        if (string.Equals(scheme, "Basic", StringComparison.OrdinalIgnoreCase))
        {
            var value = Convert.ToBase64String(Encoding.UTF8.GetBytes($"{configuration.Username}:{secret}"));
            request.Headers.Authorization = new AuthenticationHeaderValue("Basic", value);
        }
        else if (!string.IsNullOrWhiteSpace(scheme))
            request.Headers.Authorization = new AuthenticationHeaderValue(scheme, secret);
    }

    private async Task TryApplyRetentionAsync(int retentionDays, CancellationToken cancellationToken)
    {
        _nextRetentionUtc = DateTime.UtcNow.AddHours(24);
        try
        {
            await using var database = await databaseFactory.CreateDbContextAsync(cancellationToken);
            var cutoff = DateTime.UtcNow.Date.AddDays(-retentionDays);
            await database.IdentityApplicationUsageDaily.Where(row => row.Day < cutoff)
                .ExecuteDeleteAsync(cancellationToken);
        }
        catch (Exception exception) when (!cancellationToken.IsCancellationRequested)
        {
            runtime.FailedOne();
            logger.LogWarning(exception, "Identity metrics retention cleanup failed.");
        }
    }

    private static Uri BuildWriteUri(IdentityMetricsConfiguration configuration)
    {
        var endpoint = configuration.Endpoint!.TrimEnd('/');
        var database = Uri.EscapeDataString(configuration.Database ?? "identity");
        return new Uri($"{endpoint}/write?db={database}&precision=millisecond", UriKind.Absolute);
    }

    /// <summary>
    /// One point per counted combination, carrying how many uses it saw since
    /// the previous flush (summing the points over time gives the total), and
    /// the node, so series of different nodes never overwrite each other.
    /// </summary>
    internal static string BuildLineProtocol(
        IEnumerable<(IdentityUsageKey Key, long Count, DateTime LastOccurredAtUtc)> drained, string node) =>
        string.Join('\n', drained.Select(item =>
            $"sufficit_identity_application_usage,client_id={EscapeTag(item.Key.ClientId)},event_type={EscapeTag(item.Key.EventType)},endpoint_type={EscapeTag(item.Key.EndpointType)},grant_type={EscapeTag(item.Key.GrantType is { Length: > 0 } grant ? grant : "unknown")},outcome={EscapeTag(item.Key.Outcome)},node={EscapeTag(node)} value={item.Count.ToString(CultureInfo.InvariantCulture)}i {new DateTimeOffset(item.LastOccurredAtUtc).ToUnixTimeMilliseconds().ToString(CultureInfo.InvariantCulture)}"));

    private static string EscapeTag(string value) => value.Replace("\\", "\\\\").Replace(" ", "\\ ").Replace(",", "\\,").Replace("=", "\\=");
    private static string Truncate(string value, int length) => value.Length <= length ? value : value[..length];
}
