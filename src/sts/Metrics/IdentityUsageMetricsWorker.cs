using System.Globalization;
using System.Net.Http.Headers;
using System.Text;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.Core.Metrics;
using Sufficit.Identity.Vault;

namespace Sufficit.Identity.STS.Metrics;

internal sealed class IdentityUsageMetricsWorker(
    IdentityUsageMetricChannel channel,
    IDbContextFactory<AppDbContext> databaseFactory,
    IHttpClientFactory httpClientFactory,
    IKeyVault keyVault,
    IdentityMetricsRuntimeState runtime,
    ILogger<IdentityUsageMetricsWorker> logger) : BackgroundService
{
    private int _consecutiveExportFailures;
    private DateTime _exportCircuitOpenUntilUtc;
    private DateTime _nextRetentionUtc = DateTime.MinValue;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (await channel.Channel.Reader.WaitToReadAsync(stoppingToken))
        {
            // Short debounce closes the originating request/transaction before
            // touching persistence and coalesces bursts into one bounded write.
            await Task.Delay(TimeSpan.FromMilliseconds(250), stoppingToken);
            var configuration = await LoadConfigurationAsync(stoppingToken);
            var batch = new List<IdentityUsageMetric>(configuration.BatchSize);
            while (batch.Count < configuration.BatchSize && channel.Channel.Reader.TryRead(out var metric))
                batch.Add(metric);
            runtime.SetQueueDepth(channel.Channel.Reader.Count);
            if (batch.Count == 0 || !configuration.Enabled) continue;

            try
            {
                await PersistAsync(batch, stoppingToken);
                runtime.PersistedMany(batch.Count);
            }
            catch (Exception exception) when (!stoppingToken.IsCancellationRequested)
            {
                runtime.FailedOne();
                logger.LogError(exception, "Identity usage metric persistence failed; authentication remained available.");
                continue;
            }

            if (configuration.ExportEnabled && configuration.Provider == "victoria_metrics")
                await TryExportAsync(configuration, batch, stoppingToken);

            if (DateTime.UtcNow >= _nextRetentionUtc)
                await TryApplyRetentionAsync(configuration.RetentionDays, stoppingToken);
        }
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

    private async Task PersistAsync(IReadOnlyCollection<IdentityUsageMetric> batch, CancellationToken cancellationToken)
    {
        await using var database = await databaseFactory.CreateDbContextAsync(cancellationToken);
        database.IdentityApplicationUsageEvents.AddRange(batch.Select(item => new IdentityApplicationUsageEvent
        {
            OccurredAtUtc = item.OccurredAtUtc,
            ClientId = Truncate(item.ClientId, 255),
            EventType = Truncate(item.EventType, 64),
            EndpointType = Truncate(item.EndpointType, 64),
            GrantType = TruncateNullable(item.GrantType, 100),
            Outcome = Truncate(item.Outcome, 32),
            SubjectHash = TruncateNullable(item.SubjectHash, 64)
        }));
        await database.SaveChangesAsync(cancellationToken);
    }

    private async Task TryExportAsync(IdentityMetricsConfiguration configuration, IReadOnlyCollection<IdentityUsageMetric> batch, CancellationToken cancellationToken)
    {
        if (DateTime.UtcNow < _exportCircuitOpenUntilUtc || string.IsNullOrWhiteSpace(configuration.Endpoint)) return;
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Post, BuildWriteUri(configuration));
            request.Content = new StringContent(BuildLineProtocol(batch), Encoding.UTF8, "application/x-line-protocol");
            await ApplyAuthorizationAsync(request, configuration, cancellationToken);
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(TimeSpan.FromSeconds(configuration.TimeoutSeconds));
            using var response = await httpClientFactory.CreateClient("identity-metrics-export").SendAsync(request, timeout.Token);
            response.EnsureSuccessStatusCode();
            _consecutiveExportFailures = 0;
            runtime.ExportedMany(batch.Count);
        }
        catch (Exception exception) when (!cancellationToken.IsCancellationRequested)
        {
            runtime.FailedOne();
            if (++_consecutiveExportFailures >= 3)
            {
                _exportCircuitOpenUntilUtc = DateTime.UtcNow.AddMinutes(5);
                _consecutiveExportFailures = 0;
            }
            logger.LogWarning(exception, "Identity metrics export failed; local collection and authentication remain available.");
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
            var cutoff = DateTime.UtcNow.AddDays(-retentionDays);
            await database.IdentityApplicationUsageEvents.Where(item => item.OccurredAtUtc < cutoff)
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

    private static string BuildLineProtocol(IEnumerable<IdentityUsageMetric> batch) => string.Join('\n', batch.Select(item =>
        $"sufficit_identity_application_usage,client_id={EscapeTag(item.ClientId)},event_type={EscapeTag(item.EventType)},endpoint_type={EscapeTag(item.EndpointType)},grant_type={EscapeTag(item.GrantType ?? "unknown")},outcome={EscapeTag(item.Outcome)} value=1i {new DateTimeOffset(item.OccurredAtUtc).ToUnixTimeMilliseconds().ToString(CultureInfo.InvariantCulture)}"));

    private static string EscapeTag(string value) => value.Replace("\\", "\\\\").Replace(" ", "\\ ").Replace(",", "\\,").Replace("=", "\\=");
    private static string Truncate(string value, int length) => value.Length <= length ? value : value[..length];
    private static string? TruncateNullable(string? value, int length) => value is null ? null : Truncate(value, length);
}
