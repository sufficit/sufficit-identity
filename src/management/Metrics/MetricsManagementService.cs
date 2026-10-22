using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.Core.Metrics;
using Sufficit.Identity.Management.Audit;
using Sufficit.Identity.Vault;
using Sufficit.Identity.Management.Authorization;

namespace Sufficit.Identity.Management.Metrics;

internal sealed class MetricsManagementService(
    AppDbContext database,
    IOpenIddictApplicationManager applications,
    IManagementAuthorizationEvaluator authorization,
    IKeyVault keyVault,
    IOptions<VaultOptions> vaultOptions,
    IdentityMetricsRuntimeState runtime) : IMetricsManagementService
{
    private static readonly ManagementResource MetricsResource =
        new(ManagementResourceTypes.Metrics);

    public async Task<ManagementMetricsOverview> GetOverviewAsync(
        DateTime? fromUtc,
        DateTime? toUtc,
        string? clientId,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default,
        string? userId = null)
    {
        await DemandAsync(context, ManagementCapabilities.MetricsRead, cancellationToken);
        // Per-user usage is personal data: it also takes the users capability.
        var canReadUsers = (await authorization.EvaluateAsync(context.Operator, ManagementCapabilities.UsersRead,
            new ManagementResource(ManagementResourceTypes.UserCollection), cancellationToken)).IsAllowed;
        if (!string.IsNullOrWhiteSpace(userId) && !canReadUsers)
            throw new ManagementAccessException(ManagementAuthorizationDecision.Denied(
                "capability_missing", ManagementCapabilities.UsersRead));
        var to = (toUtc ?? DateTime.UtcNow).ToUniversalTime();
        var from = (fromUtc ?? to.AddDays(-30)).ToUniversalTime();
        if (from >= to || to - from > TimeSpan.FromDays(366))
            throw new ManagementValidationException("invalid_metrics_range", "The period must be between 1 minute and 366 days.", "fromUtc");

        // Daily aggregate: a day counts when it overlaps the period. Nodes are summed.
        var firstDay = from.Date;
        var query = database.IdentityApplicationUsageDaily.AsNoTracking()
            .Where(item => item.Day >= firstDay && item.Day < to);
        if (!string.IsNullOrWhiteSpace(clientId))
        {
            var normalized = clientId.Trim();
            query = query.Where(item => item.ClientId == normalized);
        }

        if (!string.IsNullOrWhiteSpace(userId))
        {
            var user = userId.Trim();
            query = query.Where(item => item.UserId == user);
        }

        var summary = await query.GroupBy(_ => 1).Select(group => new
        {
            Total = group.Sum(item => item.Count),
            Success = group.Where(item => item.Outcome == "succeeded").Sum(item => item.Count),
            Failed = group.Where(item => item.Outcome != "succeeded").Sum(item => item.Count),
            Applications = group.Select(item => item.ClientId).Distinct().Count()
        }).SingleOrDefaultAsync(cancellationToken);

        var dailyRows = await BuildDailyAggregationQuery(query)
            .ToArrayAsync(cancellationToken);
        var daily = dailyRows
            .Select(item => new ManagementMetricsDailyPoint(
                new DateTime(item.Year, item.Month, item.Day, 0, 0, 0, DateTimeKind.Utc),
                item.Count))
            .ToArray();

        var top = await query
            .GroupBy(item => item.ClientId)
            .Select(group => new { ClientId = group.Key, Count = group.Sum(item => item.Count), LastUsed = group.Max(item => item.LastOccurredAtUtc) })
            .OrderByDescending(item => item.Count)
            .ThenBy(item => item.ClientId)
            .Take(20)
            .ToArrayAsync(cancellationToken);
        var topApplications = new List<ManagementMetricsApplication>(top.Length);
        foreach (var item in top)
        {
            var application = await applications.FindByClientIdAsync(item.ClientId, cancellationToken);
            var displayName = application is null
                ? item.ClientId
                : await applications.GetDisplayNameAsync(application, cancellationToken) ?? item.ClientId;
            topApplications.Add(new(item.ClientId, displayName, item.Count, item.LastUsed));
        }

        var grantRows = await BuildGrantAggregationQuery(query)
            .ToArrayAsync(cancellationToken);
        var grants = grantRows
            .Select(item => new ManagementMetricsDimension(item.Name, item.Count))
            .ToArray();

        var activeUsers = await query.Where(item => item.UserId != "")
            .Select(item => item.UserId).Distinct().CountAsync(cancellationToken);
        var users = new List<ManagementMetricsUser>();
        if (canReadUsers)
        {
            var topUsers = await query.Where(item => item.UserId != "")
                .GroupBy(item => item.UserId)
                .Select(group => new
                {
                    UserId = group.Key,
                    Count = group.Sum(item => item.Count),
                    Applications = group.Select(item => item.ClientId).Distinct().Count(),
                    LastUsed = group.Max(item => item.LastOccurredAtUtc),
                })
                .OrderByDescending(item => item.Count)
                .ThenBy(item => item.UserId)
                .Take(20)
                .ToArrayAsync(cancellationToken);
            var ids = topUsers.Select(item => item.UserId).ToArray();
            var names = await database.Users.AsNoTracking()
                .Where(user => ids.Contains(user.Id))
                .Select(user => new { user.Id, user.UserName })
                .ToDictionaryAsync(user => user.Id, user => user.UserName, cancellationToken);
            users.AddRange(topUsers.Select(item => new ManagementMetricsUser(
                item.UserId, names.GetValueOrDefault(item.UserId) ?? item.UserId,
                item.Count, item.Applications, item.LastUsed)));
        }

        return new(from, to, summary?.Total ?? 0, summary?.Success ?? 0,
            summary?.Failed ?? 0, summary?.Applications ?? 0, daily,
            topApplications, grants, new(runtime.QueueDepth, runtime.Accepted,
                runtime.Dropped, runtime.Persisted, runtime.Exported,
                runtime.Failures, runtime.LastPersistedAtUtc,
                runtime.LastExportedAtUtc), activeUsers, users);
    }

    public async Task<ManagementMetricsConfiguration> GetConfigurationAsync(
        ManagementRequestContext context,
        CancellationToken cancellationToken = default)
    {
        await DemandAsync(context, ManagementCapabilities.MetricsRead, cancellationToken);
        var entity = await database.IdentityMetricsConfigurations.AsNoTracking()
            .SingleOrDefaultAsync(item => item.Id == IdentityMetricsConfiguration.SingletonId, cancellationToken);
        return ToContract(entity ?? DefaultConfiguration());
    }

    public async Task<ManagementMetricsConfiguration> UpdateConfigurationAsync(
        SaveManagementMetricsConfiguration command,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(command);
        var decision = await DemandAsync(context, ManagementCapabilities.MetricsManage, cancellationToken);
        Validate(command);
        if (!string.IsNullOrWhiteSpace(command.Secret) && !vaultOptions.Value.Enabled)
            throw new ManagementValidationException("metrics_vault_required",
                "Enable the internal vault before storing an export credential.", "secret");
        var entity = await database.IdentityMetricsConfigurations.SingleOrDefaultAsync(
            item => item.Id == IdentityMetricsConfiguration.SingletonId, cancellationToken)
            ?? DefaultConfiguration();

        entity.Enabled = command.Enabled;
        entity.RetentionDays = command.RetentionDays;
        entity.ExportEnabled = command.ExportEnabled;
        entity.Provider = command.Provider.Trim().ToLowerInvariant();
        entity.Endpoint = NullIfWhiteSpace(command.Endpoint);
        entity.Database = NullIfWhiteSpace(command.Database);
        entity.AuthorizationScheme = NullIfWhiteSpace(command.AuthorizationScheme);
        entity.Username = NullIfWhiteSpace(command.Username);
        entity.TimeoutSeconds = command.TimeoutSeconds;
        entity.BatchSize = command.BatchSize;
        entity.UpdatedAtUtc = DateTime.UtcNow;
        if (command.ClearSecret)
            entity.SecretCiphertext = null;
        else if (!string.IsNullOrWhiteSpace(command.Secret))
            entity.SecretCiphertext = await keyVault.EncryptAsync(
                "identity-metrics-export", command.Secret,
                new Dictionary<string, string> { ["configuration"] = "identity-metrics" },
                cancellationToken);

        if (database.Entry(entity).State is EntityState.Detached)
            database.IdentityMetricsConfigurations.Add(entity);
        database.ManagementAuditEvents.Add(ManagementAuditEventFactory.Create(
            context, ManagementCapabilities.MetricsManage, MetricsResource,
            decision, "succeeded", "metrics_configuration_updated"));
        await database.SaveChangesAsync(cancellationToken);
        return ToContract(entity);
    }

    private async Task<ManagementAuthorizationDecision> DemandAsync(
        ManagementRequestContext context, string capability, CancellationToken cancellationToken)
    {
        var decision = await authorization.EvaluateAsync(
            context.Operator, capability, MetricsResource, cancellationToken);
        if (!decision.IsAllowed) throw new ManagementAccessException(decision);
        return decision;
    }

    private static void Validate(SaveManagementMetricsConfiguration command)
    {
        if (command.RetentionDays is < 1 or > 3650)
            throw new ManagementValidationException("invalid_retention", "Retention must be between 1 and 3650 days.", "retentionDays");
        if (command.BatchSize is < 1 or > 2000)
            throw new ManagementValidationException("invalid_batch_size", "The batch size must be between 1 and 2000 events.", "batchSize");
        if (command.TimeoutSeconds is < 1 or > 120)
            throw new ManagementValidationException("invalid_timeout", "The timeout must be between 1 and 120 seconds.", "timeoutSeconds");
        var provider = command.Provider.Trim().ToLowerInvariant();
        if (provider is not ("internal" or "victoria_metrics"))
            throw new ManagementValidationException("invalid_provider", "The provider must be internal or victoria_metrics.", "provider");
        if (command.ExportEnabled && provider == "victoria_metrics" &&
            (!Uri.TryCreate(command.Endpoint, UriKind.Absolute, out var uri) || uri.Scheme is not ("http" or "https")))
            throw new ManagementValidationException("invalid_endpoint", "Provide an absolute HTTP(S) endpoint for export.", "endpoint");
    }

    private static IdentityMetricsConfiguration DefaultConfiguration() => new()
    {
        Id = IdentityMetricsConfiguration.SingletonId,
        UpdatedAtUtc = DateTime.UtcNow
    };

    private static ManagementMetricsConfiguration ToContract(IdentityMetricsConfiguration item) =>
        new(item.Enabled, item.RetentionDays, item.ExportEnabled, item.Provider,
            item.Endpoint, item.Database, item.AuthorizationScheme, item.Username,
            !string.IsNullOrWhiteSpace(item.SecretCiphertext), item.TimeoutSeconds,
            item.BatchSize, item.UpdatedAtUtc);

    private static string? NullIfWhiteSpace(string? value) =>
        string.IsNullOrWhiteSpace(value) ? null : value.Trim();

    internal static IQueryable<MetricsDailyAggregate> BuildDailyAggregationQuery(
        IQueryable<IdentityApplicationUsageDaily> query) =>
        query
            .GroupBy(item => new
            {
                item.Day.Year,
                item.Day.Month,
                item.Day.Day,
            })
            .Select(group => new MetricsDailyAggregate
            {
                Year = group.Key.Year,
                Month = group.Key.Month,
                Day = group.Key.Day,
                Count = group.Sum(item => item.Count),
            })
            .OrderBy(item => item.Year)
            .ThenBy(item => item.Month)
            .ThenBy(item => item.Day);

    internal static IQueryable<MetricsDimensionAggregate> BuildGrantAggregationQuery(
        IQueryable<IdentityApplicationUsageDaily> query) =>
        query
            .GroupBy(item => item.GrantType == "" ? "not informed" : item.GrantType)
            .Select(group => new MetricsDimensionAggregate
            {
                Name = group.Key,
                Count = group.Sum(item => item.Count),
            })
            .OrderByDescending(item => item.Count)
            .Take(12);
}

internal sealed class MetricsDailyAggregate
{
    public int Year { get; init; }
    public int Month { get; init; }
    public int Day { get; init; }
    public long Count { get; init; }
}

internal sealed class MetricsDimensionAggregate
{
    public string Name { get; init; } = string.Empty;
    public long Count { get; init; }
}
