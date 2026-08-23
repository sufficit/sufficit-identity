using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Sufficit.Identity.Core.Data;

namespace Sufficit.Identity.Management.Audit;

/// <summary>
/// Prunes management audit history past
/// <see cref="ManagementOptions.AuditRetentionDays"/>.
/// </summary>
/// <remarks>
/// The audit table is append-only and had no retention whatsoever: it grew for
/// the life of the deployment, gaining a row on every privileged operation and
/// — on the surfaces that record them — every refusal. Nothing ever removed
/// one. The metrics table already solved this exact problem
/// (<c>IdentityUsageMetricsWorker</c>); audit simply never got the same
/// treatment.
/// <para>
/// Deletion is batched. A single unbounded <c>DELETE</c> over a table that has
/// accumulated for months is precisely the statement that holds locks long
/// enough to stall the requests this same database is serving, and this
/// deployment replicates multimaster, so one oversized transaction propagates
/// that stall. Small batches with a pause between them trade wall-clock for
/// staying invisible to live traffic.
/// </para>
/// </remarks>
internal sealed class ManagementAuditRetentionWorker(
    IDbContextFactory<AppDbContext> databaseFactory,
    IOptions<ManagementOptions> optionsAccessor,
    ILogger<ManagementAuditRetentionWorker> logger) : BackgroundService
{
    private static readonly TimeSpan Interval = TimeSpan.FromHours(6);

    // Enough to make progress, small enough that the delete holds no lock a
    // live request would notice.
    private const int BatchSize = 5_000;
    private static readonly TimeSpan BetweenBatches = TimeSpan.FromMilliseconds(200);

    // A ceiling on work per pass, so a deployment enabling retention for the
    // first time against years of history sweeps it over several passes rather
    // than in one long transaction.
    private const int MaximumBatchesPerPass = 20;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await PruneAsync(stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                return;
            }
            catch (Exception error)
            {
                // Retention falling behind is an operational problem, never a
                // reason to take the host down.
                logger.LogWarning(error, "Management audit retention sweep failed.");
            }

            try
            {
                await Task.Delay(Interval, stoppingToken);
            }
            catch (OperationCanceledException)
            {
                return;
            }
        }
    }

    private async Task PruneAsync(CancellationToken cancellationToken)
    {
        var retentionDays = optionsAccessor.Value.AuditRetentionDays;
        if (retentionDays <= 0)
        {
            // Explicitly disabled: the deployment keeps everything on purpose.
            return;
        }

        var cutoff = DateTime.UtcNow.AddDays(-retentionDays);
        var removed = 0;

        for (var batch = 0; batch < MaximumBatchesPerPass; batch++)
        {
            await using var database =
                await databaseFactory.CreateDbContextAsync(cancellationToken);
            var deleted = await database.ManagementAuditEvents
                .Where(item => item.OccurredAtUtc < cutoff)
                .OrderBy(item => item.Id)
                .Take(BatchSize)
                .ExecuteDeleteAsync(cancellationToken);

            removed += deleted;
            if (deleted < BatchSize)
            {
                break;
            }

            await Task.Delay(BetweenBatches, cancellationToken);
        }

        if (removed > 0)
        {
            logger.LogInformation(
                "Pruned {Removed} management audit entries older than {RetentionDays} days.",
                removed,
                retentionDays);
        }
    }
}
