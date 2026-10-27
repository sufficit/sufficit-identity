using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.EntityFrameworkCore;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.Core.Maintenance;

namespace Sufficit.Identity.STS.Tokens;

/// <summary>
/// Background sweep that prunes dead OpenIddict tokens and orphaned ad-hoc
/// authorizations past <see cref="TokenPruningOptions.RetentionDays"/>.
/// </summary>
/// <remarks>
/// OpenIddict never deletes token entries by itself: authorization codes and
/// device codes are marked redeemed, revocation is a status flip, and
/// reference tokens stay until something prunes them. Without this sweep the
/// tokens table grows for the life of the deployment — hundreds of megabytes
/// of mostly-dead single-use codes embedded in the database multimaster
/// replication carries between nodes.
/// <para>
/// Pruning retains OpenIddict 7.7.2's eligibility rules and commits bounded
/// token/authorization batches atomically. A valid, unexpired token on a valid
/// authorization is protected regardless of age. Keeping the last child and
/// its eligible parent in one transaction also preserves their application
/// order on a parallel replication receiver.
/// </para>
/// <para>
/// The database owns the schedule and a renewable execution lease. Every batch
/// fences its writes against that lease; replicas may all run this worker.
/// RunInWebHost remains the deployment kill switch during migration.
/// </para>
/// </remarks>
internal sealed class OpenIddictPruningWorker(
    TokenPruningOptions options,
    IServiceProvider services,
    ILogger<OpenIddictPruningWorker> logger) : BackgroundService
{
    private static readonly TimeSpan Interval = TimeSpan.FromSeconds(30);
    private readonly string owner = $"{Environment.MachineName[..Math.Min(Environment.MachineName.Length, 80)]}:{Guid.NewGuid():N}";

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await RunScheduledAsync(stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                return;
            }
            catch (Exception error)
            {
                // Pruning falling behind is an operational problem, never a
                // reason to take the host down.
                logger.LogWarning(error, "OpenIddict token pruning sweep failed.");
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

    internal async Task RunScheduledAsync(CancellationToken cancellationToken)
    {
        await using var scope = services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var run = await TokenMaintenanceCoordinator.TryAcquireAsync(db, owner, cancellationToken);
        if (run == null) return;
        var retention = await db.Set<TokenMaintenance>().Select(x => x.RetentionDays).SingleAsync(cancellationToken);
        var status = "failed";
        try
        {
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            deadline.CancelAfter(TimeSpan.FromMinutes(Math.Clamp(options.TimeoutMinutes, 1, 120)));
            await new OpenIddictPruningService(services).PruneScheduledAsync(retention, run.Id, deadline.Token);
            status = "succeeded";
        }
        finally
        {
            // Cleanup gets a bounded independent deadline on host shutdown.
            // If unavailable, lease expiry permits a successor to recover.
            using var cleanup = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            await using var finishScope = services.CreateAsyncScope();
            var finishDb = finishScope.ServiceProvider.GetRequiredService<AppDbContext>();
            await TokenMaintenanceCoordinator.CompleteAsync(finishDb, run.Id, status, cleanup.Token);
        }
    }

    /// <summary>
    /// A single pruning pass. Internal because the test calls this pass
    /// directly: the scheduling loop is not what it verifies — the retention
    /// rule is.
    /// </summary>
    internal async Task PruneAsync(CancellationToken cancellationToken)
    {
        if (options.RetentionDays <= 0)
        {
            // Explicitly disabled: the deployment keeps history on purpose.
            return;
        }

        var result = await new OpenIddictPruningService(services).PruneAsync(
            options.RetentionDays, cancellationToken);
        logger.LogInformation("Pruned {Tokens} tokens and {Authorizations} authorizations.",
            result.Tokens, result.Authorizations);
    }
}
