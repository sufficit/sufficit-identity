using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using OpenIddict.Abstractions;

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
/// Pruning uses OpenIddict's supported mechanism:
/// <see cref="IOpenIddictTokenManager.PruneAsync(DateTimeOffset, CancellationToken)"/>
/// only removes entries created before the threshold that are ALREADY dead —
/// status revoked/rejected/inactive, or bound to an authorization that is no
/// longer valid, or past their expiration. A valid, unexpired refresh token
/// created before the threshold is never touched.
/// </para>
/// <para>
/// Deployments sharing a replicated database should disable this worker on
/// every API replica and schedule the maintenance command on one owner.
/// Pruning remains idempotent to tolerate scheduler retries.
/// </para>
/// </remarks>
internal sealed class OpenIddictPruningWorker(
    TokenPruningOptions options,
    IServiceProvider services,
    ILogger<OpenIddictPruningWorker> logger) : BackgroundService
{
    private static readonly TimeSpan Interval = TimeSpan.FromHours(6);

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
