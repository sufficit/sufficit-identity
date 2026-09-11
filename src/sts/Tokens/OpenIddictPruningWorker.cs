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
/// The store batches deletes internally and the manager calls are idempotent,
/// so the cluster nodes running this sweep concurrently merely race to delete
/// the same rows — the same posture as the management audit retention worker.
/// A failed sweep is an operational problem that logs and waits for the next
/// interval; it is never a reason to take the identity provider down.
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
    /// Uma passada de poda. Interno porque o teste chama esta passada
    /// diretamente: o laço de agendamento não é o que ele verifica — a regra
    /// de retenção é.
    /// </summary>
    internal async Task PruneAsync(CancellationToken cancellationToken)
    {
        if (options.RetentionDays <= 0)
        {
            // Explicitly disabled: the deployment keeps history on purpose.
            return;
        }

        var threshold = DateTimeOffset.UtcNow.AddDays(-options.RetentionDays);

        // The OpenIddict managers are scoped (they consume the scoped
        // AppDbContext) while this worker is a singleton, so each sweep
        // borrows a scope instead of holding a captive dependency.
        await using var scope = services.CreateAsyncScope();
        var tokens = scope.ServiceProvider.GetRequiredService<IOpenIddictTokenManager>();
        var authorizations = scope.ServiceProvider
            .GetRequiredService<IOpenIddictAuthorizationManager>();

        // Tokens first: the authorization sweep only removes authorizations
        // with no remaining tokens, so this ordering lets a single pass
        // retire ad-hoc chains behind the same threshold.
        var removedTokens = await tokens.PruneAsync(threshold, cancellationToken);
        var removedAuthorizations =
            await authorizations.PruneAsync(threshold, cancellationToken);

        if (removedTokens > 0 || removedAuthorizations > 0)
        {
            logger.LogInformation(
                "Pruned {Tokens} tokens and {Authorizations} authorizations older than {RetentionDays} days.",
                removedTokens,
                removedAuthorizations,
                options.RetentionDays);
        }
    }
}
