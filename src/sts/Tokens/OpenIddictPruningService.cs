using System.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.EntityFrameworkCore.Models;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.Core.Maintenance;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Sufficit.Identity.STS.Tokens;

/// <summary>Prunes expired/dead entries in bounded, atomic parent/child batches.</summary>
public sealed class OpenIddictPruningService(IServiceProvider services)
{
    private const int BatchSize = 100;
    private const int MaximumBatches = 10_000;

    public async Task<(long Tokens, long Authorizations)> PruneAsync(
        int retentionDays, CancellationToken cancellationToken)
    {
        await using var scope = services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        if (await db.Set<TokenMaintenance>().AnyAsync(x => x.Enabled, cancellationToken))
            throw new InvalidOperationException("Database-managed maintenance is enabled; request a run through Management.");
        return await PruneCoreAsync(retentionDays, null, cancellationToken);
    }

    internal Task<(long Tokens, long Authorizations)> PruneScheduledAsync(
        int retentionDays, string runId, CancellationToken cancellationToken) =>
        PruneCoreAsync(retentionDays, runId, cancellationToken);

    private async Task<(long Tokens, long Authorizations)> PruneCoreAsync(
        int retentionDays, string? runId, CancellationToken cancellationToken)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(retentionDays);
        var threshold = DateTime.UtcNow.AddDays(-retentionDays);
        long tokens = 0, authorizations = 0;

        // Handle existing orphans BEFORE deleting tokens. Thereafter every
        // eligible parent is removed in the batch that deletes its last child,
        // so that these deletes cannot become independently applied writesets.
        for (var index = 0; index < MaximumBatches; index++)
        {
            var batch = await PruneBatchAsync(threshold, pruneTokens: false, runId, cancellationToken);
            authorizations += batch.Authorizations;
            if (batch.Authorizations == 0) break;
        }

        for (var index = 0; index < MaximumBatches; index++)
        {
            var batch = await PruneBatchAsync(threshold, pruneTokens: true, runId, cancellationToken);
            tokens += batch.Tokens;
            authorizations += batch.Authorizations;
            if (batch.Tokens == 0) break;
        }
        return (tokens, authorizations);
    }

    private async Task<(int Tokens, int Authorizations)> PruneBatchAsync(
        DateTime threshold, bool pruneTokens, string? runId, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        await using var scope = services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        return await db.Database.CreateExecutionStrategy().ExecuteAsync(async () =>
        {
            // This context belongs exclusively to this batch. A provider retry
            // must not reuse entities detached/modified by an earlier attempt.
            db.ChangeTracker.Clear();
            await using var transaction = await db.Database.BeginTransactionAsync(
                IsolationLevel.RepeatableRead, cancellationToken);
            if (runId != null)
            {
                await TokenMaintenanceCoordinator.FenceAsync(db, runId, cancellationToken);
                await db.SaveChangesAsync(cancellationToken);
            }
            else
            {
                // Legacy CLI also touches the coordination row per batch. An
                // operator enabling managed execution races through the same
                // certification key, never around the ownership barrier.
                var job = await db.Set<TokenMaintenance>().SingleAsync(x => x.Id == 1, cancellationToken);
                if (job.Enabled) throw new InvalidOperationException("Database-managed maintenance is enabled.");
                job.Revision = Guid.NewGuid().ToString("N");
                await db.SaveChangesAsync(cancellationToken);
            }
            var parents = db.Set<OpenIddictEntityFrameworkCoreAuthorization>()
                .Where(authorization => authorization.CreationDate < threshold &&
                    (authorization.Status != Statuses.Valid || authorization.Type == AuthorizationTypes.AdHoc));
            var removedTokens = 0;
            if (pruneTokens)
            {
                var now = DateTime.UtcNow;
                // Same eligibility predicate as OpenIddict 7.7.2. In particular,
                // age alone never deletes a live token on a valid authorization.
                var batch = await db.Set<OpenIddictEntityFrameworkCoreToken>()
                    .Where(token => token.CreationDate < threshold &&
                        ((token.Status != Statuses.Inactive && token.Status != Statuses.Valid) ||
                         (token.Authorization != null && token.Authorization.Status != Statuses.Valid) ||
                         token.ExpirationDate < now))
                    .OrderBy(token => token.Id).Take(BatchSize)
                    .Select(token => new { Token = token,
                        AuthorizationId = token.Authorization == null ? null : token.Authorization.Id })
                    .ToListAsync(cancellationToken);
                removedTokens = batch.Count;
                if (removedTokens == 0) return (0, 0);
                var parentIds = batch.Where(entry => entry.AuthorizationId != null)
                    .Select(entry => entry.AuthorizationId!).Distinct().ToArray();
                db.RemoveRange(batch.Select(entry => entry.Token));
                await db.SaveChangesAsync(cancellationToken);
                parents = parents.Where(authorization => parentIds.Contains(authorization.Id));
            }

            var orphaned = await parents.Where(authorization => !authorization.Tokens.Any())
                .OrderBy(authorization => authorization.Id).Take(BatchSize)
                .ToListAsync(cancellationToken);
            db.RemoveRange(orphaned);
            await db.SaveChangesAsync(cancellationToken);
            // Both SaveChanges calls share this transaction. On FK/concurrency
            // failure or cancellation, disposal rolls back this entire batch.
            if (runId != null)
            {
                var run = await db.Set<TokenMaintenanceRun>().SingleAsync(x => x.Id == runId, cancellationToken);
                run.Tokens += removedTokens;
                run.Authorizations += orphaned.Count;
                await db.SaveChangesAsync(cancellationToken);
            }
            await transaction.CommitAsync(cancellationToken);
            return (removedTokens, orphaned.Count);
        });
    }
}
