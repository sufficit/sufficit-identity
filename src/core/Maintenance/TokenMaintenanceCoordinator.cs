using Microsoft.EntityFrameworkCore;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Core.Entities;

namespace Sufficit.Identity.Core.Maintenance;

/// <summary>
/// Optimistic replicated-row ownership. Every destructive batch writes Revision
/// in the SAME transaction as its deletes, so Galera certification fences a
/// stale writer even when it obtained a local row lock on another cluster node.
/// </summary>
public static class TokenMaintenanceCoordinator
{
    public static async Task<DateTime> UtcNowAsync(AppDbContext db, CancellationToken ct) =>
        db.Database.IsMySql()
            ? await db.Database.SqlQueryRaw<DateTime>("SELECT UTC_TIMESTAMP(6) AS Value").SingleAsync(ct)
            : DateTime.UtcNow;

    public static async Task<TokenMaintenanceRun?> TryAcquireAsync(
        AppDbContext db, string owner, CancellationToken ct)
    {
        var now = await UtcNowAsync(db, ct);
        var job = await db.Set<TokenMaintenance>().SingleAsync(x => x.Id == 1, ct);
        if (!job.Enabled || job.LeaseUntilUtc > now || (!job.RunRequested && job.NextRunAtUtc > now))
            return null;
        if (job.CurrentRunId is { } previous)
        {
            var abandoned = await db.Set<TokenMaintenanceRun>().SingleAsync(x => x.Id == previous, ct);
            abandoned.Status = "interrupted";
            abandoned.FinishedAtUtc = now;
        }
        var run = new TokenMaintenanceRun
        {
            Id = Guid.NewGuid().ToString("N"), Owner = owner, StartedAtUtc = now
        };
        job.Owner = owner;
        job.CurrentRunId = run.Id;
        job.LeaseUntilUtc = now.AddMinutes(2);
        job.RunRequested = false;
        job.Revision = Guid.NewGuid().ToString("N");
        db.Add(run);
        // SaveChanges commits the claim before any pruning may begin. A loser
        // on a different Galera writer fails certification at this boundary.
        await db.SaveChangesAsync(ct);
        return run;
    }

    public static async Task<TokenMaintenance> FenceAsync(AppDbContext db, string runId, CancellationToken ct)
    {
        var now = await UtcNowAsync(db, ct);
        var job = await db.Set<TokenMaintenance>().SingleAsync(x => x.Id == 1, ct);
        if (!job.Enabled || job.CurrentRunId != runId || job.LeaseUntilUtc is null || job.LeaseUntilUtc <= now)
            throw new InvalidOperationException("Token maintenance ownership was lost or disabled.");
        job.Revision = Guid.NewGuid().ToString("N");
        job.LeaseUntilUtc = now.AddMinutes(2);
        return job;
    }

    public static async Task CompleteAsync(AppDbContext db, string runId, string status, CancellationToken ct)
    {
        var job = await db.Set<TokenMaintenance>().SingleAsync(x => x.Id == 1, ct);
        // Never overwrite a successor's state. An abandoned run is closed by
        // the next acquisition, including after a process crash.
        if (job.CurrentRunId != runId) return;
        var now = await UtcNowAsync(db, ct);
        var run = await db.Set<TokenMaintenanceRun>().SingleAsync(x => x.Id == runId, ct);
        run.Status = status;
        run.FinishedAtUtc = now;
        job.Revision = Guid.NewGuid().ToString("N");
        job.NextRunAtUtc = now.AddMinutes(status == "succeeded" ? job.IntervalMinutes : 5);
        job.Owner = null;
        job.CurrentRunId = null;
        job.LeaseUntilUtc = null;
        await db.SaveChangesAsync(ct);
    }
}
