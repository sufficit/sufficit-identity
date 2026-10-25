using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.Management.Audit;
using Sufficit.Identity.Management.Authorization;

namespace Sufficit.Identity.Management.Maintenance;

internal sealed class TokenMaintenanceManagementService(AppDbContext db, ManagementOperationGuard guard)
    : ITokenMaintenanceManagementService
{
    private static readonly ManagementResource Resource = new("token-maintenance", "1");

    public async Task<TokenMaintenanceOverview> GetAsync(ManagementRequestContext context, CancellationToken ct = default)
    {
        await guard.DemandAsync(context, ManagementCapabilities.MaintenanceRead, Resource, ct);
        var job = await db.Set<TokenMaintenance>().AsNoTracking().SingleAsync(x => x.Id == 1, ct);
        var runs = await db.Set<TokenMaintenanceRun>().AsNoTracking().OrderByDescending(x => x.StartedAtUtc)
            .Take(30).Select(x => new TokenMaintenanceHistory(x.Id, x.StartedAtUtc, x.FinishedAtUtc,
                x.Status, x.Tokens, x.Authorizations)).ToListAsync(ct);
        return new(job.Enabled, job.RetentionDays, job.IntervalMinutes, job.Revision,
            job.NextRunAtUtc, job.RunRequested, job.LeaseUntilUtc, runs);
    }

    public Task SaveAsync(SaveTokenMaintenance command, ManagementRequestContext context, CancellationToken ct = default) =>
        MutateAsync(command.Revision, context, job =>
        {
            if (command.RetentionDays is < 1 or > 3650 || command.IntervalMinutes is < 5 or > 10080)
                throw new ManagementValidationException("invalid_maintenance_configuration",
                    "Retention must be 1–3650 days and interval 5–10080 minutes.");
            job.Enabled = command.Enabled;
            job.RetentionDays = command.RetentionDays;
            job.IntervalMinutes = command.IntervalMinutes;
            if (!job.Enabled) job.RunRequested = false;
        }, "maintenance_configuration_updated", ct);

    public Task RequestRunAsync(string revision, ManagementRequestContext context, CancellationToken ct = default) =>
        MutateAsync(revision, context, job =>
        {
            if (!job.Enabled) throw new ManagementValidationException("maintenance_disabled", "Enable maintenance first.");
            // Coalesce repeated requests. A request during a running sweep stays
            // pending, and is consumed by the next successful acquisition.
            job.RunRequested = true;
        }, "maintenance_run_requested", ct);

    private async Task MutateAsync(string revision, ManagementRequestContext context,
        Action<TokenMaintenance> mutation, string reason, CancellationToken ct)
    {
        var decision = await guard.DemandAsync(context, ManagementCapabilities.MaintenanceManage,
            Resource, ct, auditDenial: true);
        var job = await db.Set<TokenMaintenance>().SingleAsync(x => x.Id == 1, ct);
        if (job.Revision != revision) throw Conflict();
        var before = Describe(job);
        mutation(job);
        job.Revision = Guid.NewGuid().ToString("N");
        var audit = ManagementAuditEventFactory.Create(context, ManagementCapabilities.MaintenanceManage,
            Resource, decision, "succeeded", reason);
        audit.BeforeJson = before;
        audit.AfterJson = Describe(job);
        db.ManagementAuditEvents.Add(audit);
        try { await db.SaveChangesAsync(ct); }
        catch (DbUpdateConcurrencyException) { throw Conflict(); }
    }

    private static string Describe(TokenMaintenance job) => JsonSerializer.Serialize(new
        { job.Enabled, job.RetentionDays, job.IntervalMinutes, job.RunRequested });
    private static ManagementValidationException Conflict() => new("maintenance_conflict", "Maintenance changed. Reload before saving.");
}
