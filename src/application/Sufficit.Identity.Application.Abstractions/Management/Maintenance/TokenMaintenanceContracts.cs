using Sufficit.Identity.Management.Authorization;

namespace Sufficit.Identity.Management.Maintenance;

public interface ITokenMaintenanceManagementService
{
    Task<TokenMaintenanceOverview> GetAsync(ManagementRequestContext context, CancellationToken ct = default);
    Task SaveAsync(SaveTokenMaintenance command, ManagementRequestContext context, CancellationToken ct = default);
    Task RequestRunAsync(string revision, ManagementRequestContext context, CancellationToken ct = default);
}
public sealed record SaveTokenMaintenance(string Revision, bool Enabled, int RetentionDays, int IntervalMinutes);
public sealed record RequestTokenMaintenance(string Revision);
public sealed record TokenMaintenanceOverview(bool Enabled, int RetentionDays, int IntervalMinutes,
    string Revision, DateTime NextRunAtUtc, bool RunRequested, DateTime? LeaseUntilUtc,
    IReadOnlyList<TokenMaintenanceHistory> Runs);
public sealed record TokenMaintenanceHistory(string Id, DateTime StartedAtUtc, DateTime? FinishedAtUtc,
    string Status, long Tokens, long Authorizations);
