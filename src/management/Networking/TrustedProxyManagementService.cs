using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Core.Networking;
using Sufficit.Identity.Management.Audit;
using Sufficit.Identity.Management.Authorization;

namespace Sufficit.Identity.Management.Networking;

internal sealed class TrustedProxyManagementService(AppDbContext database,
    ManagementOperationGuard guard, TrustedProxySnapshotStore snapshots) : ITrustedProxyManagementService
{
    private static readonly ManagementResource Resource = new(ManagementResourceTypes.TrustedProxies, "1");

    public async Task<ManagementTrustedProxies> GetAsync(ManagementRequestContext context,
        CancellationToken cancellationToken = default)
    {
        await guard.DemandAsync(context, ManagementCapabilities.TrustedProxiesRead, Resource, cancellationToken);
        // A management page may request a fresh read; forwarded HTTP requests never do.
        await snapshots.RefreshAsync(cancellationToken);
        return ToContract(snapshots.Current);
    }

    public async Task<ManagementTrustedProxies> SaveAsync(SaveTrustedProxies command,
        ManagementRequestContext context, CancellationToken cancellationToken = default)
    {
        var decision = await guard.DemandAsync(context, ManagementCapabilities.TrustedProxiesManage,
            Resource, cancellationToken, auditDenial: true);
        ArgumentNullException.ThrowIfNull(command);
        string[] networks;
        try
        {
            networks = TrustedProxyValidation.Normalize(command.Networks
                ?? throw new ArgumentException("Informe a lista de proxies.")).ToArray();
            TrustedProxyValidation.ValidateForwardLimit(command.ForwardLimit);
        }
        catch (ArgumentException exception)
        {
            throw new ManagementValidationException("invalid_trusted_proxy_configuration", exception.Message);
        }
        await snapshots.CommitAsync(async commitToken =>
        {
            var entity = await database.TrustedProxyConfigurations.SingleAsync(x => x.Id == 1, commitToken);
            if (command.Revision != entity.Revision) throw Conflict();
            var before = entity.NetworksJson;
            var beforeLimit = entity.ForwardLimit;
            entity.NetworksJson = JsonSerializer.Serialize(networks);
            entity.ForwardLimit = command.ForwardLimit;
            entity.Revision = Guid.NewGuid().ToString("N");
            entity.UpdatedAtUtc = DateTime.UtcNow;
            var audit = ManagementAuditEventFactory.Create(context, ManagementCapabilities.TrustedProxiesManage,
                Resource, decision, "succeeded", "trusted_proxies_updated");
            audit.BeforeJson = JsonSerializer.Serialize(new { Networks = JsonSerializer.Deserialize<string[]>(before), ForwardLimit = beforeLimit });
            audit.AfterJson = JsonSerializer.Serialize(new { Networks = networks, command.ForwardLimit });
            database.ManagementAuditEvents.Add(audit);
            try { await database.SaveChangesAsync(commitToken); }
            catch (DbUpdateConcurrencyException) { throw Conflict(); }
            return entity;
        }, cancellationToken);
        return ToContract(snapshots.Current);
    }

    private static ManagementValidationException Conflict() => new("trusted_proxy_conflict",
        "A configuração foi alterada por outro operador. Recarregue antes de salvar.");

    private ManagementTrustedProxies ToContract(TrustedProxySnapshot s) => new(
        s.FileNetworks, s.DatabaseNetworks, s.EffectiveNetworks, s.FileForwardLimit,
        s.DatabaseForwardLimit, s.ForwardLimit, s.Revision, s.UpdatedAtUtc, snapshots.Synchronization.ReconcileSeconds,
        snapshots.NotificationsEnabled, snapshots.NotificationsConnected, snapshots.Diagnostics.NotificationPending,
        snapshots.Diagnostics.LastConfirmedAtUtc, snapshots.Diagnostics.Generation, snapshots.IsFresh);
}
