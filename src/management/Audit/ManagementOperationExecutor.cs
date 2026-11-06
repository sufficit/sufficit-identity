using Microsoft.Extensions.Logging;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Management.Authorization;

namespace Sufficit.Identity.Management.Audit;

/// <summary>
/// Shared capability demand and best-effort outcome recording for management
/// services. The caller owns mutation transactions and successful audit writes.
/// </summary>
public sealed class ManagementOperationExecutor(
    IManagementAuthorizationEvaluator authorization,
    AppDbContext database,
    ILogger<ManagementOperationExecutor> logger)
{
    /// <summary>
    /// Demand a capability, optionally recording every refusal. Services needing
    /// repeated-denial suppression or fresh-MFA checks use ManagementOperationGuard.
    /// No successful operation is audited here or implicitly committed.
    /// </summary>
    public async Task<ManagementAuthorizationDecision> DemandAsync(
        ManagementRequestContext context,
        string capability,
        ManagementResource resource,
        CancellationToken cancellationToken,
        bool auditDenial = false)
    {
        var decision = await authorization.EvaluateAsync(
            context.Operator, capability, resource, cancellationToken);
        if (decision.IsAllowed)
        {
            return decision;
        }

        if (auditDenial)
        {
            await TryWriteAuditAsync(context, capability, resource, decision,
                "denied", decision.ReasonCode, cancellationToken);
        }

        throw new ManagementAccessException(decision);
    }

    /// <summary>
    /// Best-effort save using the caller's scoped context and current transaction,
    /// if any. Audit failure (including cancellation) must not replace the original
    /// operation outcome. This is not an isolated unit of work or a durable outbox.
    /// </summary>
    public async Task TryWriteAuditAsync(
        ManagementRequestContext context,
        string capability,
        ManagementResource resource,
        ManagementAuthorizationDecision decision,
        string operationOutcome,
        string? reasonCode,
        CancellationToken cancellationToken)
    {
        try
        {
            database.ManagementAuditEvents.Add(ManagementAuditEventFactory.Create(
                context, capability, resource, decision, operationOutcome, reasonCode));
            await database.SaveChangesAsync(cancellationToken);
        }
        catch (Exception exception)
        {
            logger.LogError(exception,
                "Unable to persist management audit event. Capability={Capability} CorrelationId={CorrelationId}",
                capability, context.CorrelationId);
        }
    }
}
