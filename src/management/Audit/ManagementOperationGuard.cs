using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Management.Authorization;

namespace Sufficit.Identity.Management.Audit;

/// <summary>
/// Authorizes a management operation and records the outcome when it is
/// refused.
/// </summary>
/// <remarks>
/// Every management service opened its operations with the same pair of
/// private helpers — evaluate the capability, throw on refusal, and (in some
/// of them) write an audit row first. Twelve copies had drifted apart, and the
/// drift was not cosmetic: four services audited refusals, six discarded them
/// silently, and one had already invented a flag to choose. A thirteenth copy
/// was about to be created for the credential registry.
/// <para>
/// <b>The divergence is preserved, not erased.</b> Whether a refusal is
/// recorded is now an explicit argument at the call site rather than a
/// property of whichever copy a service inherited. Unifying it outright would
/// have silently changed behavior in either six services or four, and deciding
/// which refusals matter is a per-surface judgement — this type makes that
/// judgement visible and greppable so it can be made deliberately.
/// </para>
/// <para>
/// Only the REFUSAL path lives here. A successful mutation records its audit
/// row inside the operation's own transaction, so it commits atomically with
/// the change it describes; that guarantee is the point and is deliberately
/// left in the services. A refusal has no such transaction — the operation is
/// about to throw — so it needs its own save, and a failure to record it must
/// never mask the authorization error the caller is owed.
/// </para>
/// </remarks>
internal sealed class ManagementOperationGuard(
    IManagementAuthorizationEvaluator authorization,
    AppDbContext database,
    ILogger<ManagementOperationGuard> logger)
{
    /// <summary>
    /// Evaluates <paramref name="capability"/> against
    /// <paramref name="resource"/> and returns the decision, throwing
    /// <see cref="ManagementAccessException"/> when it is refused.
    /// </summary>
    /// <param name="auditDenial">
    /// Records the refusal before throwing. Off by default so a caller that
    /// has not considered the question keeps the quieter behavior rather than
    /// silently gaining writes on a hot read path.
    /// </param>
    public async Task<ManagementAuthorizationDecision> DemandAsync(
        ManagementRequestContext context,
        string capability,
        ManagementResource resource,
        CancellationToken cancellationToken,
        bool auditDenial = false)
    {
        var decision = await authorization.EvaluateAsync(
            context.Operator,
            capability,
            resource,
            cancellationToken);

        if (decision.IsAllowed)
        {
            return decision;
        }

        if (auditDenial)
        {
            await TryWriteAuditAsync(
                context,
                capability,
                resource,
                decision,
                "denied",
                decision.ReasonCode,
                cancellationToken);
        }

        throw new ManagementAccessException(decision);
    }

    /// <summary>
    /// Persists an audit row on its own, outside any surrounding transaction.
    /// Failures are logged and swallowed: losing the record of a refusal is
    /// bad, but replacing the caller's authorization error with a database
    /// error is worse — it would turn "you may not do this" into "something
    /// broke", which is both less accurate and less actionable.
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
                context,
                capability,
                resource,
                decision,
                operationOutcome,
                reasonCode));
            await database.SaveChangesAsync(cancellationToken);
        }
        catch (Exception exception)
        {
            logger.LogError(
                exception,
                "Unable to persist management audit event. Capability={Capability} CorrelationId={CorrelationId}",
                capability,
                context.CorrelationId);
        }
    }
}
