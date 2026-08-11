#if !APPLICATION_CONTRACTS
using Microsoft.EntityFrameworkCore;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Core.Entities;
#endif
using Sufficit.Identity.Management.Authorization;

namespace Sufficit.Identity.Management.Audit;

#if APPLICATION_CONTRACTS

public interface IManagementAuditService
{
    Task<IReadOnlyList<ManagementAuditRecord>> ListAsync(
        ManagementRequestContext context,
        int limit = 100,
        CancellationToken cancellationToken = default);
}

public sealed record ManagementAuditRecord(
    long Id,
    DateTime OccurredAtUtc,
    string OperatorSubject,
    string? OperatorDisplayName,
    string Capability,
    string ResourceType,
    string? ResourceId,
    string? TenantId,
    string AuthorizationOutcome,
    string OperationOutcome,
    string? ReasonCode,
    string CorrelationId,
    string? AuthenticationMethods);

#else

internal sealed class ManagementAuditService(
    AppDbContext database,
    IManagementAuthorizationEvaluator authorization) : IManagementAuditService
{
    public async Task<IReadOnlyList<ManagementAuditRecord>> ListAsync(
        ManagementRequestContext context,
        int limit = 100,
        CancellationToken cancellationToken = default)
    {
        var decision = await authorization.EvaluateAsync(
            context.Operator,
            ManagementCapabilities.AuditRead,
            new ManagementResource(ManagementResourceTypes.Audit),
            cancellationToken);

        if (!decision.IsAllowed)
        {
            throw new ManagementAccessException(decision);
        }

        var boundedLimit = Math.Clamp(limit, 1, 250);

        return await database.ManagementAuditEvents
            .AsNoTracking()
            .OrderByDescending(entry => entry.OccurredAtUtc)
            .ThenByDescending(entry => entry.Id)
            .Take(boundedLimit)
            .Select(entry => new ManagementAuditRecord(
                entry.Id,
                entry.OccurredAtUtc,
                entry.OperatorSubject,
                entry.OperatorDisplayName,
                entry.Capability,
                entry.ResourceType,
                entry.ResourceId,
                entry.ContextId,
                entry.AuthorizationOutcome,
                entry.OperationOutcome,
                entry.ReasonCode,
                entry.CorrelationId,
                entry.AuthenticationMethods))
            .ToArrayAsync(cancellationToken);
    }
}

internal static class ManagementAuditEventFactory
{
    public static ManagementAuditEvent Create(
        ManagementRequestContext context,
        string capability,
        ManagementResource resource,
        ManagementAuthorizationDecision authorization,
        string operationOutcome,
        string? reasonCode = null) =>
        new()
        {
            OccurredAtUtc = DateTime.UtcNow,
            OperatorSubject = TruncateRequired(context.OperatorSubject, 255),
            OperatorDisplayName = Truncate(context.OperatorDisplayName, 255),
            Capability = TruncateRequired(capability, 150),
            ResourceType = TruncateRequired(resource.Type, 100),
            ResourceId = Truncate(resource.Id, 255),
            ContextId = Truncate(resource.TenantId, 255),
            AuthorizationOutcome = authorization.Outcome.ToString().ToLowerInvariant(),
            OperationOutcome = TruncateRequired(operationOutcome, 50),
            ReasonCode = Truncate(reasonCode ?? authorization.ReasonCode, 100),
            CorrelationId = TruncateRequired(context.CorrelationId, 100),
            AuthenticationMethods = Truncate(context.AuthenticationMethods, 255)
        };

    private static string TruncateRequired(string value, int maxLength) =>
        value.Length <= maxLength ? value : value[..maxLength];

    private static string? Truncate(string? value, int maxLength) =>
        value is null || value.Length <= maxLength ? value : value[..maxLength];
}
#endif
