using Sufficit.Identity.Management.Authorization;

namespace Sufficit.Identity.Management.Audit;

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
    string? ContextId,
    string AuthorizationOutcome,
    string OperationOutcome,
    string? ReasonCode,
    string CorrelationId,
    string? AuthenticationMethods);
