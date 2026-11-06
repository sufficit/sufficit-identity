using Sufficit.Identity.Management.Authorization;

namespace Sufficit.Identity.Management.Audit;

public interface IManagementAuditService
{
    Task<ManagementAuditPage> SearchAsync(
        ManagementRequestContext context,
        ManagementAuditQuery query,
        CancellationToken cancellationToken = default);

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
    string? AuthenticationMethods,
    string? BeforeJson = null,
    string? AfterJson = null);

/// <summary>Exact resource filters and a half-open UTC interval. Reuse filters when following a cursor.</summary>
public sealed record ManagementAuditQuery(
    string? ResourceType = null,
    string? ResourceId = null,
    DateTimeOffset? FromUtc = null,
    DateTimeOffset? ToUtc = null,
    int Limit = 100,
    string? Cursor = null);

public sealed record ManagementAuditPage(
    IReadOnlyList<ManagementAuditRecord> Items,
    string? NextCursor);
