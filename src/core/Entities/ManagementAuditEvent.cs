namespace Sufficit.Identity.Core.Entities;

/// <summary>
/// Append-only record of an administrative authorization decision and its
/// operation outcome. Sensitive request payloads and credentials never belong
/// in this entity.
/// </summary>
public sealed class ManagementAuditEvent
{
    public long Id { get; set; }

    public DateTime OccurredAtUtc { get; set; }

    public string OperatorSubject { get; set; } = string.Empty;

    public string? OperatorDisplayName { get; set; }

    public string Capability { get; set; } = string.Empty;

    public string ResourceType { get; set; } = string.Empty;

    public string? ResourceId { get; set; }

    public string? ContextId { get; set; }

    public string AuthorizationOutcome { get; set; } = string.Empty;

    public string OperationOutcome { get; set; } = string.Empty;

    public string? ReasonCode { get; set; }

    public string CorrelationId { get; set; } = string.Empty;

    public string? AuthenticationMethods { get; set; }
}
