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

    /// <summary>Non-secret configuration values before and after an audited mutation.</summary>
    public string? BeforeJson { get; set; }
    public string? AfterJson { get; set; }

    public string? AuthenticationMethods { get; set; }

    /// <summary>
    /// When the event may be pruned. Null follows the deployment's default
    /// retention (<c>AuditRetentionDays</c>, counted from
    /// <see cref="OccurredAtUtc"/>); <see cref="ManagementAuditRetention.Never"/>
    /// keeps it for good.
    /// </summary>
    public DateTime? ExpiresAtUtc { get; set; }
}

/// <summary>Explicit expiry values for <see cref="ManagementAuditEvent.ExpiresAtUtc"/>.</summary>
public static class ManagementAuditRetention
{
    /// <summary>Kept for good: facts that must outlive the default retention, such as who created a system user.</summary>
    public static readonly DateTime Never = new(9999, 12, 31, 0, 0, 0, DateTimeKind.Utc);
}
