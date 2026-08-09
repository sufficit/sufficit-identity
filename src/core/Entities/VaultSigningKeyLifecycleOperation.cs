namespace Sufficit.Identity.Core.Entities;

/// <summary>Secret-free, idempotent journal entry for a signing-key lifecycle
/// operation. The operation id is supplied by the caller for safe retries.</summary>
public sealed class VaultSigningKeyLifecycleOperation
{
    public string OperationId { get; set; } = string.Empty;
    public string KeyName { get; set; } = string.Empty;
    public int KeyVersion { get; set; }
    public int? PreviousKeyVersion { get; set; }
    public string Action { get; set; } = string.Empty;
    public string? Reason { get; set; }
    public DateTime OccurredAtUtc { get; set; }
    public DateTime? RetireAfterUtc { get; set; }
}
