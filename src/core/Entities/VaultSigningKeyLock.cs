namespace Sufficit.Identity.Core.Entities;

/// <summary>Database-backed distributed lease serializing lifecycle changes
/// for a named signing key across replicas.</summary>
public sealed class VaultSigningKeyLock
{
    public string KeyName { get; set; } = string.Empty;
    public string OwnerId { get; set; } = string.Empty;
    public DateTime ExpiresAtUtc { get; set; }
}
