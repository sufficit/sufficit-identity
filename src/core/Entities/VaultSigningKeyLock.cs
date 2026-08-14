namespace Sufficit.Identity.Core.Entities;

/// <summary>Database-backed distributed lease serializing key lifecycle
/// changes for a named key across replicas. Used by the signing-key
/// rotate/retire/revoke lifecycle AND (since eval 2026-08-14, F-7) by
/// symmetric DEK first-use creation and rotation, so concurrent replicas
/// cannot race version allocation on the (KeyName, KeyVersion) unique
/// index. The table name keeps its historical "signing" spelling; the row
/// is a generic per-key-name operation lease.</summary>
public sealed class VaultSigningKeyLock
{
    public string KeyName { get; set; } = string.Empty;
    public string OwnerId { get; set; } = string.Empty;
    public DateTime ExpiresAtUtc { get; set; }
}
