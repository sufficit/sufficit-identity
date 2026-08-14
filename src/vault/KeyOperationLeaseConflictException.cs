namespace Sufficit.Identity.Vault;

/// <summary>
/// Thrown when the per-key-name distributed operation lease is held by
/// another replica and no expired lease is available for recovery. Callers
/// that can absorb the race (symmetric first-use creation) retry with a
/// bounded re-read; operator-driven actions (rotation) surface the error.
/// </summary>
internal sealed class KeyOperationLeaseConflictException(
    string keyName)
    : InvalidOperationException(
        $"A key lifecycle operation for '{keyName}' is already running on another replica.")
{
    public string KeyName { get; } = keyName;
}
