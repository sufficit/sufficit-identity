namespace Sufficit.Identity.Vault;

/// <summary>
/// Controls the read snapshot used by the vault. The snapshot keeps encrypted
/// rows and public signing metadata in process memory and optionally mirrors
/// them through the host distributed cache (Redis in a clustered deployment).
/// Plaintext secret values are never stored in either cache.
/// </summary>
public sealed class VaultSnapshotOptions
{
    /// <summary>Enables the local/distributed read snapshot.</summary>
    public bool Enabled { get; init; } = true;

    /// <summary>
    /// How long a local entry may be served without a refresh. A background
    /// refresh normally keeps hot entries inside this window.
    /// </summary>
    public int LocalLifetimeSeconds { get; init; } = 10;

    /// <summary>
    /// Lifetime of the serialized encrypted snapshot in the shared cache.
    /// </summary>
    public int DistributedLifetimeSeconds { get; init; } = 30;

    /// <summary>
    /// Interval used by the background refresher for entries already touched
    /// by a request. A failed refresh never replaces a valid entry.
    /// </summary>
    public int RefreshIntervalSeconds { get; init; } = 10;

    /// <summary>
    /// Upper bound for the number of per-secret entries retained by one
    /// process. This prevents an unbounded context/name cardinality from
    /// becoming a memory leak.
    /// </summary>
    public int MaxEntries { get; init; } = 4096;
}
