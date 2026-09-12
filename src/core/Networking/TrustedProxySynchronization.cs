namespace Sufficit.Identity.Core.Networking;

public sealed class TrustedProxySynchronizationOptions
{
    public int ReconcileSeconds { get; set; } = 30;
    public int MaxStaleSeconds { get; set; } = 120;
    public int RefreshTimeoutSeconds { get; set; } = 10;

    /// <summary>
    /// What forwarding does when the database-managed proxy list has not been
    /// confirmed within <see cref="MaxStaleSeconds"/>.
    /// </summary>
    /// <remarks>
    /// The default degrades to the file-configured proxies. That trusts fewer
    /// peers, never more — a proxy an operator just removed from the database
    /// is not trusted while the database is unreachable — and it keeps every
    /// node serving through a database outage instead of refusing all traffic
    /// at the same moment.
    /// </remarks>
    public TrustedProxyStaleSnapshotMode StaleSnapshotMode { get; set; } =
        TrustedProxyStaleSnapshotMode.FileBaseline;

    public void Validate()
    {
        if (ReconcileSeconds is < 1 or > 3600 || MaxStaleSeconds < ReconcileSeconds * 2
            || MaxStaleSeconds > 86400 || RefreshTimeoutSeconds is < 1 or > 60
            || !Enum.IsDefined(StaleSnapshotMode))
            throw new ArgumentException("Invalid trusted proxy synchronization settings.");
    }
}

/// <summary>Behavior when the database-managed proxy list is stale.</summary>
public enum TrustedProxyStaleSnapshotMode
{
    /// <summary>
    /// Forward only through the proxies listed in configuration files until the
    /// database confirms the list again. Traffic keeps flowing.
    /// </summary>
    FileBaseline,

    /// <summary>
    /// Refuse traffic with 503 until the database confirms the list again.
    /// Liveness is still answered, so a process that is merely waiting on the
    /// database is not restarted in a loop.
    /// </summary>
    Reject,
}

/// <summary>Which proxy list forwarding is using right now.</summary>
public enum TrustedProxySnapshotState
{
    /// <summary>The full list was confirmed within its freshness limit.</summary>
    Fresh,

    /// <summary>Stale; forwarding trusts only the file-configured proxies.</summary>
    StaleFileBaseline,

    /// <summary>Stale; traffic is refused.</summary>
    StaleRejected,
}

/// <summary>
/// The snapshot forwarding must apply, together with the state that produced
/// it. <see cref="Snapshot"/> is null only when traffic must be refused.
/// </summary>
public readonly record struct TrustedProxyForwarding(
    TrustedProxySnapshotState State,
    TrustedProxySnapshot? Snapshot);

/// <summary>Best-effort notification only; the database remains authoritative.</summary>
public interface ITrustedProxyChangePublisher
{
    bool Enabled { get; }
    bool Connected { get; }
    Task<bool> PublishAsync(string revision, CancellationToken cancellationToken);
}

public sealed record TrustedProxySyncDiagnostics(DateTimeOffset? LastConfirmedAtUtc = null,
    DateTimeOffset? LastChangedAtUtc = null, long Generation = 0, long RevisionReads = 0,
    long ContentReads = 0, int ConsecutiveFailures = 0, bool NotificationPending = false);
