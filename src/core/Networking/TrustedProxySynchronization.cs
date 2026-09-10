namespace Sufficit.Identity.Core.Networking;

public sealed class TrustedProxySynchronizationOptions
{
    public int ReconcileSeconds { get; set; } = 30;
    public int MaxStaleSeconds { get; set; } = 120;
    public int RefreshTimeoutSeconds { get; set; } = 10;

    public void Validate()
    {
        if (ReconcileSeconds is < 1 or > 3600 || MaxStaleSeconds < ReconcileSeconds * 2
            || MaxStaleSeconds > 86400 || RefreshTimeoutSeconds is < 1 or > 60)
            throw new ArgumentException("Invalid trusted proxy synchronization intervals.");
    }
}

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
