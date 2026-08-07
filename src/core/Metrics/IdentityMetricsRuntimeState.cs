namespace Sufficit.Identity.Core.Metrics;

/// <summary>Lock-free operational snapshot shared by collection and management.</summary>
public sealed class IdentityMetricsRuntimeState
{
    private long _accepted;
    private long _dropped;
    private long _persisted;
    private long _exported;
    private long _failures;
    private long _queueDepth;

    public long Accepted => Interlocked.Read(ref _accepted);
    public long Dropped => Interlocked.Read(ref _dropped);
    public long Persisted => Interlocked.Read(ref _persisted);
    public long Exported => Interlocked.Read(ref _exported);
    public long Failures => Interlocked.Read(ref _failures);
    public long QueueDepth => Interlocked.Read(ref _queueDepth);
    public DateTime? LastPersistedAtUtc { get; private set; }
    public DateTime? LastExportedAtUtc { get; private set; }

    public void AcceptedOne() => Interlocked.Increment(ref _accepted);
    public void DroppedOne() => Interlocked.Increment(ref _dropped);
    public void SetQueueDepth(long value) => Interlocked.Exchange(ref _queueDepth, value);
    public void PersistedMany(int count)
    {
        Interlocked.Add(ref _persisted, count);
        LastPersistedAtUtc = DateTime.UtcNow;
    }
    public void ExportedMany(int count)
    {
        Interlocked.Add(ref _exported, count);
        LastExportedAtUtc = DateTime.UtcNow;
    }
    public void FailedOne() => Interlocked.Increment(ref _failures);
}
