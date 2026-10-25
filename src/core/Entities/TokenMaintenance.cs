namespace Sufficit.Identity.Core.Entities;

/// <summary>Singleton durable schedule; Revision fences every pruning transaction.</summary>
public sealed class TokenMaintenance
{
    public int Id { get; set; } = 1;
    public bool Enabled { get; set; }
    public int RetentionDays { get; set; } = 30;
    public int IntervalMinutes { get; set; } = 360;
    public DateTime NextRunAtUtc { get; set; } = DateTime.UnixEpoch;
    public bool RunRequested { get; set; }
    public string Revision { get; set; } = "initial";
    public string? Owner { get; set; }
    public DateTime? LeaseUntilUtc { get; set; }
    public string? CurrentRunId { get; set; }
}

/// <summary>Run-level history, without tokens, subjects or database exception text.</summary>
public sealed class TokenMaintenanceRun
{
    public string Id { get; set; } = "";
    public DateTime StartedAtUtc { get; set; }
    public DateTime? FinishedAtUtc { get; set; }
    public string Status { get; set; } = "running";
    public long Tokens { get; set; }
    public long Authorizations { get; set; }
    public string Owner { get; set; } = "";
}
