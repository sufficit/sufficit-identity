namespace Sufficit.Identity.STS;

/// <summary>
/// Retention policy for dead OpenIddict tokens and orphaned authorizations,
/// applied by the maintenance command or optional background worker.
/// Bound from <c>Sufficit:Identity:TokenPruning</c>.
/// </summary>
public sealed class TokenPruningOptions
{
    /// <summary>
    /// Prunes token entries created more than this many days ago that are
    /// already dead — revoked/rejected/inactive status, bound to an invalid
    /// authorization, or past their expiration date. Valid, unexpired tokens
    /// are never pruned regardless of age, so retention can be short without
    /// risking live sessions. Zero or negative disables pruning entirely
    /// (the deployment keeps everything on purpose).
    /// </summary>
    public int RetentionDays { get; init; } = 30;

    /// <summary>Disable on every API replica when an external scheduler owns pruning.</summary>
    public bool RunInWebHost { get; init; } = true;

    /// <summary>Absolute path on durable storage, shared by the job and its watchdog.</summary>
    public string? StatePath { get; init; }

    /// <summary>Maximum age of the last successful sweep before the watchdog fails.</summary>
    public int AlertAfterHours { get; init; } = 14;

    /// <summary>Cooperative deadline; the scheduler must also enforce a hard deadline.</summary>
    public int TimeoutMinutes { get; init; } = 30;
}
