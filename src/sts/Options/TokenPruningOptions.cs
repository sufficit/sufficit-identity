namespace Sufficit.Identity.STS;

/// <summary>
/// Retention policy for dead OpenIddict tokens and orphaned authorizations,
/// applied by the background <c>OpenIddictPruningWorker</c>.
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
}
