namespace Sufficit.Identity.Core.Entities;

/// <summary>
/// Privacy-safe, append-only observation of an OAuth/OIDC application use.
/// Authentication never waits for this row to be written: events reach the
/// database exclusively through a bounded background channel.
/// </summary>
public sealed class IdentityApplicationUsageEvent
{
    public long Id { get; set; }
    public DateTime OccurredAtUtc { get; set; }
    public string ClientId { get; set; } = string.Empty;
    public string EventType { get; set; } = string.Empty;
    public string EndpointType { get; set; } = string.Empty;
    public string? GrantType { get; set; }
    public string Outcome { get; set; } = "succeeded";
    public string? SubjectHash { get; set; }
}
