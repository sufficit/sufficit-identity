namespace Sufficit.Identity.STS.Metrics;

/// <summary>One application use, and the user it was for when there is one.</summary>
internal sealed record IdentityUsageMetric(
    DateTime OccurredAtUtc,
    string ClientId,
    string EventType,
    string EndpointType,
    string? GrantType,
    string Outcome,
    string? UserId = null);

internal interface IIdentityUsageMetricSink
{
    bool TryRecord(IdentityUsageMetric metric);
}
