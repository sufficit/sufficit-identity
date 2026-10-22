namespace Sufficit.Identity.STS.Metrics;

/// <summary>One application use. No user: usage metrics count applications, they do not track people.</summary>
internal sealed record IdentityUsageMetric(
    DateTime OccurredAtUtc,
    string ClientId,
    string EventType,
    string EndpointType,
    string? GrantType,
    string Outcome);

internal interface IIdentityUsageMetricSink
{
    bool TryRecord(IdentityUsageMetric metric);
}
