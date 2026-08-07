namespace Sufficit.Identity.STS.Metrics;

internal sealed record IdentityUsageMetric(
    DateTime OccurredAtUtc,
    string ClientId,
    string EventType,
    string EndpointType,
    string? GrantType,
    string Outcome,
    string? SubjectHash);

internal interface IIdentityUsageMetricSink
{
    bool TryRecord(IdentityUsageMetric metric);
}
