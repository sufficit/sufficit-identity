using System.Diagnostics.Metrics;

namespace Sufficit.Identity.STS;

public interface ISecurityDecisionTelemetry
{
    void Record(
        string policy,
        string mode,
        bool wouldReject,
        bool rejected,
        IEnumerable<string>? reasonCodes = null);
}

/// <summary>
/// Low-cardinality, PII-free security decision instruments. Subject, client,
/// token and resource identifiers are deliberately excluded from metric tags.
/// </summary>
internal sealed class SecurityDecisionTelemetry : ISecurityDecisionTelemetry
{
    private static readonly Meter Meter = new(
        "Sufficit.Identity.Security",
        "1.0.0");
    private static readonly Counter<long> Decisions = Meter.CreateCounter<long>(
        "identity.security.policy.decisions");
    private static readonly Counter<long> CompatibilityFallbacks =
        Meter.CreateCounter<long>(
            "identity.security.policy.compatibility_fallbacks");

    public void Record(
        string policy,
        string mode,
        bool wouldReject,
        bool rejected,
        IEnumerable<string>? reasonCodes = null)
    {
        var outcome = rejected
            ? "rejected"
            : wouldReject ? "compatibility_allowed" : "allowed";
        var reasons = (reasonCodes ?? [])
            .Where(reason => !string.IsNullOrWhiteSpace(reason))
            .Distinct(StringComparer.Ordinal)
            .DefaultIfEmpty("allowed");
        foreach (var reason in reasons)
        {
            Decisions.Add(
                1,
                new KeyValuePair<string, object?>("policy", policy),
                new KeyValuePair<string, object?>("mode", mode),
                new KeyValuePair<string, object?>("outcome", outcome),
                new KeyValuePair<string, object?>("reason", reason));
        }

        if (wouldReject && !rejected)
        {
            CompatibilityFallbacks.Add(
                1,
                new KeyValuePair<string, object?>("policy", policy),
                new KeyValuePair<string, object?>("mode", mode));
        }
    }
}
