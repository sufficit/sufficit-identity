using System.Diagnostics.Metrics;
using Sufficit.Identity.STS;
using Xunit;

namespace Sufficit.Identity.Tests;

public sealed class SecurityDecisionTelemetryTests
{
    [Fact]
    public void Security_metrics_are_low_cardinality_and_record_observe_fallbacks()
    {
        var measurements = new List<(
            string Instrument,
            IReadOnlyDictionary<string, object?> Tags)>();
        using var listener = new MeterListener
        {
            InstrumentPublished = (instrument, meterListener) =>
            {
                if (instrument.Meter.Name == "Sufficit.Identity.Security")
                {
                    meterListener.EnableMeasurementEvents(instrument);
                }
            },
        };
        listener.SetMeasurementEventCallback<long>((
            instrument,
            _,
            tags,
            _) => measurements.Add((
                instrument.Name,
                tags.ToArray().ToDictionary(
                    tag => tag.Key,
                    tag => tag.Value,
                    StringComparer.Ordinal))));
        listener.Start();

        ISecurityDecisionTelemetry telemetry = new SecurityDecisionTelemetry();
        telemetry.Record(
            "personal_token_issuance",
            "Observe",
            wouldReject: true,
            rejected: false,
            ["recent_authentication_required"]);

        Assert.Contains(measurements, measurement =>
            measurement.Instrument == "identity.security.policy.decisions"
            && Equals(measurement.Tags["outcome"], "compatibility_allowed")
            && Equals(
                measurement.Tags["reason"],
                "recent_authentication_required"));
        Assert.Contains(measurements, measurement =>
            measurement.Instrument ==
            "identity.security.policy.compatibility_fallbacks");
        Assert.All(measurements, measurement =>
        {
            Assert.DoesNotContain("subject", measurement.Tags.Keys);
            Assert.DoesNotContain("client_id", measurement.Tags.Keys);
            Assert.DoesNotContain("token", measurement.Tags.Keys);
        });
    }
}
