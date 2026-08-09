using System.Diagnostics.Metrics;
using Microsoft.Extensions.Logging.Abstractions;
using Sufficit.Identity.Vault;
using Xunit;

namespace Sufficit.Identity.Tests;

public sealed class VaultCryptographyTelemetryTests
{
    [Fact]
    public void Encryption_metric_is_partitioned_by_key_name_and_version()
    {
        var measurements = new List<IReadOnlyDictionary<string, object?>>();
        using var listener = new MeterListener
        {
            InstrumentPublished = (instrument, meterListener) =>
            {
                if (instrument.Meter.Name == VaultCryptographyTelemetry.MeterName
                    && instrument.Name ==
                        VaultCryptographyTelemetry.EncryptionCounterName)
                {
                    meterListener.EnableMeasurementEvents(instrument);
                }
            },
        };
        listener.SetMeasurementEventCallback<long>((_, value, tags, _) =>
        {
            Assert.Equal(1, value);
            measurements.Add(tags.ToArray().ToDictionary(
                tag => tag.Key,
                tag => tag.Value,
                StringComparer.Ordinal));
        });
        listener.Start();
        var telemetry = new VaultCryptographyTelemetry(
            new VaultOptions { AesGcmMessageBudgetPerKeyVersion = 10 },
            NullLogger<VaultCryptographyTelemetry>.Instance);

        telemetry.RecordEncryption("dpop-nonce", 3);

        var measurement = Assert.Single(measurements);
        Assert.Equal("dpop-nonce", measurement["key.name"]);
        Assert.Equal(3, measurement["key.version"]);
        Assert.DoesNotContain("plaintext", measurement.Keys);
        Assert.DoesNotContain("ciphertext", measurement.Keys);
    }
}
