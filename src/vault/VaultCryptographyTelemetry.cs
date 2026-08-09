using System.Collections.Concurrent;
using System.Diagnostics.Metrics;
using Microsoft.Extensions.Logging;

namespace Sufficit.Identity.Vault;

/// <summary>
/// Counts successful AES-GCM encryptions by non-secret key name and version.
/// External metrics aggregation is the durable authority; local counts only
/// provide an early warning within one process lifetime.
/// </summary>
internal sealed class VaultCryptographyTelemetry
{
    internal const string MeterName = "Sufficit.Identity.Vault";
    internal const string EncryptionCounterName =
        "sufficit.vault.aes_gcm.encryptions";
    private static readonly Meter Meter = new(MeterName, "1.0.0");
    private static readonly Counter<long> Encryptions =
        Meter.CreateCounter<long>(EncryptionCounterName);
    private readonly ConcurrentDictionary<(string Name, int Version), long>
        _localCounts = new();
    private readonly ILogger<VaultCryptographyTelemetry> _logger;
    private readonly long _budget;
    private readonly long _warningThreshold;

    public VaultCryptographyTelemetry(
        VaultOptions options,
        ILogger<VaultCryptographyTelemetry> logger)
    {
        _logger = logger;
        _budget = options.AesGcmMessageBudgetPerKeyVersion;
        _warningThreshold = Math.Max(1, _budget * 4 / 5);
    }

    public void RecordEncryption(string keyName, int keyVersion)
    {
        Encryptions.Add(
            1,
            new KeyValuePair<string, object?>("key.name", keyName),
            new KeyValuePair<string, object?>("key.version", keyVersion));
        var count = _localCounts.AddOrUpdate(
            (keyName, keyVersion),
            1,
            static (_, current) => current + 1);
        if (count == _warningThreshold)
        {
            _logger.LogWarning(
                "Vault AES-GCM key '{KeyName}' version {KeyVersion} reached 80% of its configured per-version message budget in this process. Rotate the data key after confirming the aggregated metric.",
                keyName,
                keyVersion);
        }
        else if (count == _budget)
        {
            _logger.LogCritical(
                "Vault AES-GCM key '{KeyName}' version {KeyVersion} reached its configured per-version message budget in this process. Rotate it before further issuance; automatic rotation is intentionally disabled until aggregated operational evidence is available.",
                keyName,
                keyVersion);
        }
    }
}
