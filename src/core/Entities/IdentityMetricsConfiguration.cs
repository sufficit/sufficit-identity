namespace Sufficit.Identity.Core.Entities;

/// <summary>
/// Runtime configuration for identity usage telemetry. The singleton row is
/// managed through the canonical management boundary and reloaded by the
/// background collector without requiring a process restart.
/// </summary>
public sealed class IdentityMetricsConfiguration
{
    public const int SingletonId = 1;

    public int Id { get; set; } = SingletonId;
    public bool Enabled { get; set; } = true;
    public int RetentionDays { get; set; } = 90;
    public bool ExportEnabled { get; set; }
    public string Provider { get; set; } = "internal";
    public string? Endpoint { get; set; }
    public string? Database { get; set; }
    public string? AuthorizationScheme { get; set; }
    public string? Username { get; set; }
    public string? SecretCiphertext { get; set; }
    public int TimeoutSeconds { get; set; } = 10;
    public int BatchSize { get; set; } = 250;
    public DateTime UpdatedAtUtc { get; set; }
}
