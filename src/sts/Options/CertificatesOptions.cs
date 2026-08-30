using Sufficit.Identity.Application.Security;

namespace Sufficit.Identity.STS;

/// <summary>
/// Production X.509 certificate configuration used by OpenIddict to sign and
/// encrypt tokens. When left unset, the server falls back to ephemeral
/// development certificates, but ONLY while <c>ASPNETCORE_ENVIRONMENT</c> is
/// <c>Development</c>; outside that environment, startup fails fast instead
/// of silently issuing tokens signed with a throwaway key.
/// </summary>
public sealed class CertificatesOptions
{
    /// <summary>
    /// When enabled, active signing and encryption credentials must be
    /// different certificates. Disabled initially as a rollout gate.
    /// </summary>
    public bool RequirePurposeSeparation { get; init; } = false;

    /// <summary>
    /// Warn (or fail) when a configured certificate has less remaining
    /// lifetime than this rollout window.
    /// </summary>
    public int MinimumRemainingLifetimeDays { get; init; } = 30;

    /// <summary>
    /// When true, the expiry window is enforced at startup. False preserves
    /// availability while operators first deploy expiry telemetry.
    /// </summary>
    public bool FailOnExpiringCertificate { get; init; } = false;

    /// <summary>
    /// Filesystem path to the PFX file used to sign tokens (JWT signing key).
    /// Required in production.
    /// </summary>
    public string? SigningPath { get; init; }

    /// <summary>
    /// Ordered active/retiring signing certificates. The first unique entry is
    /// active; subsequent certificates remain published during overlap.
    /// </summary>
    public string[] SigningPaths { get; init; } = [];

    /// <summary>
    /// Password protecting the signing PFX file referenced by <see cref="SigningPath"/>.
    /// </summary>
    public string? SigningPassword { get; init; }

    /// <summary>
    /// Filesystem path to the PFX file used to encrypt tokens (JWE encryption key).
    /// Required in production.
    /// </summary>
    public string? EncryptionPath { get; init; }

    /// <summary>
    /// Ordered active/retiring encryption certificates. The first unique entry
    /// is active; subsequent certificates remain available during overlap.
    /// </summary>
    public string[] EncryptionPaths { get; init; } = [];

    /// <summary>
    /// Password protecting the encryption PFX file referenced by <see cref="EncryptionPath"/>.
    /// </summary>
    public string? EncryptionPassword { get; init; }
}
