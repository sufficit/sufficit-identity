namespace Sufficit.Identity.Vault;

/// <summary>
/// Configuration for the internal secret vault. Bound from
/// <c>Sufficit:Vault</c>.
/// </summary>
public sealed class VaultOptions
{
    public const string SectionName = "Sufficit:Vault";

    /// <summary>
    /// Master toggle. When <c>false</c> in Development,
    /// <see cref="IKeyVault"/> resolves to <see cref="PassThroughKeyVault"/>.
    /// Outside Development the disabled state is rejected at startup. When
    /// <c>true</c>, real envelope encryption uses the configured
    /// <see cref="KeySource"/>.
    /// </summary>
    public bool Enabled { get; init; } = false;

    /// <summary>
    /// Retained for configuration compatibility. Encryption is always
    /// required outside Development; setting this value to false no longer
    /// permits the pass-through backend.
    /// </summary>
    [Obsolete("Encryption is always required outside Development.")]
    public bool RequireEncryptionInProduction { get; init; } = true;

    /// <summary>
    /// KEK source: <c>dataprotection</c>, <c>certificate</c> (dedicated RSA
    /// certificate) or <c>external</c> (KMS/HSM adapter).
    /// <c>dataprotection</c> is NOT rejected outright outside Development:
    /// <see cref="AddSufficitVault"/>'s key-encryption policy instead REQUIRES
    /// a dedicated <see cref="CertificatePath"/> protecting the Data
    /// Protection key ring, distinct from every token-signing certificate —
    /// so a database dump alone still cannot recover the vault KEK, but the
    /// ring must genuinely be certificate-protected for that property to
    /// hold (doc/code drift corrected per eval 2026-08-14; code wins).
    /// </summary>
    public string KeySource { get; init; } = "dataprotection";

    /// <summary>
    /// The Data Protection purpose string used as the KEK. Changing this
    /// invalidates all wrapped DEKs (they can no longer be unwrapped).
    /// </summary>
    public string DataProtectionPurpose { get; init; } =
        "Sufficit.Identity.Vault.Master.v1";

    /// <summary>
    /// Dedicated PKCS#12/PFX certificate protecting the shared ASP.NET Data
    /// Protection key ring. When <see cref="KeySource"/> is
    /// <c>certificate</c>, the same dedicated certificate also wraps vault
    /// DEKs directly. It must not be a token-signing certificate.
    /// </summary>
    public string? CertificatePath { get; init; }

    /// <summary>Password for <see cref="CertificatePath"/>. Supply it through
    /// a secret-bearing configuration provider, never a committed file.</summary>
    public string? CertificatePassword { get; init; }

    /// <summary>
    /// Bounded compatibility window for Data Protection keys previously
    /// encrypted with a token-signing certificate. New keys are always
    /// protected by <see cref="CertificatePath"/>; this only permits reading
    /// the legacy ring until it has naturally rotated.
    /// </summary>
    public VaultLegacyCertificateMigrationOptions
        LegacyDataProtectionCertificateMigration { get; init; } = new();

    /// <summary>
    /// Bounded compatibility window for reading legacy <c>pt1.</c> plaintext
    /// pass-through values through the real vault (eval 2026-08-14, F-2).
    /// Outside Development the decrypt path rejects <c>pt1.</c> ciphertext by
    /// default — a tampered database/Redis row swapped for
    /// <c>pt1.&lt;base64url&gt;</c> would otherwise resolve to attacker-chosen
    /// plaintext. Configure Owner, Reason and a future ExpiresAtUtc (max 180
    /// days) only while legacy rows are being rewritten with envelope
    /// encryption; reads stop accepting the marker once the window expires.
    /// </summary>
    public VaultPlaintextReadCompatibilityOptions
        PlaintextReadCompatibility { get; init; } = new();

    /// <summary>
    /// Stable, non-secret identifier expected from the external KMS/HSM
    /// adapter. A mismatch fails startup and prevents accidentally switching
    /// to a different remote KEK.
    /// </summary>
    public string? ExternalKeyIdentifier { get; init; }

    /// <summary>
    /// Enables the optional database-backed named-secret store. It requires
    /// <see cref="Enabled"/> and replaces the environment-only ISecretStore
    /// registration.
    /// </summary>
    public bool EnableSecretStore { get; init; } = false;

    /// <summary>
    /// Opts OpenIddict token signing into the vault-backed RSA provider. When
    /// false, the existing certificate path remains unchanged.
    /// </summary>
    public bool ManageSigningKeys { get; init; } = false;

    /// <summary>
    /// Read snapshot for VaultKeys/VaultSecrets. It caches only encrypted
    /// ciphertext and public metadata; plaintext secret values are never
    /// retained by this layer.
    /// </summary>
    public VaultSnapshotOptions Snapshot { get; init; } = new();

    /// <summary>Name of the versioned RSA key used for OpenIddict tokens.</summary>
    public string SigningKeyName { get; init; } = "oidc-signing";

    /// <summary>
    /// Minimum time that a previous signing key remains published after a
    /// rotation. The STS validates this against its longest token lifetime.
    /// </summary>
    public int SigningKeyOverlapSeconds { get; init; } = 1_209_600;

    /// <summary>Lease duration for the database-backed distributed rotation
    /// lock. An abandoned lease can be recovered after this interval.</summary>
    public int SigningKeyLockSeconds { get; init; } = 60;

    /// <summary>
    /// Operational ceiling for successful AES-GCM encryptions under one
    /// random 96-bit-nonce key version. The default 250 million keeps the
    /// approximate nonce-collision probability below 4e-13. Metrics warn at
    /// 80% and at the budget; rotation remains an explicit operator action.
    /// </summary>
    public long AesGcmMessageBudgetPerKeyVersion { get; init; } = 250_000_000;
}

public sealed class VaultLegacyCertificateMigrationOptions
{
    public string? Owner { get; init; }
    public string? Reason { get; init; }
    public DateTimeOffset? ExpiresAtUtc { get; init; }

    public bool IsConfigured => ExpiresAtUtc is not null
        || !string.IsNullOrWhiteSpace(Owner)
        || !string.IsNullOrWhiteSpace(Reason);
}

public sealed class VaultPlaintextReadCompatibilityOptions
{
    public string? Owner { get; init; }
    public string? Reason { get; init; }
    public DateTimeOffset? ExpiresAtUtc { get; init; }

    public bool IsConfigured => ExpiresAtUtc is not null
        || !string.IsNullOrWhiteSpace(Owner)
        || !string.IsNullOrWhiteSpace(Reason);
}
