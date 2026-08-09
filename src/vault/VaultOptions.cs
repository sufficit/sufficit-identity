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
    /// KEK source: <c>dataprotection</c> (development compatibility only),
    /// <c>certificate</c> (dedicated RSA certificate) or <c>external</c>
    /// (KMS/HSM adapter). Production rejects <c>dataprotection</c> so a
    /// database/key-ring dump cannot also recover the vault KEK.
    /// </summary>
    public string KeySource { get; init; } = "dataprotection";

    /// <summary>
    /// The Data Protection purpose string used as the KEK. Changing this
    /// invalidates all wrapped DEKs (they can no longer be unwrapped).
    /// </summary>
    public string DataProtectionPurpose { get; init; } =
        "Sufficit.Identity.Vault.Master.v1";

    /// <summary>
    /// Dedicated PKCS#12/PFX certificate used only to wrap vault DEKs when
    /// <see cref="KeySource"/> is <c>certificate</c>. It must not be one of
    /// the token-signing certificates.
    /// </summary>
    public string? CertificatePath { get; init; }

    /// <summary>Password for <see cref="CertificatePath"/>. Supply it through
    /// a secret-bearing configuration provider, never a committed file.</summary>
    public string? CertificatePassword { get; init; }

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
}
