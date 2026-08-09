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
    /// KEK source: <c>dataprotection</c> (default) | <c>certificate</c> |
    /// <c>external</c>. Only <c>dataprotection</c> is implemented in Phase 1;
    /// it wraps vault DEKs using ASP.NET Core Data Protection (already
    /// persisted + X.509-protected by the host), so there are zero new
    /// dependencies.
    /// </summary>
    public string KeySource { get; init; } = "dataprotection";

    /// <summary>
    /// The Data Protection purpose string used as the KEK. Changing this
    /// invalidates all wrapped DEKs (they can no longer be unwrapped).
    /// </summary>
    public string DataProtectionPurpose { get; init; } =
        "Sufficit.Identity.Vault.Master.v1";

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
}
