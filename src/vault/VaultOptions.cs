namespace Sufficit.Identity.Vault;

/// <summary>
/// Configuration for the internal secret vault. Bound from
/// <c>Sufficit:Vault</c>.
/// </summary>
public sealed class VaultOptions
{
    public const string SectionName = "Sufficit:Vault";

    /// <summary>
    /// Master toggle. When <c>false</c> (default), <see cref="IKeyVault"/>
    /// resolves to <see cref="PassThroughKeyVault"/> — round-trip without
    /// crypto, so consumers can be wired unconditionally without forcing
    /// encryption on in dev. When <c>true</c>, real envelope encryption with
    /// the configured <see cref="KeySource"/>.
    /// </summary>
    public bool Enabled { get; init; } = false;

    /// <summary>
    /// Rolling-upgrade guard. When true outside Development, startup fails
    /// instead of registering the plaintext compatibility vault.
    /// </summary>
    public bool RequireEncryptionInProduction { get; init; } = false;

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
}
