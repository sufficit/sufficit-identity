namespace Sufficit.Identity.Core.Entities;

/// <summary>
/// A wrapped vault key (DEK or item key) persisted in the <c>vault_keys</c>
/// table. The key material is never stored unwrapped; the configured KEK
/// authority unwraps it at runtime, and the unwrapped key lives only in memory.
/// </summary>
public sealed class VaultKey
{
    /// <summary>Database primary key (autoincrement).</summary>
    public long Id { get; set; }

    /// <summary>
    /// Stable key name, e.g. <c>ssf-stream-authz</c>. Pairs with
    /// <see cref="KeyVersion"/> for uniqueness.
    /// </summary>
    public string KeyName { get; set; } = string.Empty;

    /// <summary>
    /// Monotonically increasing per <see cref="KeyName"/>. New encrypts use
    /// the latest version; old ciphertext decrypts via the version embedded in
    /// the blob.
    /// </summary>
    public int KeyVersion { get; set; }

    /// <summary>
    /// <c>symmetric</c> (Phase 1 — AES-256-GCM data encryption) or
    /// <c>signing</c> (Phase 3 — RSA/ECDSA JWT signing, not yet implemented).
    /// </summary>
    public string Purpose { get; set; } = "symmetric";

    /// <summary>
    /// The wrapped (KEK-encrypted) key material. Format is the
    /// <c>EnvelopeCrypto.Wrap</c> output: <c>iv ‖ wrapped-key ‖ tag</c>.
    /// </summary>
    public byte[] WrappedKey { get; set; } = Array.Empty<byte>();

    /// <summary>
    /// Public JWK for signing keys. Null for symmetric keys. It never contains
    /// private key material and is safe to publish through JWKS later.
    /// </summary>
    public string? PublicJwk { get; set; }

    /// <summary>When this key version was created (UTC).</summary>
    public DateTime CreatedAtUtc { get; set; }

    /// <summary>
    /// When this key version was retired (UTC). Null = active or still
    /// decryptable. Set on rotation after all ciphertext has migrated.
    /// </summary>
    public DateTime? RetiredAtUtc { get; set; }

    /// <summary>Lifecycle state for signing keys. Null for symmetric and
    /// rolling-deployment legacy rows.</summary>
    public VaultSigningKeyState? SigningState { get; set; }

    /// <summary>Deadline through which a retiring key remains in JWKS.</summary>
    public DateTime? RetireAfterUtc { get; set; }

    /// <summary>Emergency revocation timestamp. Revoked keys are never
    /// published, used for issuance or accepted for verification.</summary>
    public DateTime? RevokedAtUtc { get; set; }

    /// <summary>Optimistic concurrency counter for lifecycle transitions.</summary>
    public int LifecycleVersion { get; set; }
}

public enum VaultSigningKeyState
{
    Active,
    Retiring,
    Retired,
    Revoked,
}
