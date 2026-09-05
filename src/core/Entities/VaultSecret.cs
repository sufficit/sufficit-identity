namespace Sufficit.Identity.Core.Entities;

/// <summary>
/// A named secret stored as vault ciphertext. The plaintext is never persisted;
/// the vault binds the ciphertext to <see cref="Name"/> through AAD.
/// </summary>
public sealed class VaultSecret
{
    public long Id { get; set; }
    /// <summary>Root path segment. Nested names inherit this namespace and
    /// cannot override it.</summary>
    public string Namespace { get; set; } = string.Empty;
    /// <summary>
    /// Owner-kind discriminator — user | tenant | client | global — stored as
    /// a short varchar. It completes the row key: the same context Guid can
    /// exist as a user's private context and as a client's system context
    /// without colliding. <c>user</c> is a per-user private context,
    /// <c>tenant</c> is reserved for future credential sharing, <c>client</c>
    /// holds per-application credentials (connection strings and the like) and
    /// <c>global</c> is the administrator-owned integration bucket.
    /// </summary>
    public string Type { get; set; } = Data.IdentityDatabaseSchema.VaultSecretTypeGlobal;
    /// <summary>Context identifier within its <see cref="Type"/>, stored as
    /// <c>binary(16)</c>. A textual GUID is persisted as-is, a
    /// <c>user-&lt;guid&gt;</c> legacy value keeps only the GUID part, and any
    /// other historical form (global, service slugs) normalized to
    /// <see cref="Guid.Empty"/>. See <c>VaultBackedSecretStore</c> for the
    /// canonical string mapping used by every external surface.</summary>
    public Guid ContextId { get; set; } = Guid.Empty;
    /// <summary>
    /// Subject that first created the scoped secret, stored as
    /// <c>binary(16)</c> under the same conversion rules as
    /// <see cref="ContextId"/> (GUID kept, <c>user-</c> prefix stripped,
    /// everything else <see cref="Guid.Empty"/>). For <c>user</c>-type rows it
    /// equals the owner's subject Guid. Ownership is immutable metadata;
    /// access still requires context + namespace policy.
    /// </summary>
    public Guid OwnerSubject { get; set; } = Guid.Empty;
    public string Name { get; set; } = string.Empty;
    public string Ciphertext { get; set; } = string.Empty;
    public string? AadJson { get; set; }
    /// <summary>Optional expiration. Expired secrets stop resolving but remain
    /// listed so operators can audit and rotate them.</summary>
    public DateTime? ExpiresAtUtc { get; set; }
    public DateTime UpdatedAtUtc { get; set; }
    public string UpdatedBy { get; set; } = string.Empty;
}
