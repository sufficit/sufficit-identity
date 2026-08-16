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
    /// <summary>Management authorization context owning this secret.</summary>
    public string ContextId { get; set; } = "global";
    /// <summary>Subject that first created the scoped secret. Ownership is
    /// immutable metadata; access still requires context + namespace policy.</summary>
    public string OwnerSubject { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public string Ciphertext { get; set; } = string.Empty;
    public string? AadJson { get; set; }
    /// <summary>Optional expiration. Expired secrets stop resolving but remain
    /// listed so operators can audit and rotate them.</summary>
    public DateTime? ExpiresAtUtc { get; set; }
    public DateTime UpdatedAtUtc { get; set; }
    public string UpdatedBy { get; set; } = string.Empty;
}
