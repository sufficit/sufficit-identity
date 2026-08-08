namespace Sufficit.Identity.Core.Entities;

/// <summary>
/// A user-owned named secret. Ownership is part of the key so personal Vault
/// entries can never collide with or enumerate the operator's global secrets.
/// </summary>
public sealed class VaultPersonalSecret
{
    public long Id { get; set; }
    public string OwnerSubject { get; set; } = string.Empty;
    public string Namespace { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public string Ciphertext { get; set; } = string.Empty;
    public string? AadJson { get; set; }
    public DateTime UpdatedAtUtc { get; set; }
    public string UpdatedBy { get; set; } = string.Empty;
}
