namespace Sufficit.Identity.Core.Entities;

/// <summary>
/// A named secret stored as vault ciphertext. The plaintext is never persisted;
/// the vault binds the ciphertext to <see cref="Name"/> through AAD.
/// </summary>
public sealed class VaultSecret
{
    public long Id { get; set; }
    public string Name { get; set; } = string.Empty;
    public string Ciphertext { get; set; } = string.Empty;
    public string? AadJson { get; set; }
    public DateTime UpdatedAtUtc { get; set; }
    public string UpdatedBy { get; set; } = string.Empty;
}
