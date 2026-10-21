namespace Sufficit.Identity.Core.Entities;

/// <summary>
/// A one-time enrollment code an operator issues for a system user and one
/// client. The software redeems it at the token endpoint (with its own DPoP
/// key, when it has one) for a long-lived refresh token in the system user's
/// name, so the operator never handles the long-lived credential. Only a
/// SHA-256 hash of the 256-bit code is stored.
/// </summary>
public sealed class SystemUserEnrollment
{
    public Guid Id { get; set; }

    public string UserId { get; set; } = string.Empty;

    /// <summary>The client allowed to redeem the code.</summary>
    public string ClientId { get; set; } = string.Empty;

    /// <summary>Operator-supplied description (e.g. the host or agent).</summary>
    public string Label { get; set; } = string.Empty;

    /// <summary>Lowercase hexadecimal SHA-256 of the code.</summary>
    public string CodeHash { get; set; } = string.Empty;

    /// <summary>Leading characters of the hash, to tell codes apart in listings.</summary>
    public string CodeHint { get; set; } = string.Empty;

    public string IssuedBy { get; set; } = string.Empty;

    public DateTime CreatedAtUtc { get; set; }

    public DateTime ExpiresAtUtc { get; set; }

    /// <summary>When redeemed; a code is single-use.</summary>
    public DateTime? RedeemedAtUtc { get; set; }

    /// <summary>OpenIddict authorization created on redemption; revoking it revokes the credential.</summary>
    public string? AuthorizationId { get; set; }

    public DateTime? RevokedAtUtc { get; set; }

    public string? RevokedBy { get; set; }
}
