namespace Sufficit.Identity.Core.Entities;

/// <summary>
/// An initial access token for RFC 7591 dynamic client registration, issued by
/// an operator to one registrant. Only a SHA-256 hash of the token is stored:
/// tokens are 256-bit random values, so a slow password hash adds nothing and
/// would prevent the indexed lookup.
/// </summary>
public sealed class DcrInitialAccessToken
{
    public Guid Id { get; set; }

    /// <summary>Operator-supplied description of the registrant.</summary>
    public string Label { get; set; } = string.Empty;

    /// <summary>Lowercase hexadecimal SHA-256 of the token.</summary>
    public string TokenHash { get; set; } = string.Empty;

    /// <summary>Leading characters of the hash, to tell tokens apart in listings.</summary>
    public string TokenHint { get; set; } = string.Empty;

    /// <summary>Subject of the operator who issued the token.</summary>
    public string IssuedBy { get; set; } = string.Empty;

    public DateTime CreatedAtUtc { get; set; }

    public DateTime ExpiresAtUtc { get; set; }

    /// <summary>When true, the token registers exactly one client.</summary>
    public bool SingleUse { get; set; } = true;

    public int RegistrationCount { get; set; }

    /// <summary>
    /// JSON array of the grant types a registration with this token may
    /// request, within the server-wide allowlist. Null leaves the server-wide
    /// allowlist as the only limit.
    /// </summary>
    public string? AllowedGrantTypesJson { get; set; }

    /// <summary>JSON array of the scopes a registration may request; see
    /// <see cref="AllowedGrantTypesJson"/>.</summary>
    public string? AllowedScopesJson { get; set; }

    public DateTime? LastUsedAtUtc { get; set; }

    public DateTime? RevokedAtUtc { get; set; }

    public string? RevokedBy { get; set; }
}
