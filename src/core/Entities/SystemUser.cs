namespace Sufficit.Identity.Core.Entities;

/// <summary>
/// Marks a user as a system user: an ordinary user to every application
/// (subject, claims, entitlements, userinfo) that can never sign in
/// interactively. Its credentials are issued by an operator through a
/// one-time enrollment (<see cref="SystemUserEnrollment"/>). The marker lives
/// in its own table so nothing about it reaches tokens or the users table.
/// </summary>
public sealed class SystemUser
{
    /// <summary>The <see cref="ApplicationUser"/> this marks.</summary>
    public string UserId { get; set; } = string.Empty;

    /// <summary>Subject of the operator who created the system user.</summary>
    public string CreatedBy { get; set; } = string.Empty;

    public DateTime CreatedAtUtc { get; set; }

    /// <summary>Correlation id of the creating request, for the audit trail.</summary>
    public string? CorrelationId { get; set; }

    /// <summary>Set while disabled: no token is issued and credentials are revoked.</summary>
    public DateTime? DisabledAtUtc { get; set; }

    public string? DisabledBy { get; set; }
}
