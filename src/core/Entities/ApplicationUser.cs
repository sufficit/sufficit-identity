using Microsoft.AspNetCore.Identity;

namespace Sufficit.Identity.Core.Entities;

/// <summary>
/// Application user. Inherits all standard ASP.NET Core Identity columns
/// (Id, UserName, NormalizedUserName, Email, NormalizedEmail, EmailConfirmed,
/// PasswordHash, SecurityStamp, ConcurrencyStamp, PhoneNumber,
/// PhoneNumberConfirmed, TwoFactorEnabled, LockoutEnd, LockoutEnabled,
/// AccessFailedCount).
///
/// Mapped to the legacy <c>users</c> table in the <c>identity2</c> database,
/// which has one extra column not present in the Identity default schema:
/// <see cref="Timestamp"/> (MySQL <c>utc_TIMESTAMP()</c> row version).
/// </summary>
public sealed class ApplicationUser : IdentityUser
{
    /// <summary>
    /// Row creation/update timestamp populated by MySQL
    /// (<c>DEFAULT UTC_TIMESTAMP()</c>). Not used by Identity itself but kept
    /// for compatibility with the legacy schema and audit/debug tooling.
    /// </summary>
    public DateTime Timestamp { get; set; }
}
