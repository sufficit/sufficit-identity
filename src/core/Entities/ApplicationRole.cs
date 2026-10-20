using Microsoft.AspNetCore.Identity;

namespace Sufficit.Identity.Core.Entities;

/// <summary>
/// Application role. Inherits the standard ASP.NET Core Identity columns
/// (Id, Name, NormalizedName, ConcurrencyStamp). Mapped to the legacy
/// lowercase <c>roles</c> table in <c>AppDbContext.OnModelCreating</c>.
/// Kept as a distinct type (instead of using <c>IdentityRole</c> directly)
/// to keep identity persistence mapping explicit and independent of consumer business roles.
/// </summary>
public sealed class ApplicationRole : IdentityRole { }
