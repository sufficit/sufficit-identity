using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Sufficit.Identity.Core.Entities;

namespace Sufficit.Identity.STS;

/// <summary>
/// One account per normalized email, without requiring an email (plan F9).
/// <c>IdentityOptions.User.RequireUniqueEmail</c> would also reject accounts
/// with no email at all — system users and provisioned accounts have none.
/// The unique <c>EmailIndex</c> is the last line against a race; this turns
/// the ordinary case into Identity's own <c>DuplicateEmail</c> error.
/// </summary>
internal sealed class UniqueEmailWhenPresentValidator(IdentityErrorDescriber describer)
    : IUserValidator<ApplicationUser>
{
    public async Task<IdentityResult> ValidateAsync(UserManager<ApplicationUser> manager, ApplicationUser user)
    {
        var email = await manager.GetEmailAsync(user);
        if (string.IsNullOrWhiteSpace(email))
            return IdentityResult.Success;

        var normalized = manager.NormalizeEmail(email);
        var userId = await manager.GetUserIdAsync(user);
        var taken = await manager.Users.AnyAsync(other =>
            other.NormalizedEmail == normalized && other.Id != userId);
        return taken ? IdentityResult.Failed(describer.DuplicateEmail(email)) : IdentityResult.Success;
    }
}
