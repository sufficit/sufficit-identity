using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Core.Entities;

namespace Sufficit.Identity.Core.Services;

/// <summary>
/// Non-secret recovery state kept outside editable user claims. Only verified
/// enrollment clears it; disabling MFA or changing a password cannot bypass it.
/// </summary>
public static class MfaRecoveryState
{
    public const string Provider = "Sufficit.Identity.Recovery";
    public const string TokenName = "MfaReenrollmentRequired";

    public static Task<bool> IsRequiredAsync(
        AppDbContext database, string userId, CancellationToken cancellationToken = default) =>
        database.UserTokens.AsNoTracking().AnyAsync(
            token => token.UserId == userId && token.LoginProvider == Provider
                && token.Name == TokenName, cancellationToken);

    public static async Task<bool> IsRequiredAsync(
        UserManager<ApplicationUser> users, ApplicationUser user) =>
        await users.GetAuthenticationTokenAsync(user, Provider, TokenName) is not null;

    public static Task<IdentityResult> RequireAsync(
        UserManager<ApplicationUser> users, ApplicationUser user) =>
        users.SetAuthenticationTokenAsync(user, Provider, TokenName, "required");

    public static Task<IdentityResult> CompleteAsync(
        UserManager<ApplicationUser> users, ApplicationUser user) =>
        users.RemoveAuthenticationTokenAsync(user, Provider, TokenName);
}
