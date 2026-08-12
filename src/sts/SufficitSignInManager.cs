using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Sufficit.Identity.Core.Entities;

namespace Sufficit.Identity.STS;

/// <summary>
/// Exposes the canonical ASP.NET Identity external-login-to-2FA transition
/// to the application boundary without duplicating Identity's cookie format.
/// </summary>
public sealed class SufficitSignInManager(
    UserManager<ApplicationUser> userManager,
    IHttpContextAccessor contextAccessor,
    IUserClaimsPrincipalFactory<ApplicationUser> claimsFactory,
    IOptions<IdentityOptions> optionsAccessor,
    ILogger<SignInManager<ApplicationUser>> logger,
    IAuthenticationSchemeProvider schemes,
    IUserConfirmation<ApplicationUser> confirmation)
    : SignInManager<ApplicationUser>(
        userManager,
        contextAccessor,
        claimsFactory,
        optionsAccessor,
        logger,
        schemes,
        confirmation)
{
    public Task<SignInResult> SignInOrTwoFactorForExternalAsync(
        ApplicationUser user,
        string loginProvider,
        bool isPersistent = false) =>
        SignInOrTwoFactorAsync(
            user,
            isPersistent,
            loginProvider,
            bypassTwoFactor: false);
}
