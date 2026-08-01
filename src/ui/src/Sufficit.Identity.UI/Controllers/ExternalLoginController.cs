using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Logging;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.Core.Services;
using Sufficit.Identity.UI.Services;

namespace Sufficit.Identity.UI.Controllers;

/// <summary>
/// Handles external login challenge and callback via HTTP redirects
/// (Blazor Server components can't access HttpContext directly).
/// Routes: /Account/ExternalChallenge and /Account/ExternalLoginCallback.
/// </summary>
[ApiController]
public sealed class ExternalLoginController(
    SignInManager<ApplicationUser> signInManager,
    UserManager<ApplicationUser> userManager,
    IAccountExternalIdentityService externalIdentityService,
    RegisterConfiguration registerConfig,
    ILogger<ExternalLoginController> logger) : ControllerBase
{
    /// <summary>
    /// Initiates the external login challenge (redirects to Google/GitHub/etc).
    /// GET /Account/ExternalChallenge?provider=Google&returnUrl=/connect/authorize?...
    /// </summary>
    [HttpGet("/account/externalchallenge")]
    public IActionResult Challenge([FromQuery] string provider, [FromQuery] string returnUrl)
    {
        if (string.IsNullOrEmpty(provider))
            return BadRequest("Provider is required.");

        // Reject absolute/off-host returnUrl up front — it gets carried through
        // the whole challenge/callback round trip and is otherwise trusted blindly
        // once the provider redirects back (authenticated open redirect).
        var safeReturnUrl = LocalUrlValidator.EnsureLocal(returnUrl);

        var redirectUrl = QueryHelpers.AddQueryString(
            "/account/externallogincallback", "returnUrl", safeReturnUrl);

        var properties = signInManager.ConfigureExternalAuthenticationProperties(
            provider, redirectUrl);

        return new ChallengeResult(provider, properties);
    }

    /// <summary>
    /// Handles the callback from the external provider (Google/GitHub redirect here).
    /// GET /Account/ExternalLoginCallback?returnUrl=...&code=...&state=...
    /// </summary>
    [HttpGet("/account/externallogincallback")]
    public async Task<IActionResult> Callback([FromQuery] string? returnUrl)
    {
        // Reject absolute/off-host returnUrl (authenticated open redirect).
        returnUrl = LocalUrlValidator.EnsureLocal(returnUrl);

        var info = await signInManager.GetExternalLoginInfoAsync();
        if (info is null)
        {
            logger.LogWarning("External login info is null — redirect expired or denied.");
            return Redirect("/account/login?returnUrl=" + Uri.EscapeDataString(returnUrl));
        }

        // Try to sign in with the external login (if already linked)
        var result = await signInManager.ExternalLoginSignInAsync(
            info.LoginProvider, info.ProviderKey, isPersistent: false, bypassTwoFactor: false);

        if (result.Succeeded)
        {
            logger.LogInformation("User signed in via {Provider}.", info.LoginProvider);
            return Redirect(returnUrl);
        }

        if (result.IsLockedOut)
            return Redirect("/account/login?error=locked_out");

        if (result.IsNotAllowed)
            return Redirect("/account/login?error=not_allowed");

        if (result.RequiresTwoFactor)
            return Redirect("/account/loginwith2fa?returnUrl=" + Uri.EscapeDataString(returnUrl));

        // No existing login row for this (provider, providerKey) pair.
        //
        // If the caller already carries a local authenticated session, this is an
        // explicit "link this provider to MY account" request (e.g. a future
        // Manage > External logins "Link" action) — account ownership is proven by
        // the session/cookie, not by whatever email the provider happens to assert,
        // so it's safe to link directly.
        if (User.Identity?.IsAuthenticated == true)
        {
            var linkResult = await externalIdentityService.LinkAsync(
                User,
                new AccountExternalIdentityLink(
                    info.LoginProvider,
                    info.ProviderKey,
                    info.ProviderDisplayName));
            if (linkResult.Succeeded)
            {
                logger.LogInformation(
                    "Linked {Provider} to the authenticated account.",
                    info.LoginProvider);
                if (returnUrl.StartsWith(
                        "/manage/externallogins",
                        StringComparison.OrdinalIgnoreCase))
                {
                    return Redirect(QueryHelpers.AddQueryString(
                        returnUrl,
                        new Dictionary<string, string?>
                        {
                            ["status"] = "linked",
                            ["provider"] = info.ProviderDisplayName
                                ?? info.LoginProvider,
                        }));
                }

                return Redirect(returnUrl);
            }

            var errorCode = linkResult.Errors.FirstOrDefault()?.Code
                ?? "external-identity-link-failed";
            logger.LogWarning(
                "Failed to link {Provider} to the authenticated account: {ErrorCode}",
                info.LoginProvider,
                errorCode);
            return Redirect(QueryHelpers.AddQueryString(
                "/manage/externallogins",
                "error",
                errorCode));
        }

        // Anonymous flow (no local session). This used to look up an existing user
        // by email and silently link + sign in — an account-takeover: anyone who
        // can get an external IdP to assert an arbitrary email (self-reported,
        // unverified) could sign in AS that email's local account with zero proof
        // of ownership. We now NEVER auto-link by email match alone. If an account
        // already exists, the user must sign in normally (password/2FA) and link
        // the provider from an authenticated session (see branch above) instead.
        var email = info.Principal.FindFirst(ClaimTypes.Email)?.Value
                    ?? info.Principal.FindFirst("email")?.Value;

        if (string.IsNullOrEmpty(email))
        {
            return Redirect("/account/login?error=no_email_from_provider");
        }

        var existingByEmail = await userManager.FindByEmailAsync(email);
        if (existingByEmail is not null)
        {
            logger.LogWarning(
                "External {Provider} login asserted email {Email} matching an existing account, " +
                "but the request carries no local session to prove ownership — refusing to auto-link.",
                info.LoginProvider, email);
            return Redirect("/account/login?error=account_link_requires_signin&email=" + Uri.EscapeDataString(email));
        }

        // No account exists yet — this would create one. Respect the Register
        // switch: if registration is disabled, external login must not be usable
        // as a side-channel to create accounts.
        if (!registerConfig.Enabled)
        {
            logger.LogInformation(
                "Refusing to create a new account via {Provider} for {Email}: registration is disabled.",
                info.LoginProvider, email);
            return Redirect("/account/login?error=registration_disabled");
        }

        // Only trust the provider's own "email is verified" assertion — never
        // assume a self-reported email is confirmed. Providers that emit no such
        // claim (e.g. this app's current Facebook integration, or Google until
        // "email_verified" is mapped in the OAuth handler's ClaimActions) are
        // treated as unverified: the account is created but EmailConfirmed stays
        // false, same as a normal password registration.
        var emailVerifiedClaim = info.Principal.FindFirst("email_verified")?.Value;
        var emailVerified = string.Equals(emailVerifiedClaim, "true", StringComparison.OrdinalIgnoreCase)
                             || emailVerifiedClaim == "1";

        var user = new ApplicationUser
        {
            UserName = email,
            Email = email,
            EmailConfirmed = emailVerified,
        };

        var create = await userManager.CreateAsync(user);
        if (!create.Succeeded)
        {
            var errors = string.Join(", ", create.Errors.Select(e => e.Description));
            logger.LogWarning("Failed to create user from {Provider}: {Errors}", info.LoginProvider, errors);
            return Redirect("/account/login?error=create_failed");
        }

        var link = await userManager.AddLoginAsync(user,
            new UserLoginInfo(info.LoginProvider, info.ProviderKey, info.ProviderDisplayName));
        if (!link.Succeeded)
        {
            return Redirect("/account/login?error=link_failed");
        }

        await signInManager.SignInAsync(user, isPersistent: false);
        logger.LogInformation("Created and signed in new user {Email} via {Provider} (emailVerified={EmailVerified}).",
            email, info.LoginProvider, emailVerified);
        return Redirect(returnUrl);
    }
}
