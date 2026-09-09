using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Logging;
using Sufficit.Identity.Application.Accounts;

namespace Sufficit.Identity.STS.Controllers;

/// <summary>
/// Converts an authenticated but old central session into Identity's existing
/// pending-MFA flow. This preserves the selected account while ensuring that
/// a remembered-browser cookie cannot silently satisfy fresh authentication.
/// </summary>
[ApiController]
[Authorize]
public sealed class ReauthenticationController(
    IInteractiveSignInService signInService,
    ILogger<ReauthenticationController> logger) : ControllerBase
{
    [HttpGet("/account/reauthenticate")]
    public async Task<IActionResult> Begin(
        [FromQuery] string? returnUrl,
        CancellationToken cancellationToken)
    {
        var safeReturnUrl = LocalUrlValidator.EnsureLocal(returnUrl);

        // SignOutAsync writes the deletion cookie to the response, while the
        // current request can still have the old authentication result cached.
        // A redirect gives the forced-MFA transition a clean request boundary.
        var remembered = await HttpContext.AuthenticateAsync(
            IdentityConstants.TwoFactorRememberMeScheme);
        if (remembered.Succeeded)
        {
            await HttpContext.SignOutAsync(
                IdentityConstants.TwoFactorRememberMeScheme);
            return Redirect(QueryHelpers.AddQueryString(
                "/account/reauthenticate",
                "returnUrl",
                safeReturnUrl));
        }

        var result = await signInService.BeginReauthenticationAsync(
            User,
            cancellationToken);
        if (result.Status == InteractiveSignInStatus.RequiresTwoFactor)
        {
            return Redirect(QueryHelpers.AddQueryString(
                "/account/loginwith2fa",
                new Dictionary<string, string?>
                {
                    ["returnUrl"] = safeReturnUrl,
                    ["rememberMe"] = bool.TrueString,
                }));
        }

        logger.LogInformation(
            "Recent authentication requires primary sign-in. "
            + "Outcome={Status}; TraceId={TraceId}.",
            result.Status,
            AuthenticationFlowDiagnostics.TraceId);
        await HttpContext.SignOutAsync(IdentityConstants.ApplicationScheme);
        return Redirect(QueryHelpers.AddQueryString(
            "/account/login",
            "returnUrl",
            safeReturnUrl));
    }
}
