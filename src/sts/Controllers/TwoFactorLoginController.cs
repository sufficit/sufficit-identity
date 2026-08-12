using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using Sufficit.Identity.Application.Accounts;

namespace Sufficit.Identity.STS.Controllers;

/// <summary>
/// Completes the pending Identity two-factor sign-in on a normal HTTP request.
/// Cookie issuance must happen before the response starts and must not depend
/// on an already-established Blazor circuit.
/// </summary>
[ApiController]
[AllowAnonymous]
public sealed class TwoFactorLoginController(
    IInteractiveSignInService signInService,
    IAntiforgery antiforgery) : ControllerBase
{
    [HttpPost("/account/login/2fa")]
    public async Task<IActionResult> Authenticator(
        [FromForm] AuthenticatorRequest request,
        CancellationToken cancellationToken)
    {
        var returnUrl = LocalUrlValidator.EnsureLocal(request.ReturnUrl);
        // A hidden field can arrive empty when the page is rendered without
        // the optional remember-me query parameter. Treat that as the secure
        // default instead of letting ApiController return an opaque 400.
        var rememberMe = ParseBoolean(request.RememberMe);
        if (!await ValidateAntiforgeryAsync())
        {
            return RedirectToAuthenticator(
                returnUrl,
                rememberMe,
                "request_expired");
        }

        if (!await signInService.HasPendingTwoFactorSignInAsync(
                cancellationToken))
        {
            return RedirectToAuthenticator(
                returnUrl,
                rememberMe,
                "pending_state_missing");
        }

        var result = await signInService.AuthenticatorSignInAsync(
            new AuthenticatorSignInCommand(
                request.Code ?? string.Empty,
                rememberMe,
                request.RememberClient),
            cancellationToken);

        return result.Status switch
        {
            InteractiveSignInStatus.Succeeded => LocalRedirect(returnUrl),
            InteractiveSignInStatus.LockedOut => RedirectToAuthenticator(
                returnUrl,
                rememberMe,
                "locked_out"),
            _ => RedirectToAuthenticator(
                returnUrl,
                rememberMe,
                "invalid_code"),
        };
    }

    [HttpPost("/account/login/recoverycode")]
    public async Task<IActionResult> RecoveryCode(
        [FromForm] RecoveryCodeRequest request,
        CancellationToken cancellationToken)
    {
        var returnUrl = LocalUrlValidator.EnsureLocal(request.ReturnUrl);
        if (!await ValidateAntiforgeryAsync())
        {
            return RedirectToRecoveryCode(returnUrl, "request_expired");
        }

        if (!await signInService.HasPendingTwoFactorSignInAsync(
                cancellationToken))
        {
            return RedirectToRecoveryCode(
                returnUrl,
                "pending_state_missing");
        }

        var result = await signInService.RecoveryCodeSignInAsync(
            request.Code ?? string.Empty,
            cancellationToken);

        return result.Status switch
        {
            InteractiveSignInStatus.Succeeded => LocalRedirect(returnUrl),
            InteractiveSignInStatus.LockedOut => RedirectToRecoveryCode(
                returnUrl,
                "locked_out"),
            _ => RedirectToRecoveryCode(returnUrl, "invalid_code"),
        };
    }

    private async Task<bool> ValidateAntiforgeryAsync()
    {
        try
        {
            await antiforgery.ValidateRequestAsync(HttpContext);
            return true;
        }
        catch (AntiforgeryValidationException)
        {
            return false;
        }
    }

    private static bool ParseBoolean(string? value) =>
        bool.TryParse(value, out var parsed) && parsed;

    private RedirectResult RedirectToAuthenticator(
        string returnUrl,
        bool rememberMe,
        string error) =>
        Redirect(QueryHelpers.AddQueryString(
            "/account/loginwith2fa",
            new Dictionary<string, string?>
            {
                ["returnUrl"] = returnUrl,
                ["rememberMe"] = rememberMe.ToString(),
                ["error"] = error,
            }));

    private RedirectResult RedirectToRecoveryCode(
        string returnUrl,
        string error) =>
        Redirect(QueryHelpers.AddQueryString(
            "/account/loginwithrecoverycode",
            new Dictionary<string, string?>
            {
                ["returnUrl"] = returnUrl,
                ["error"] = error,
            }));

    public sealed class AuthenticatorRequest
    {
        public string? Code { get; init; }
        public string? RememberMe { get; init; }
        public bool RememberClient { get; init; }
        public string? ReturnUrl { get; init; }
    }

    public sealed class RecoveryCodeRequest
    {
        public string? Code { get; init; }
        public string? ReturnUrl { get; init; }
    }
}
