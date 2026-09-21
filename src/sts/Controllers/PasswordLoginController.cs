using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using Sufficit.Identity.Application.Accounts;

namespace Sufficit.Identity.STS.Controllers;

/// <summary>
/// Handles password sign-in on a normal HTTP request so ASP.NET Core Identity
/// can issue the application cookie before the response starts. Cookie
/// authentication must never run from an already-established Blazor circuit.
/// </summary>
[ApiController]
public sealed class PasswordLoginController(
    IInteractiveSignInService signInService,
    IAntiforgery antiforgery) : ControllerBase
{
    [AllowAnonymous]
    [HttpPost("/account/login/password")]
    [Consumes("application/x-www-form-urlencoded")]
    public async Task<IActionResult> Login(
        [FromForm] PasswordLoginRequest request,
        CancellationToken cancellationToken)
    {
        var returnUrl = LocalUrlValidator.EnsureLocal(request.ReturnUrl);

        try
        {
            await antiforgery.ValidateRequestAsync(HttpContext);
        }
        catch (AntiforgeryValidationException)
        {
            return LoginError("request_expired", returnUrl);
        }

        var result = await signInService.PasswordSignInAsync(
            new PasswordSignInCommand(
                request.UserName ?? string.Empty,
                request.Password ?? string.Empty,
                request.RememberMe,
                UseEmail: request.FromRegistration),
            cancellationToken);

        return result.Status switch
        {
            InteractiveSignInStatus.Succeeded => Redirect(
                AuthenticationContinuation.Location(returnUrl, HttpContext)),
            InteractiveSignInStatus.RequiresTwoFactor => Redirect(
                QueryHelpers.AddQueryString(
                    "/account/loginwith2fa",
                    new Dictionary<string, string?>
                    {
                        ["returnUrl"] = returnUrl,
                        ["rememberMe"] = request.RememberMe.ToString(),
                    })),
            InteractiveSignInStatus.LockedOut =>
                LoginError("locked_out", returnUrl, request),
            InteractiveSignInStatus.NotAllowed =>
                LoginError("not_allowed", returnUrl, request),
            InteractiveSignInStatus.RequiresExternalSignIn => Redirect(
                QueryHelpers.AddQueryString("/account/login", new Dictionary<string, string?>
                {
                    ["notice"] = "external_signin",
                    ["returnUrl"] = returnUrl,
                    ["login_hint"] = request.UserName,
                })),
            _ => LoginError(request.FromRegistration ? "invalid_password" : "invalid_credentials", returnUrl, request),
        };
    }

    private RedirectResult LoginError(string error, string returnUrl, PasswordLoginRequest? request = null) =>
        Redirect(QueryHelpers.AddQueryString(
            "/account/login",
            new Dictionary<string, string?>
            {
                ["error"] = error,
                ["returnUrl"] = returnUrl,
                ["login_hint"] = request?.FromRegistration == true ? request.UserName : null,
            }));

    public sealed class PasswordLoginRequest
    {
        public string? UserName { get; init; }
        public string? Password { get; init; }
        public bool RememberMe { get; init; }
        public string? ReturnUrl { get; init; }
        public bool FromRegistration { get; init; }
    }
}
