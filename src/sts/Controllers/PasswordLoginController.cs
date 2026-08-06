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
                request.RememberMe),
            cancellationToken);

        return result.Status switch
        {
            InteractiveSignInStatus.Succeeded => LocalRedirect(returnUrl),
            InteractiveSignInStatus.RequiresTwoFactor => Redirect(
                QueryHelpers.AddQueryString(
                    "/account/loginwith2fa",
                    new Dictionary<string, string?>
                    {
                        ["returnUrl"] = returnUrl,
                        ["rememberMe"] = request.RememberMe.ToString(),
                    })),
            InteractiveSignInStatus.LockedOut =>
                LoginError("locked_out", returnUrl),
            InteractiveSignInStatus.NotAllowed =>
                LoginError("not_allowed", returnUrl),
            _ => LoginError("invalid_credentials", returnUrl),
        };
    }

    private RedirectResult LoginError(string error, string returnUrl) =>
        Redirect(QueryHelpers.AddQueryString(
            "/account/login",
            new Dictionary<string, string?>
            {
                ["error"] = error,
                ["returnUrl"] = returnUrl,
            }));

    public sealed class PasswordLoginRequest
    {
        public string? UserName { get; init; }
        public string? Password { get; init; }
        public bool RememberMe { get; init; }
        public string? ReturnUrl { get; init; }
    }
}
