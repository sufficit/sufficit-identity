using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using Sufficit.Identity.Application.Accounts;
using Sufficit.Identity.Application.Security;
using Sufficit.Identity.STS.Security;

namespace Sufficit.Identity.STS.Controllers;

/// <summary>
/// Handles password sign-in on a normal HTTP request so ASP.NET Core Identity
/// can issue the application cookie before the response starts. Cookie
/// authentication must never run from an already-established Blazor circuit.
/// </summary>
[ApiController]
public sealed class PasswordLoginController(
    IInteractiveSignInService signInService,
    IAntiforgery antiforgery,
    CredentialAbuseGuard abuseGuard,
    CredentialAbuseOptions abuseOptions,
    IHumanVerificationService humanVerification,
    HumanVerificationOptions humanVerificationOptions) : ControllerBase
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

        // Shared, per account and per IP (plan D6): decided before the password
        // is even looked at, so a refused attempt costs the attacker a guess.
        var account = request.UserName ?? string.Empty;
        var ip = ClientAddressPartition.Of(HttpContext.Connection.RemoteIpAddress);
        var decision = await abuseGuard.EvaluateAsync(account, ip, cancellationToken);
        _requireVerification = decision.Action == CredentialAbuseAction.RequireVerification
            && humanVerificationOptions.Protects(HumanVerificationFlow.Login);
        switch (decision.Action)
        {
            case CredentialAbuseAction.Block:
                return LoginError("too_many_attempts", returnUrl, request);
            case CredentialAbuseAction.Delay:
                await Task.Delay(decision.Delay, cancellationToken);
                break;
            case CredentialAbuseAction.RequireVerification
                when humanVerificationOptions.Protects(HumanVerificationFlow.Login):
                var verification = await humanVerification.VerifyAsync(
                    HumanVerificationFlow.Login,
                    Request.HasFormContentType ? Request.Form[HumanVerificationResponseField].ToString() : null,
                    cancellationToken);
                if (!verification.Succeeded)
                    return LoginError("verification_required", returnUrl, request);
                break;
            case CredentialAbuseAction.RequireVerification:
                // No verification provider: the longest delay is the next best brake.
                await Task.Delay(TimeSpan.FromSeconds(Math.Max(1, abuseOptions.MaxDelaySeconds)), cancellationToken);
                break;
        }

        var result = await signInService.PasswordSignInAsync(
            new PasswordSignInCommand(
                request.UserName ?? string.Empty,
                request.Password ?? string.Empty,
                request.RememberMe,
                UseEmail: request.FromRegistration),
            cancellationToken);

        // A right password clears the account's count (LockedOut and NotAllowed
        // are only reported for one: WithoutEnumerationAsync turns them into
        // Failed otherwise); a wrong one adds to it.
        if (result.Status is InteractiveSignInStatus.Failed)
            await abuseGuard.RecordFailureAsync(account, ip, cancellationToken);
        else if (result.Status is InteractiveSignInStatus.Succeeded or InteractiveSignInStatus.RequiresTwoFactor
            or InteractiveSignInStatus.NotAllowed or InteractiveSignInStatus.LockedOut)
            await abuseGuard.RecordSuccessAsync(account, cancellationToken);

        return result.Status switch
        {
            InteractiveSignInStatus.Succeeded => SignedIn(returnUrl),
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

    /// <summary>Form field the human-verification widget writes its token to.</summary>
    internal const string HumanVerificationResponseField = "human-verification-response";

    private RedirectResult SignedIn(string returnUrl)
    {
        LoginErrorLocation.Reset(HttpContext);
        return Redirect(AuthenticationContinuation.Location(returnUrl, HttpContext));
    }

    // Set per request (controllers are transient): every error answer while
    // verification is required keeps the widget on the page.
    private bool _requireVerification;

    private RedirectResult LoginError(string error, string returnUrl, PasswordLoginRequest? request = null) =>
        Redirect(LoginErrorLocation.Build(
            HttpContext,
            error,
            returnUrl,
            request?.FromRegistration == true ? request.UserName : null,
            _requireVerification));

    public sealed class PasswordLoginRequest
    {
        public string? UserName { get; init; }
        public string? Password { get; init; }
        public bool RememberMe { get; init; }
        public string? ReturnUrl { get; init; }
        public bool FromRegistration { get; init; }
    }
}
