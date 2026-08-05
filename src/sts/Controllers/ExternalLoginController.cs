using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using Sufficit.Identity.Application.Accounts;

namespace Sufficit.Identity.STS.Controllers;

/// <summary>
/// Same-origin transport for external authentication challenge and callback.
/// Provider and identity implementation details remain behind
/// <see cref="IExternalSignInService"/>.
/// </summary>
[ApiController]
public sealed class ExternalLoginController(
    IExternalSignInService externalSignInService) : ControllerBase
{
    [HttpGet("/account/externalchallenge")]
    public async Task<IActionResult> Challenge(
        [FromQuery] string provider,
        [FromQuery] string? returnUrl,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(provider))
            return BadRequest("Provider is required.");

        var safeReturnUrl = LocalUrlValidator.EnsureLocal(returnUrl);
        var callbackUri = QueryHelpers.AddQueryString(
            "/account/externallogincallback",
            "returnUrl",
            safeReturnUrl);
        var challenge = await externalSignInService.CreateChallengeAsync(
            provider,
            callbackUri,
            cancellationToken);
        var properties = new AuthenticationProperties
        {
            RedirectUri = challenge.RedirectUri,
        };
        foreach (var property in challenge.Properties)
        {
            properties.Items[property.Key] = property.Value;
        }

        return new ChallengeResult(
            challenge.AuthenticationScheme,
            properties);
    }

    [HttpGet("/account/externallogincallback")]
    public async Task<IActionResult> Callback(
        [FromQuery] string? returnUrl,
        CancellationToken cancellationToken)
    {
        var safeReturnUrl = LocalUrlValidator.EnsureLocal(returnUrl);
        var result = await externalSignInService.CompleteAsync(
            User,
            cancellationToken);
        return result.Status switch
        {
            ExternalSignInStatus.Succeeded => Redirect(safeReturnUrl),
            ExternalSignInStatus.Linked => RedirectLinked(
                safeReturnUrl,
                result.ProviderDisplayName),
            ExternalSignInStatus.LinkFailed => Redirect(
                QueryHelpers.AddQueryString(
                    "/manage/externallogins",
                    "error",
                    result.ErrorCode ?? "external-identity-link-failed")),
            ExternalSignInStatus.RequiresTwoFactor => Redirect(
                QueryHelpers.AddQueryString(
                    "/account/loginwith2fa",
                    "returnUrl",
                    safeReturnUrl)),
            ExternalSignInStatus.LockedOut => LoginError(
                "locked_out",
                safeReturnUrl),
            ExternalSignInStatus.NotAllowed => LoginError(
                "not_allowed",
                safeReturnUrl),
            ExternalSignInStatus.MissingEmail => LoginError(
                "no_email_from_provider",
                safeReturnUrl),
            ExternalSignInStatus.AccountLinkRequiresSignIn => LoginError(
                "account_link_requires_signin",
                safeReturnUrl),
            ExternalSignInStatus.RegistrationDisabled => LoginError(
                "registration_disabled",
                safeReturnUrl),
            ExternalSignInStatus.CreateFailed => LoginError(
                "create_failed",
                safeReturnUrl),
            _ => LoginError(
                "external_callback_unavailable",
                safeReturnUrl),
        };
    }

    private IActionResult RedirectLinked(
        string returnUrl,
        string? providerDisplayName)
    {
        if (!returnUrl.StartsWith(
                "/manage/externallogins",
                StringComparison.OrdinalIgnoreCase))
        {
            return Redirect(returnUrl);
        }

        return Redirect(QueryHelpers.AddQueryString(
            returnUrl,
            new Dictionary<string, string?>
            {
                ["status"] = "linked",
                ["provider"] = providerDisplayName,
            }));
    }

    private RedirectResult LoginError(string error, string returnUrl) =>
        Redirect(QueryHelpers.AddQueryString(
            "/account/login",
            new Dictionary<string, string?>
            {
                ["error"] = error,
                ["returnUrl"] = returnUrl,
            }));
}
