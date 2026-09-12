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
            forceMfa: safeReturnUrl.StartsWith(
                "/management",
                StringComparison.OrdinalIgnoreCase),
            cancellationToken: cancellationToken);
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
            ExternalSignInStatus.EmailVerificationRequired => LoginNotice(
                "external_email_verification_sent",
                safeReturnUrl),
            ExternalSignInStatus.RegistrationDeniedForProvider => LoginError(
                "registration_denied_for_provider",
                safeReturnUrl),
            _ => LoginError(
                "external_callback_unavailable",
                safeReturnUrl),
        };
    }

    /// <summary>
    /// Redeems the proof-of-possession ticket sent to an address that an
    /// external provider asserted but did not verify. This is where the account
    /// is created and bound — not at the provider callback.
    /// </summary>
    /// <remarks>
    /// Anonymous by design: the person proving the address has no session yet,
    /// and commonly opens the link in a different browser than the one that
    /// started the provider flow.
    /// </remarks>
    [HttpGet("/account/externallink/confirm")]
    public async Task<IActionResult> ConfirmLink(
        [FromQuery] string? ticket,
        CancellationToken cancellationToken)
    {
        var result = await externalSignInService.CompletePendingLinkAsync(
            ticket,
            cancellationToken);
        return result.Status switch
        {
            ExternalSignInStatus.Succeeded => Redirect("/"),
            ExternalSignInStatus.NotAllowed => LoginError("not_allowed", "/"),
            ExternalSignInStatus.AccountLinkRequiresSignIn => LoginError(
                "account_link_requires_signin",
                "/"),
            ExternalSignInStatus.CreateFailed => LoginError("create_failed", "/"),
            _ => LoginError("external_link_ticket_invalid", "/"),
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

    /// <summary>
    /// A non-error outcome the login page should explain rather than flag: the
    /// flow did not fail, it is waiting on the user's mailbox.
    /// </summary>
    private RedirectResult LoginNotice(string notice, string returnUrl) =>
        Redirect(QueryHelpers.AddQueryString(
            "/account/login",
            new Dictionary<string, string?>
            {
                ["notice"] = notice,
                ["returnUrl"] = returnUrl,
            }));

    private RedirectResult LoginError(string error, string returnUrl) =>
        Redirect(QueryHelpers.AddQueryString(
            "/account/login",
            new Dictionary<string, string?>
            {
                ["error"] = error,
                ["returnUrl"] = returnUrl,
            }));
}
