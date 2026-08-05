using System.Text;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Sufficit.Identity.Application.Accounts;

namespace Sufficit.Identity.STS.Controllers;

/// <summary>
/// Thin HTTP adapter for WebAuthn ceremonies. These endpoints exist because
/// ASP.NET Identity updates protected challenge state through its temporary
/// authentication scheme; executing them from a Blazor Server circuit would
/// occur after the response started.
/// </summary>
[ApiController]
[Route("account/passkeys")]
public sealed class AccountPasskeysController(
    IAccountPasskeyService accountPasskeys,
    IPasskeyAuthenticationService authentication,
    IAntiforgery antiforgery) : ControllerBase
{
    [Authorize]
    [HttpPost("creation-options")]
    public async Task<IActionResult> CreateRegistrationOptions(
        CancellationToken cancellationToken)
    {
        if (!await IsAntiforgeryValidAsync())
        {
            return BadRequest(PasskeyOptionsResult.Failure(
                "antiforgery-invalid",
                "A página expirou. Recarregue-a e tente novamente."));
        }

        var result = await accountPasskeys.CreateRegistrationOptionsAsync(
            User,
            cancellationToken);
        if (!result.Succeeded || string.IsNullOrWhiteSpace(result.OptionsJson))
        {
            return StatusCode(StatusCodeFor(result.Errors), result);
        }

        return Content(result.OptionsJson, "application/json", Encoding.UTF8);
    }

    [Authorize]
    [HttpPost("register")]
    public async Task<IActionResult> Register(
        [FromForm] string? credentialJson,
        [FromForm] string? name,
        CancellationToken cancellationToken)
    {
        if (!await IsAntiforgeryValidAsync())
        {
            return BadRequest(AccountPasskeyResult.Failure(
                "antiforgery-invalid",
                "A página expirou. Recarregue-a e tente novamente."));
        }

        var result = await accountPasskeys.RegisterAsync(
            User,
            new AccountPasskeyRegistration(credentialJson, name),
            cancellationToken);
        return StatusCode(
            result.Succeeded
                ? StatusCodes.Status200OK
                : StatusCodeFor(result.Errors),
            result);
    }

    [AllowAnonymous]
    [HttpPost("request-options")]
    public async Task<IActionResult> CreateRequestOptions(
        [FromQuery] string? username,
        CancellationToken cancellationToken)
    {
        if (!await IsAntiforgeryValidAsync())
        {
            return BadRequest(PasskeyOptionsResult.Failure(
                "antiforgery-invalid",
                "A página expirou. Recarregue-a e tente novamente."));
        }

        var result = await authentication.CreateRequestOptionsAsync(
            username,
            cancellationToken);
        if (!result.Succeeded || string.IsNullOrWhiteSpace(result.OptionsJson))
        {
            return StatusCode(StatusCodeFor(result.Errors), result);
        }

        return Content(result.OptionsJson, "application/json", Encoding.UTF8);
    }

    [AllowAnonymous]
    [HttpPost("authenticate")]
    public async Task<IActionResult> Authenticate(
        [FromForm] string? credentialJson,
        CancellationToken cancellationToken)
    {
        if (!await IsAntiforgeryValidAsync())
        {
            return BadRequest(PasskeyAuthenticationResult.Failure(
                "antiforgery-invalid",
                "A página expirou. Recarregue-a e tente novamente."));
        }

        var result = await authentication.SignInAsync(
            credentialJson,
            cancellationToken);
        return StatusCode(
            result.Succeeded
                ? StatusCodes.Status200OK
                : StatusCodeFor(result.Errors),
            result);
    }

    private async Task<bool> IsAntiforgeryValidAsync()
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

    private static int StatusCodeFor(
        IReadOnlyList<AccountSelfServiceError> errors) =>
        errors.FirstOrDefault()?.Code switch
        {
            "unauthenticated" => StatusCodes.Status401Unauthorized,
            "passkey-not-found" => StatusCodes.Status404NotFound,
            "passkey-limit-reached" => StatusCodes.Status409Conflict,
            "account-locked" => StatusCodes.Status423Locked,
            "sign-in-not-allowed" => StatusCodes.Status403Forbidden,
            "passkey-authentication-failed" => StatusCodes.Status401Unauthorized,
            _ => StatusCodes.Status400BadRequest,
        };
}
