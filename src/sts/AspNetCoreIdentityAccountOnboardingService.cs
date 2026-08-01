using System.Text;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.Core.Services;

namespace Sufficit.Identity.STS;

/// <summary>
/// ASP.NET Core Identity implementation of the canonical public account
/// onboarding and recovery boundary.
/// </summary>
public sealed class AspNetCoreIdentityAccountOnboardingService(
    UserManager<ApplicationUser> userManager,
    IEmailSender emailSender,
    IHttpContextAccessor httpContextAccessor,
    IConfiguration configuration,
    ILogger<AspNetCoreIdentityAccountOnboardingService> logger)
    : IAccountOnboardingService
{
    private readonly AccountRegistrationPolicy _registrationPolicy = new(
        configuration.GetValue(
            "Sufficit:Identity:Register:Enabled",
            true),
        configuration.GetValue(
            "Sufficit:Identity:Register:RequireUsername",
            false));

    private readonly string? _publicBaseUrl = configuration[
        "Sufficit:Identity:PublicUrl"]?.TrimEnd('/');

    public Task<AccountRegistrationPolicy> GetRegistrationPolicyAsync(
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult(_registrationPolicy);
    }

    public async Task<AccountRegistrationResult> RegisterAsync(
        AccountRegistrationCommand command,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(command);
        cancellationToken.ThrowIfCancellationRequested();
        if (!_registrationPolicy.Enabled)
        {
            return RegistrationFailure(
                "registration-disabled",
                "Cadastro de novas contas está desativado.");
        }

        var userName = _registrationPolicy.RequiresUserName
            ? command.UserName
            : command.Email;
        var user = new ApplicationUser
        {
            UserName = userName,
            Email = command.Email,
        };

        var creation = await userManager.CreateAsync(user, command.Password);
        cancellationToken.ThrowIfCancellationRequested();
        if (!creation.Succeeded)
        {
            return new AccountRegistrationResult(
                false,
                false,
                MapErrors(creation.Errors));
        }

        logger.LogInformation(
            "User {UserId} registered a new account.",
            user.Id);

        var delivered = await SendConfirmationMessageAsync(
            user,
            command.Email,
            cancellationToken);
        return new AccountRegistrationResult(true, delivered, []);
    }

    public async Task<AccountEmailRequestResult>
        RequestEmailConfirmationAsync(
            string email,
            CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var user = await userManager.FindByEmailAsync(email);
        cancellationToken.ThrowIfCancellationRequested();
        if (user is not null)
        {
            await SendConfirmationMessageAsync(
                user,
                email,
                cancellationToken);
        }

        return new AccountEmailRequestResult(true);
    }

    public async Task<AccountEmailConfirmationResult> ConfirmEmailAsync(
        string? userId,
        string? encodedToken,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (string.IsNullOrWhiteSpace(userId)
            || string.IsNullOrWhiteSpace(encodedToken))
        {
            return InvalidConfirmationRequest();
        }

        var user = await userManager.FindByIdAsync(userId);
        cancellationToken.ThrowIfCancellationRequested();
        if (user is null)
        {
            return InvalidConfirmationRequest();
        }

        string token;
        try
        {
            token = DecodeToken(encodedToken);
        }
        catch (FormatException)
        {
            return InvalidConfirmationRequest();
        }

        var confirmation = await userManager.ConfirmEmailAsync(user, token);
        cancellationToken.ThrowIfCancellationRequested();
        logger.LogInformation(
            "Email confirmation for {UserId}: {Status}.",
            user.Id,
            confirmation.Succeeded ? "succeeded" : "failed");
        return new AccountEmailConfirmationResult(
            confirmation.Succeeded
                ? AccountEmailConfirmationStatus.Succeeded
                : AccountEmailConfirmationStatus.Failed,
            MapErrors(confirmation.Errors));
    }

    public async Task<AccountEmailRequestResult> RequestPasswordResetAsync(
        string email,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var user = await userManager.FindByEmailAsync(email);
        cancellationToken.ThrowIfCancellationRequested();
        if (user is null || !await userManager.IsEmailConfirmedAsync(user))
        {
            return new AccountEmailRequestResult(true);
        }

        try
        {
            var token = await userManager.GeneratePasswordResetTokenAsync(user);
            var callbackUrl = BuildAbsolute(
                "/account/resetpassword",
                new Dictionary<string, string?>
                {
                    ["userId"] = user.Id,
                    ["code"] = EncodeToken(token),
                });
            var body = $"Redefina sua senha <a href=\"{HtmlEncoder.Default.Encode(callbackUrl)}\">clicando aqui</a>.";
            await emailSender.SendEmailAsync(
                email,
                "Redefinir senha — Sufficit Identity",
                body);
            cancellationToken.ThrowIfCancellationRequested();
            logger.LogInformation(
                "Password reset message accepted for user {UserId}.",
                user.Id);
        }
        catch (OperationCanceledException)
            when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception)
        {
            logger.LogError(
                exception,
                "Password reset message delivery failed for user {UserId}.",
                user.Id);
        }

        // Never reveal whether an account exists or whether delivery failed.
        return new AccountEmailRequestResult(true);
    }

    public async Task<AccountPasswordResetContext>
        GetPasswordResetContextAsync(
            string? userId,
            string? encodedToken,
            CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (string.IsNullOrWhiteSpace(userId)
            || string.IsNullOrWhiteSpace(encodedToken))
        {
            return new AccountPasswordResetContext(false, null);
        }

        var user = await userManager.FindByIdAsync(userId);
        cancellationToken.ThrowIfCancellationRequested();
        if (user is null)
        {
            return new AccountPasswordResetContext(false, null);
        }

        string token;
        try
        {
            token = DecodeToken(encodedToken);
        }
        catch (FormatException)
        {
            return new AccountPasswordResetContext(false, null);
        }

        var validToken = await userManager.VerifyUserTokenAsync(
            user,
            userManager.Options.Tokens.PasswordResetTokenProvider,
            UserManager<ApplicationUser>.ResetPasswordTokenPurpose,
            token);
        cancellationToken.ThrowIfCancellationRequested();
        if (!validToken)
        {
            return new AccountPasswordResetContext(false, null);
        }

        var label = await userManager.GetEmailAsync(user) ?? user.UserName;
        return string.IsNullOrWhiteSpace(label)
            ? new AccountPasswordResetContext(false, null)
            : new AccountPasswordResetContext(true, label);
    }

    public async Task<AccountPasswordResetResult> ResetPasswordAsync(
        AccountPasswordResetCommand command,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(command);
        cancellationToken.ThrowIfCancellationRequested();
        var user = await userManager.FindByIdAsync(command.UserId);
        cancellationToken.ThrowIfCancellationRequested();
        if (user is null)
        {
            return InvalidPasswordResetRequest();
        }

        string token;
        try
        {
            token = DecodeToken(command.EncodedToken);
        }
        catch (FormatException)
        {
            return InvalidPasswordResetRequest();
        }

        var reset = await userManager.ResetPasswordAsync(
            user,
            token,
            command.NewPassword);
        cancellationToken.ThrowIfCancellationRequested();
        if (reset.Succeeded)
        {
            logger.LogInformation(
                "Password reset succeeded for user {UserId}.",
                user.Id);
        }

        return new AccountPasswordResetResult(
            reset.Succeeded
                ? AccountPasswordResetStatus.Succeeded
                : AccountPasswordResetStatus.Failed,
            MapErrors(reset.Errors));
    }

    private async Task<bool> SendConfirmationMessageAsync(
        ApplicationUser user,
        string email,
        CancellationToken cancellationToken)
    {
        try
        {
            var token = await userManager
                .GenerateEmailConfirmationTokenAsync(user);
            var callbackUrl = BuildAbsolute(
                "/account/confirmemail",
                new Dictionary<string, string?>
                {
                    ["userId"] = user.Id,
                    ["code"] = EncodeToken(token),
                });
            var body = $"Confirme sua conta <a href=\"{HtmlEncoder.Default.Encode(callbackUrl)}\">clicando aqui</a>.";
            await emailSender.SendEmailAsync(
                email,
                "Confirme seu e-mail — Sufficit Identity",
                body);
            cancellationToken.ThrowIfCancellationRequested();
            return true;
        }
        catch (OperationCanceledException)
            when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception)
        {
            logger.LogError(
                exception,
                "Confirmation message delivery failed for user {UserId}.",
                user.Id);
            return false;
        }
    }

    private string BuildAbsolute(
        string relativePath,
        IEnumerable<KeyValuePair<string, string?>> query)
    {
        var pathWithQuery = QueryHelpers.AddQueryString(relativePath, query);
        if (!string.IsNullOrWhiteSpace(_publicBaseUrl))
        {
            return $"{_publicBaseUrl}{pathWithQuery}";
        }

        var request = httpContextAccessor.HttpContext?.Request
            ?? throw new InvalidOperationException(
                "An HTTP request is required to build an account callback URL.");
        return $"{request.Scheme}://{request.Host}{pathWithQuery}";
    }

    private static AccountRegistrationResult RegistrationFailure(
        string code,
        string description) =>
        new(false, false, [new AccountLifecycleError(code, description)]);

    private static AccountEmailConfirmationResult
        InvalidConfirmationRequest() =>
        new(AccountEmailConfirmationStatus.InvalidRequest, []);

    private static AccountPasswordResetResult InvalidPasswordResetRequest() =>
        new(AccountPasswordResetStatus.InvalidRequest, []);

    private static IReadOnlyList<AccountLifecycleError> MapErrors(
        IEnumerable<IdentityError> errors) =>
        errors
            .Select(error => new AccountLifecycleError(
                error.Code,
                error.Description))
            .ToArray();

    private static string EncodeToken(string token) =>
        WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(token));

    private static string DecodeToken(string encodedToken) =>
        Encoding.UTF8.GetString(
            WebEncoders.Base64UrlDecode(encodedToken));
}
