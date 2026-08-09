using System.Diagnostics.Metrics;
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
using Sufficit.Identity.Application.Accounts;
using Sufficit.Identity.Application.Security;

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
    IPublicOriginResolver publicOrigin,
    IAccountLookupPolicy accountLookup,
    IIdentityUserSessionRevoker sessionRevoker,
    ISecurityEventTrigger securityEvents,
    ILogger<AspNetCoreIdentityAccountOnboardingService> logger)
    : IAccountOnboardingService
{
    private const int PasswordResetRevocationAttempts = 3;
    private static readonly Meter SecurityMeter = new(
        "Sufficit.Identity.Security",
        "1.0.0");
    private static readonly Counter<long> PasswordResetRevocationCounter =
        SecurityMeter.CreateCounter<long>(
            "identity.security.password_reset_revocation");

    private readonly AccountRegistrationPolicy _registrationPolicy = new(
        configuration.GetValue(
            "Sufficit:Identity:Register:Enabled",
            true),
        configuration.GetValue(
            "Sufficit:Identity:Register:RequireUsername",
            false));

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
        var user = await accountLookup.FindUniqueByEmailAsync(email, cancellationToken);
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
        var user = await accountLookup.FindUniqueByEmailAsync(email, cancellationToken);
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
            // A password reset is the flow a victim uses AFTER losing control
            // of the account, so the attacker's existing access must not
            // survive it. ResetPasswordAsync rotates the security stamp
            // (invalidating cookies at the next stamp validation), but it does
            // NOT revoke issued OpenIddict refresh/access tokens, their
            // authorizations, or other browser sessions. Revoke everything —
            // unlike the authenticated change-password path there is no
            // current session to preserve, since this flow is unauthenticated.
            var revocation = await RevokePasswordResetSessionsAsync(
                user.Id,
                cancellationToken);
            if (revocation is not null)
            {
                logger.LogInformation(
                    "Password reset for user {UserId} revoked {TokenCount} tokens, "
                    + "{AuthorizationCount} authorizations and {BrowserSessionCount} browser sessions.",
                    user.Id,
                    revocation.RevokedTokens,
                    revocation.RevokedAuthorizations,
                    revocation.RevokedBrowserSessions);
            }

            // CAEP credential-change so SSF receivers can react (the
            // authenticated change-password path already emits this). Keep it
            // independent from local revocation: even if the database cleanup
            // exhausts its retries, receivers still get a chance to terminate
            // their own sessions.
            try
            {
                await securityEvents.CredentialChangedAsync(
                    user.Id,
                    sessionId: null,
                    new CaepCredentialChange(
                        CaepCredentialType.Password,
                        CaepChangeOperation.Updated),
                    cancellationToken);
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
                    "Password reset for user {UserId} succeeded but the "
                    + "credential-change signal failed.",
                    user.Id);
            }

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

    private async Task<IdentityUserSessionRevocation?>
        RevokePasswordResetSessionsAsync(
            string userId,
            CancellationToken cancellationToken)
    {
        for (var attempt = 1; attempt <= PasswordResetRevocationAttempts; attempt++)
        {
            try
            {
                var revocation = await sessionRevoker.RevokeAsync(
                    userId,
                    cancellationToken);
                PasswordResetRevocationCounter.Add(
                    1,
                    new KeyValuePair<string, object?>("outcome", "succeeded"),
                    new KeyValuePair<string, object?>("attempt", attempt));
                return revocation;
            }
            catch (OperationCanceledException)
                when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception exception)
            {
                var finalAttempt = attempt == PasswordResetRevocationAttempts;
                PasswordResetRevocationCounter.Add(
                    1,
                    new KeyValuePair<string, object?>(
                        "outcome",
                        finalAttempt ? "failed" : "retry"),
                    new KeyValuePair<string, object?>("attempt", attempt));

                if (finalAttempt)
                {
                    // ResetPasswordAsync already committed the new password and
                    // rotated the security stamp. Returning a generic failure
                    // would make the user retry with an invalidated reset token,
                    // so retain the successful result while emitting a critical,
                    // metric-backed operational signal.
                    logger.LogCritical(
                        exception,
                        "Password reset for user {UserId} succeeded, but token, "
                        + "authorization and browser-session revocation failed "
                        + "after {AttemptCount} attempts. Existing OAuth sessions "
                        + "may remain valid and require operational intervention.",
                        userId,
                        PasswordResetRevocationAttempts);
                    return null;
                }

                logger.LogWarning(
                    exception,
                    "Password reset session revocation for user {UserId} failed "
                    + "on attempt {Attempt}/{AttemptCount}; retrying.",
                    userId,
                    attempt,
                    PasswordResetRevocationAttempts);
                await Task.Delay(
                    TimeSpan.FromMilliseconds(50 * attempt),
                    cancellationToken);
            }
        }

        return null;
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
        var request = httpContextAccessor.HttpContext?.Request
            ?? throw new InvalidOperationException(
                "An HTTP request is required to build an account callback URL.");
        return publicOrigin.BuildAbsolute(request, pathWithQuery);
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
            .Select(error =>
            {
                // Finding #17 (anti-enumeration): collapse duplicate-username/
                // duplicate-email errors into a generic message so the
                // registration form does not reveal whether a specific
                // username or email is already taken.
                var description = error.Code switch
                {
                    "DuplicateUserName" => "Não foi possível criar a conta. Verifique os dados informados.",
                    "DuplicateEmail" => "Não foi possível criar a conta. Verifique os dados informados.",
                    _ => error.Description,
                };
                return new AccountLifecycleError(error.Code, description);
            })
            .ToArray();

    private static string EncodeToken(string token) =>
        WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(token));

    private static string DecodeToken(string encodedToken) =>
        Encoding.UTF8.GetString(
            WebEncoders.Base64UrlDecode(encodedToken));
}
