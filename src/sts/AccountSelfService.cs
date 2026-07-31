using System.Globalization;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.Core.Services;

namespace Sufficit.Identity.STS;

/// <summary>
/// ASP.NET Identity implementation of account self-service. This is the only
/// runtime path used by embedded UI adapters and future HTTP adapters.
/// </summary>
public sealed class AccountSelfService(
    UserManager<ApplicationUser> userManager,
    SignInManager<ApplicationUser> signInManager,
    IIdentityAccountLifecycleService accountLifecycle,
    IHttpContextAccessor httpContextAccessor,
    ILogger<AccountSelfService> logger)
    : IAccountSelfService
{
    private static readonly JsonSerializerOptions PersonalDataJsonOptions =
        new() { WriteIndented = true };

    public async Task<AccountSelfServiceProfile?> GetProfileAsync(
        ClaimsPrincipal principal,
        CancellationToken cancellationToken = default)
    {
        var user = await GetAuthenticatedUserAsync(
            principal,
            cancellationToken);
        if (user is null)
        {
            return null;
        }

        return new AccountSelfServiceProfile(
            user.Id,
            await userManager.GetUserNameAsync(user),
            await userManager.GetEmailAsync(user),
            await userManager.IsEmailConfirmedAsync(user));
    }

    public async Task<AccountSelfServiceResult> ChangePasswordAsync(
        ClaimsPrincipal principal,
        AccountPasswordChange command,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(command);

        var user = await GetAuthenticatedUserAsync(
            principal,
            cancellationToken);
        if (user is null)
        {
            return Unauthenticated();
        }

        if (string.IsNullOrWhiteSpace(command.CurrentPassword)
            || string.IsNullOrWhiteSpace(command.NewPassword))
        {
            return AccountSelfServiceResult.Failure(
                "password-required",
                "A senha atual e a nova senha são obrigatórias.");
        }

        if (!string.Equals(
                command.NewPassword,
                command.ConfirmPassword,
                StringComparison.Ordinal))
        {
            return AccountSelfServiceResult.Failure(
                "password-confirmation-mismatch",
                "A confirmação da nova senha não confere.");
        }

        cancellationToken.ThrowIfCancellationRequested();
        var result = await userManager.ChangePasswordAsync(
            user,
            command.CurrentPassword,
            command.NewPassword);
        if (!result.Succeeded)
        {
            return FromIdentityResult(result);
        }

        await TryRefreshSignInAsync(user);
        logger.LogInformation(
            "User {UserId} changed their password.",
            user.Id);
        return AccountSelfServiceResult.Success;
    }

    public async Task<AccountPersonalDataExport?> ExportPersonalDataAsync(
        ClaimsPrincipal principal,
        CancellationToken cancellationToken = default)
    {
        var user = await GetAuthenticatedUserAsync(
            principal,
            cancellationToken);
        if (user is null)
        {
            return null;
        }

        var personalData = new SortedDictionary<string, string>(
            StringComparer.Ordinal);
        foreach (var property in typeof(ApplicationUser)
                     .GetProperties()
                     .Where(property =>
                         property.CanRead
                         && (property.PropertyType.IsValueType
                             || property.PropertyType == typeof(string))
                         && property.Name
                             is not nameof(ApplicationUser.PasswordHash)
                             and not nameof(ApplicationUser.SecurityStamp)
                             and not nameof(ApplicationUser.ConcurrencyStamp)))
        {
            var value = property.GetValue(user);
            personalData[property.Name] = value switch
            {
                null => string.Empty,
                IFormattable formattable => formattable.ToString(
                    null,
                    CultureInfo.InvariantCulture),
                _ => value.ToString() ?? string.Empty,
            };
        }

        try
        {
            var claims = await userManager.GetClaimsAsync(user);
            personalData["Claims"] = string.Join(
                "; ",
                claims.Select(claim =>
                    $"{claim.Type}={claim.Value}"));
        }
        catch (Exception exception)
        {
            logger.LogWarning(
                exception,
                "Claims could not be included in the personal data export for user {UserId}.",
                user.Id);
        }

        try
        {
            var logins = await userManager.GetLoginsAsync(user);
            personalData["ExternalLogins"] = string.Join(
                "; ",
                logins.Select(login => login.LoginProvider));
        }
        catch (Exception exception)
        {
            logger.LogWarning(
                exception,
                "External logins could not be included in the personal data export for user {UserId}.",
                user.Id);
        }

        cancellationToken.ThrowIfCancellationRequested();
        var json = JsonSerializer.Serialize(
            personalData,
            PersonalDataJsonOptions);
        var fileName =
            $"personal-data-{user.Id}-{DateTime.UtcNow:yyyyMMdd}.json";

        logger.LogInformation(
            "Personal data was exported by user {UserId}.",
            user.Id);
        return new AccountPersonalDataExport(
            fileName,
            "application/json",
            Encoding.UTF8.GetBytes(json));
    }

    public async Task<AccountSelfServiceResult> DeleteAccountAsync(
        ClaimsPrincipal principal,
        AccountDeletionRequest command,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(command);

        var user = await GetAuthenticatedUserAsync(
            principal,
            cancellationToken);
        if (user is null)
        {
            return Unauthenticated();
        }

        var email = await userManager.GetEmailAsync(user);
        if (!string.Equals(
                command.Email,
                email,
                StringComparison.OrdinalIgnoreCase))
        {
            return AccountSelfServiceResult.Failure(
                "email-confirmation-mismatch",
                "E-mail não confere.");
        }

        if (!await userManager.CheckPasswordAsync(user, command.Password))
        {
            return AccountSelfServiceResult.Failure(
                "password-incorrect",
                "Senha incorreta.");
        }

        try
        {
            var revocation = await accountLifecycle.DeleteAsync(
                user,
                cancellationToken);
            await TrySignOutAsync();

            logger.LogInformation(
                "User {UserId} deleted their own account; {TokenCount} tokens and {AuthorizationCount} authorizations were revoked.",
                user.Id,
                revocation.RevokedTokens,
                revocation.RevokedAuthorizations);
            return AccountSelfServiceResult.Success;
        }
        catch (IdentityAccountLifecycleException exception)
        {
            logger.LogWarning(
                exception,
                "Self-service account deletion failed for user {UserId}.",
                user.Id);
            return FromIdentityResult(exception.Result);
        }
    }

    private async Task<ApplicationUser?> GetAuthenticatedUserAsync(
        ClaimsPrincipal principal,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(principal);
        cancellationToken.ThrowIfCancellationRequested();
        if (principal.Identity?.IsAuthenticated != true)
        {
            return null;
        }

        var user = await userManager.GetUserAsync(principal);
        cancellationToken.ThrowIfCancellationRequested();
        return user;
    }

    private async Task TryRefreshSignInAsync(ApplicationUser user)
    {
        if (httpContextAccessor.HttpContext is null)
        {
            return;
        }

        try
        {
            await signInManager.RefreshSignInAsync(user);
        }
        catch (Exception exception)
        {
            logger.LogWarning(
                exception,
                "The interactive session could not be refreshed after the password change for user {UserId}.",
                user.Id);
        }
    }

    private async Task TrySignOutAsync()
    {
        if (httpContextAccessor.HttpContext is null)
        {
            return;
        }

        try
        {
            await signInManager.SignOutAsync();
        }
        catch (Exception exception)
        {
            logger.LogWarning(
                exception,
                "The local interactive cookie could not be cleared after account deletion.");
        }
    }

    private static AccountSelfServiceResult FromIdentityResult(
        IdentityResult result) =>
        new(
            result.Succeeded,
            result.Errors
                .Select(error => new AccountSelfServiceError(
                    error.Code,
                    error.Description))
                .ToArray());

    private static AccountSelfServiceResult Unauthenticated() =>
        AccountSelfServiceResult.Failure(
            "unauthenticated",
            "A sessão não está autenticada.");
}
