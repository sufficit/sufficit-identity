using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.Core.Services;

namespace Sufficit.Identity.STS;

/// <summary>
/// ASP.NET Identity adapter for authenticator-app two-factor management.
/// </summary>
public sealed class AspNetCoreIdentityAccountTwoFactorService(
    UserManager<ApplicationUser> userManager,
    SignInManager<ApplicationUser> signInManager,
    IHttpContextAccessor httpContextAccessor,
    TwoFactorOptions options,
    ILogger<AspNetCoreIdentityAccountTwoFactorService> logger)
    : IAccountTwoFactorService
{
    public async Task<AccountTwoFactorOverview?> GetOverviewAsync(
        ClaimsPrincipal principal,
        CancellationToken cancellationToken = default)
    {
        var user = await GetAuthenticatedUserAsync(principal, cancellationToken);
        return user is null
            ? null
            : await BuildOverviewAsync(user, cancellationToken);
    }

    public async Task<AccountTwoFactorResult> BeginSetupAsync(
        ClaimsPrincipal principal,
        CancellationToken cancellationToken = default)
    {
        var user = await GetAuthenticatedUserAsync(principal, cancellationToken);
        if (user is null)
        {
            return Unauthenticated();
        }

        if (await userManager.GetTwoFactorEnabledAsync(user))
        {
            return AccountTwoFactorResult.Failure(
                "two-factor-already-enabled",
                "A autenticação em duas etapas já está ativada.",
                await BuildOverviewAsync(user, cancellationToken));
        }

        var key = await userManager.GetAuthenticatorKeyAsync(user);
        if (string.IsNullOrWhiteSpace(key))
        {
            var reset = await userManager.ResetAuthenticatorKeyAsync(user);
            if (!reset.Succeeded)
            {
                return await FromIdentityResultAsync(
                    reset,
                    user,
                    cancellationToken);
            }

            key = await userManager.GetAuthenticatorKeyAsync(user);
        }

        if (string.IsNullOrWhiteSpace(key))
        {
            return AccountTwoFactorResult.Failure(
                "authenticator-key-unavailable",
                "Não foi possível preparar a chave do autenticador.");
        }

        var state = await BuildOverviewAsync(user, cancellationToken);
        logger.LogInformation(
            "User {UserId} began authenticator setup.",
            user.Id);
        return AccountTwoFactorResult.Success(state);
    }

    public async Task<AccountTwoFactorResult> EnableAsync(
        ClaimsPrincipal principal,
        string verificationCode,
        CancellationToken cancellationToken = default)
    {
        var user = await GetAuthenticatedUserAsync(principal, cancellationToken);
        if (user is null)
        {
            return Unauthenticated();
        }

        var state = await BuildOverviewAsync(user, cancellationToken);
        if (state.IsEnabled)
        {
            return AccountTwoFactorResult.Failure(
                "two-factor-already-enabled",
                "A autenticação em duas etapas já está ativada.",
                state);
        }

        var code = NormalizeVerificationCode(verificationCode);
        if (code.Length != 6 || code.Any(character => character is < '0' or > '9'))
        {
            return AccountTwoFactorResult.Failure(
                "authenticator-code-invalid",
                "Informe o código de seis dígitos exibido pelo aplicativo autenticador.",
                state);
        }

        if (state.AuthenticatorSetup is null)
        {
            return AccountTwoFactorResult.Failure(
                "authenticator-setup-required",
                "Inicie a configuração do aplicativo autenticador antes de confirmar o código.",
                state);
        }

        cancellationToken.ThrowIfCancellationRequested();
        var valid = await userManager.VerifyTwoFactorTokenAsync(
            user,
            userManager.Options.Tokens.AuthenticatorTokenProvider,
            code);
        if (!valid)
        {
            return AccountTwoFactorResult.Failure(
                "authenticator-code-invalid",
                "O código informado é inválido ou expirou. Use o código atual do aplicativo.",
                state);
        }

        var enabled = await userManager.SetTwoFactorEnabledAsync(user, true);
        if (!enabled.Succeeded)
        {
            return await FromIdentityResultAsync(
                enabled,
                user,
                cancellationToken);
        }

        var recoveryCodes = await GenerateRecoveryCodesInternalAsync(
            user,
            cancellationToken);
        var enabledState = await BuildOverviewAsync(user, cancellationToken);
        await TryRefreshSignInAsync(user);
        if (recoveryCodes is null)
        {
            return AccountTwoFactorResult.Failure(
                "recovery-codes-generation-failed",
                "A autenticação em duas etapas foi ativada, mas os códigos de recuperação não puderam ser gerados. Gere novos códigos antes de sair.",
                enabledState);
        }

        logger.LogInformation(
            "User {UserId} enabled authenticator two-factor authentication.",
            user.Id);
        return AccountTwoFactorResult.Success(enabledState, recoveryCodes);
    }

    public async Task<AccountTwoFactorResult> GenerateRecoveryCodesAsync(
        ClaimsPrincipal principal,
        CancellationToken cancellationToken = default)
    {
        var user = await GetAuthenticatedUserAsync(principal, cancellationToken);
        if (user is null)
        {
            return Unauthenticated();
        }

        if (!await userManager.GetTwoFactorEnabledAsync(user))
        {
            return AccountTwoFactorResult.Failure(
                "two-factor-not-enabled",
                "Ative a autenticação em duas etapas antes de gerar códigos de recuperação.",
                await BuildOverviewAsync(user, cancellationToken));
        }

        var recoveryCodes = await GenerateRecoveryCodesInternalAsync(
            user,
            cancellationToken);
        var state = await BuildOverviewAsync(user, cancellationToken);
        if (recoveryCodes is null)
        {
            return AccountTwoFactorResult.Failure(
                "recovery-codes-generation-failed",
                "Não foi possível gerar novos códigos de recuperação.",
                state);
        }

        logger.LogInformation(
            "User {UserId} regenerated two-factor recovery codes.",
            user.Id);
        return AccountTwoFactorResult.Success(state, recoveryCodes);
    }

    public async Task<AccountTwoFactorResult> ResetAuthenticatorAsync(
        ClaimsPrincipal principal,
        CancellationToken cancellationToken = default)
    {
        var user = await GetAuthenticatedUserAsync(principal, cancellationToken);
        if (user is null)
        {
            return Unauthenticated();
        }

        var disabled = await userManager.SetTwoFactorEnabledAsync(user, false);
        if (!disabled.Succeeded)
        {
            return await FromIdentityResultAsync(
                disabled,
                user,
                cancellationToken);
        }

        var reset = await userManager.ResetAuthenticatorKeyAsync(user);
        if (!reset.Succeeded)
        {
            return await FromIdentityResultAsync(
                reset,
                user,
                cancellationToken);
        }

        await TryRefreshSignInAsync(user);
        var state = await BuildOverviewAsync(user, cancellationToken);
        logger.LogInformation(
            "User {UserId} reset their authenticator key.",
            user.Id);
        return AccountTwoFactorResult.Success(state);
    }

    public async Task<AccountTwoFactorResult> DisableAsync(
        ClaimsPrincipal principal,
        CancellationToken cancellationToken = default)
    {
        var user = await GetAuthenticatedUserAsync(principal, cancellationToken);
        if (user is null)
        {
            return Unauthenticated();
        }

        var result = await userManager.SetTwoFactorEnabledAsync(user, false);
        if (!result.Succeeded)
        {
            return await FromIdentityResultAsync(
                result,
                user,
                cancellationToken);
        }

        await TryRefreshSignInAsync(user);
        var state = await BuildOverviewAsync(user, cancellationToken);
        logger.LogInformation(
            "User {UserId} disabled authenticator two-factor authentication.",
            user.Id);
        return AccountTwoFactorResult.Success(state);
    }

    private async Task<AccountTwoFactorOverview> BuildOverviewAsync(
        ApplicationUser user,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var enabled = await userManager.GetTwoFactorEnabledAsync(user);
        var recoveryCodes = await userManager.CountRecoveryCodesAsync(user);
        AccountAuthenticatorSetup? setup = null;
        if (!enabled)
        {
            var key = await userManager.GetAuthenticatorKeyAsync(user);
            if (!string.IsNullOrWhiteSpace(key))
            {
                var accountName = await userManager.GetEmailAsync(user)
                    ?? await userManager.GetUserNameAsync(user)
                    ?? user.Id;
                setup = new AccountAuthenticatorSetup(
                    key,
                    FormatManualKey(key),
                    BuildAuthenticatorUri(accountName, key));
            }
        }

        cancellationToken.ThrowIfCancellationRequested();
        return new AccountTwoFactorOverview(enabled, recoveryCodes, setup);
    }

    private async Task<IReadOnlyList<string>?> GenerateRecoveryCodesInternalAsync(
        ApplicationUser user,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var count = Math.Clamp(options.RecoveryCodeCount, 1, 20);
        var codes = await userManager.GenerateNewTwoFactorRecoveryCodesAsync(
            user,
            count);
        cancellationToken.ThrowIfCancellationRequested();
        return codes?.ToArray();
    }

    private async Task<AccountTwoFactorResult> FromIdentityResultAsync(
        IdentityResult result,
        ApplicationUser user,
        CancellationToken cancellationToken) =>
        new(
            result.Succeeded,
            result.Errors
                .Select(error => new AccountSelfServiceError(
                    error.Code,
                    error.Description))
                .ToArray(),
            await BuildOverviewAsync(user, cancellationToken),
            []);

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
                "The interactive session could not be refreshed after changing two-factor settings for user {UserId}.",
                user.Id);
        }
    }

    private string BuildAuthenticatorUri(string accountName, string key)
    {
        var issuer = string.IsNullOrWhiteSpace(options.AuthenticatorIssuer)
            ? "Sufficit Identity"
            : options.AuthenticatorIssuer.Trim();
        return $"otpauth://totp/{Uri.EscapeDataString(issuer)}:{Uri.EscapeDataString(accountName)}"
            + $"?secret={Uri.EscapeDataString(key)}"
            + $"&issuer={Uri.EscapeDataString(issuer)}&digits=6";
    }

    private static string FormatManualKey(string key) =>
        string.Join(
            ' ',
            Enumerable.Range(0, (key.Length + 3) / 4)
                .Select(index => key.Substring(
                    index * 4,
                    Math.Min(4, key.Length - index * 4))));

    private static string NormalizeVerificationCode(string? value) =>
        (value ?? "")
            .Replace(" ", "", StringComparison.Ordinal)
            .Replace("-", "", StringComparison.Ordinal);

    private static AccountTwoFactorResult Unauthenticated() =>
        AccountTwoFactorResult.Failure(
            "unauthenticated",
            "A sessão não está autenticada.");
}
