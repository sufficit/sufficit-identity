using System.Security.Claims;

namespace Sufficit.Identity.Application.Accounts;

public sealed record AccountAuthenticatorSetup(
    string SharedKey,
    string ManualKey,
    string AuthenticatorUri);

public sealed record AccountTwoFactorOverview(
    bool IsEnabled,
    int RecoveryCodesRemaining,
    AccountAuthenticatorSetup? AuthenticatorSetup);

public sealed record AccountTwoFactorResult(
    bool Succeeded,
    IReadOnlyList<AccountSelfServiceError> Errors,
    AccountTwoFactorOverview? State,
    IReadOnlyList<string> RecoveryCodes)
{
    public static AccountTwoFactorResult Success(
        AccountTwoFactorOverview state,
        IReadOnlyList<string>? recoveryCodes = null) =>
        new(
            true,
            [],
            state,
            recoveryCodes ?? []);

    public static AccountTwoFactorResult Failure(
        string code,
        string description,
        AccountTwoFactorOverview? state = null) =>
        new(
            false,
            [new AccountSelfServiceError(code, description)],
            state,
            []);
}

/// <summary>
/// Provider-neutral application boundary for authenticator-app two-factor
/// management. UI adapters never access identity stores or token providers.
/// </summary>
public interface IAccountTwoFactorService
{
    Task<AccountTwoFactorOverview?> GetOverviewAsync(
        ClaimsPrincipal principal,
        CancellationToken cancellationToken = default);

    Task<AccountTwoFactorResult> BeginSetupAsync(
        ClaimsPrincipal principal,
        CancellationToken cancellationToken = default);

    Task<AccountTwoFactorResult> EnableAsync(
        ClaimsPrincipal principal,
        string verificationCode,
        CancellationToken cancellationToken = default);

    Task<AccountTwoFactorResult> GenerateRecoveryCodesAsync(
        ClaimsPrincipal principal,
        CancellationToken cancellationToken = default);

    Task<AccountTwoFactorResult> ResetAuthenticatorAsync(
        ClaimsPrincipal principal,
        CancellationToken cancellationToken = default);

    Task<AccountTwoFactorResult> DisableAsync(
        ClaimsPrincipal principal,
        CancellationToken cancellationToken = default);
}
