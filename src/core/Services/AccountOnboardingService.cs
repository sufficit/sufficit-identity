namespace Sufficit.Identity.Core.Services;

/// <summary>
/// Runtime-owned public account policy projected to presentation clients.
/// </summary>
public sealed record AccountRegistrationPolicy(
    bool Enabled,
    bool RequiresUserName);

public sealed record AccountRegistrationCommand(
    string? UserName,
    string Email,
    string Password);

public sealed record AccountLifecycleError(
    string Code,
    string Description);

public sealed record AccountRegistrationResult(
    bool Succeeded,
    bool ConfirmationMessageSent,
    IReadOnlyList<AccountLifecycleError> Errors);

public sealed record AccountEmailRequestResult(bool Accepted);

public enum AccountEmailConfirmationStatus
{
    Succeeded,
    InvalidRequest,
    Failed,
}

public sealed record AccountEmailConfirmationResult(
    AccountEmailConfirmationStatus Status,
    IReadOnlyList<AccountLifecycleError> Errors);

public sealed record AccountPasswordResetContext(
    bool IsValid,
    string? AccountLabel);

public sealed record AccountPasswordResetCommand(
    string UserId,
    string EncodedToken,
    string NewPassword);

public enum AccountPasswordResetStatus
{
    Succeeded,
    InvalidRequest,
    Failed,
}

public sealed record AccountPasswordResetResult(
    AccountPasswordResetStatus Status,
    IReadOnlyList<AccountLifecycleError> Errors);

/// <summary>
/// Canonical boundary for public registration, email confirmation and password
/// recovery. Identity stores, token formats, callback construction and email
/// delivery are runtime implementation details.
/// </summary>
public interface IAccountOnboardingService
{
    Task<AccountRegistrationPolicy> GetRegistrationPolicyAsync(
        CancellationToken cancellationToken = default);

    Task<AccountRegistrationResult> RegisterAsync(
        AccountRegistrationCommand command,
        CancellationToken cancellationToken = default);

    Task<AccountEmailRequestResult> RequestEmailConfirmationAsync(
        string email,
        CancellationToken cancellationToken = default);

    Task<AccountEmailConfirmationResult> ConfirmEmailAsync(
        string? userId,
        string? encodedToken,
        CancellationToken cancellationToken = default);

    Task<AccountEmailRequestResult> RequestPasswordResetAsync(
        string email,
        CancellationToken cancellationToken = default);

    Task<AccountPasswordResetContext> GetPasswordResetContextAsync(
        string? userId,
        string? encodedToken,
        CancellationToken cancellationToken = default);

    Task<AccountPasswordResetResult> ResetPasswordAsync(
        AccountPasswordResetCommand command,
        CancellationToken cancellationToken = default);
}
