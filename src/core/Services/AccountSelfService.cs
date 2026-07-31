using System.Security.Claims;

namespace Sufficit.Identity.Core.Services;

/// <summary>
/// Read model for the authenticated user's account.
/// </summary>
public sealed record AccountSelfServiceProfile(
    string UserId,
    string? UserName,
    string? Email,
    bool EmailConfirmed);

public sealed record AccountPasswordChange(
    string CurrentPassword,
    string NewPassword,
    string ConfirmPassword);

public sealed record AccountDeletionRequest(
    string Email,
    string Password);

public sealed record AccountSelfServiceError(
    string Code,
    string Description);

public sealed record AccountSelfServiceResult(
    bool Succeeded,
    IReadOnlyList<AccountSelfServiceError> Errors)
{
    public static AccountSelfServiceResult Success { get; } =
        new(true, Array.Empty<AccountSelfServiceError>());

    public static AccountSelfServiceResult Failure(
        string code,
        string description) =>
        new(
            false,
            [new AccountSelfServiceError(code, description)]);
}

public sealed record AccountPersonalDataExport(
    string FileName,
    string ContentType,
    byte[] Content);

/// <summary>
/// Canonical application boundary for authenticated account self-service.
/// UI and HTTP adapters pass the current principal and never access Identity
/// stores or mutable user entities directly.
/// </summary>
public interface IAccountSelfService
{
    Task<AccountSelfServiceProfile?> GetProfileAsync(
        ClaimsPrincipal principal,
        CancellationToken cancellationToken = default);

    Task<AccountSelfServiceResult> ChangePasswordAsync(
        ClaimsPrincipal principal,
        AccountPasswordChange command,
        CancellationToken cancellationToken = default);

    Task<AccountPersonalDataExport?> ExportPersonalDataAsync(
        ClaimsPrincipal principal,
        CancellationToken cancellationToken = default);

    Task<AccountSelfServiceResult> DeleteAccountAsync(
        ClaimsPrincipal principal,
        AccountDeletionRequest command,
        CancellationToken cancellationToken = default);
}
