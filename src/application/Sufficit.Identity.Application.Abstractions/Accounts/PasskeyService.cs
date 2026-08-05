using System.Security.Claims;

namespace Sufficit.Identity.Application.Accounts;

/// <summary>
/// Provider-neutral projection of a WebAuthn credential owned by an account.
/// The credential identifier is opaque and URL-safe; key material and
/// attestation payloads never cross the application boundary.
/// </summary>
public sealed record AccountPasskeyCredential(
    string CredentialId,
    string? Name,
    DateTimeOffset CreatedAt,
    bool IsBackedUp,
    bool IsBackupEligible);

public sealed record AccountPasskeyOverview(
    IReadOnlyList<AccountPasskeyCredential> Credentials,
    int MaximumCredentials,
    int MaximumNameLength,
    bool CanRegister);

public sealed record AccountPasskeyRegistration(
    string? CredentialJson,
    string? Name);

public sealed record AccountPasskeyRename(
    string CredentialId,
    string? Name);

public sealed record PasskeyOptionsResult(
    bool Succeeded,
    IReadOnlyList<AccountSelfServiceError> Errors,
    string? OptionsJson)
{
    public static PasskeyOptionsResult Success(string optionsJson) =>
        new(true, [], optionsJson);

    public static PasskeyOptionsResult Failure(
        string code,
        string description) =>
        new(
            false,
            [new AccountSelfServiceError(code, description)],
            null);
}

public sealed record AccountPasskeyResult(
    bool Succeeded,
    IReadOnlyList<AccountSelfServiceError> Errors,
    AccountPasskeyOverview? State)
{
    public static AccountPasskeyResult Success(AccountPasskeyOverview state) =>
        new(true, [], state);

    public static AccountPasskeyResult Failure(
        string code,
        string description,
        AccountPasskeyOverview? state = null) =>
        new(
            false,
            [new AccountSelfServiceError(code, description)],
            state);
}

public sealed record PasskeyAuthenticationResult(
    bool Succeeded,
    IReadOnlyList<AccountSelfServiceError> Errors)
{
    public static PasskeyAuthenticationResult Success { get; } =
        new(true, []);

    public static PasskeyAuthenticationResult Failure(
        string code,
        string description) =>
        new(
            false,
            [new AccountSelfServiceError(code, description)]);
}

/// <summary>
/// Canonical application boundary for passkeys owned by the authenticated
/// account. UI adapters never access identity stores or mutable credentials.
/// </summary>
public interface IAccountPasskeyService
{
    Task<AccountPasskeyOverview?> GetOverviewAsync(
        ClaimsPrincipal principal,
        CancellationToken cancellationToken = default);

    Task<PasskeyOptionsResult> CreateRegistrationOptionsAsync(
        ClaimsPrincipal principal,
        CancellationToken cancellationToken = default);

    Task<AccountPasskeyResult> RegisterAsync(
        ClaimsPrincipal principal,
        AccountPasskeyRegistration command,
        CancellationToken cancellationToken = default);

    Task<AccountPasskeyResult> RenameAsync(
        ClaimsPrincipal principal,
        AccountPasskeyRename command,
        CancellationToken cancellationToken = default);

    Task<AccountPasskeyResult> RemoveAsync(
        ClaimsPrincipal principal,
        string credentialId,
        CancellationToken cancellationToken = default);
}

/// <summary>
/// Canonical application boundary for the anonymous WebAuthn authentication
/// ceremony. The concrete identity engine remains an implementation detail.
/// </summary>
public interface IPasskeyAuthenticationService
{
    Task<PasskeyOptionsResult> CreateRequestOptionsAsync(
        string? username,
        CancellationToken cancellationToken = default);

    Task<PasskeyAuthenticationResult> SignInAsync(
        string? credentialJson,
        CancellationToken cancellationToken = default);
}
