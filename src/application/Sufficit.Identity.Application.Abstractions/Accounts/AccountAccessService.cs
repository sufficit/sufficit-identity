using System.Security.Claims;

namespace Sufficit.Identity.Application.Accounts;

/// <summary>
/// Application authorized by the authenticated account. Multiple OpenIddict
/// authorizations for the same client are intentionally projected as one item.
/// </summary>
public sealed record AccountConnectedApplication(
    string ApplicationId,
    string? ClientId,
    string DisplayName,
    DateTimeOffset? AuthorizedAt,
    IReadOnlyList<string> Scopes,
    int AuthorizationCount,
    int ActiveCredentialCount);

/// <summary>
/// Active credential issued by the provider for the authenticated account.
/// Token payloads and reference identifiers never cross this boundary.
/// </summary>
public sealed record AccountSessionCredential(
    string Id,
    string? ClientId,
    string DisplayName,
    string Type,
    DateTimeOffset? CreatedAt,
    DateTimeOffset? ExpiresAt);

/// <summary>
/// Credential another application delegated to a device on behalf of the
/// authenticated account (RFC 8693 token exchange bound to the device's DPoP
/// key). <see cref="Label"/> is the device identifier chosen by the
/// delegating application; the credential itself never crosses this boundary.
/// </summary>
public sealed record AccountDelegatedCredential(
    string Id,
    string? ClientId,
    string DisplayName,
    string Label,
    string? DelegatorClientId,
    DateTimeOffset? CreatedAt,
    DateTimeOffset ExpiresAt);

/// <summary>
/// Canonical application boundary for OAuth/OIDC access owned by the current
/// account. UI and future HTTP adapters share these methods and never access
/// OpenIddict stores or mutable entities directly.
/// </summary>
public interface IAccountAccessService
{
    Task<IReadOnlyList<AccountConnectedApplication>>
        GetConnectedApplicationsAsync(
            ClaimsPrincipal principal,
            CancellationToken cancellationToken = default);

    Task<IReadOnlyList<AccountSessionCredential>> GetSessionsAsync(
        ClaimsPrincipal principal,
        CancellationToken cancellationToken = default);

    Task<AccountSelfServiceResult> RevokeConnectedApplicationAsync(
        ClaimsPrincipal principal,
        string applicationId,
        CancellationToken cancellationToken = default);

    Task<AccountSelfServiceResult> RevokeSessionAsync(
        ClaimsPrincipal principal,
        string sessionId,
        CancellationToken cancellationToken = default);

    Task<AccountSelfServiceResult> RevokeAllSessionsAsync(
        ClaimsPrincipal principal,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Active delegated device credentials of the account. The default
    /// implementation keeps hosts without the feature source-compatible.
    /// </summary>
    Task<IReadOnlyList<AccountDelegatedCredential>> GetDelegatedCredentialsAsync(
        ClaimsPrincipal principal,
        CancellationToken cancellationToken = default) =>
        Task.FromResult<IReadOnlyList<AccountDelegatedCredential>>([]);

    /// <summary>Revokes one delegated device credential of the account.</summary>
    Task<AccountSelfServiceResult> RevokeDelegatedCredentialAsync(
        ClaimsPrincipal principal,
        string credentialId,
        CancellationToken cancellationToken = default) =>
        Task.FromResult(AccountSelfServiceResult.Failure(
            "delegated-credential-not-found",
            "The delegated credential was not found."));
}
