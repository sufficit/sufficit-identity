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
}
