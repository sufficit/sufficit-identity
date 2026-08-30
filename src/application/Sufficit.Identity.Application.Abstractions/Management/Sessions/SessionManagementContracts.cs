using Sufficit.Identity.Management.Authorization;

namespace Sufficit.Identity.Management.Sessions;

/// <summary>
/// Canonical application boundary for provider-issued credentials. OpenIddict
/// remains the source of truth; no parallel browser-session store is created.
/// </summary>
public interface ISessionManagementService
{
    Task<ManagementSessionPage> SearchAsync(
        ManagementSessionSearch query,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default);

    Task RevokeAsync(
        string id,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default);

    Task<ManagementUserSessionRevocation> RevokeAllForUserAsync(
        string userId,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default);
}

public sealed record ManagementSessionSearch(
    string? Search = null,
    string? UserId = null,
    string? ClientId = null,
    bool ActiveOnly = true,
    int Page = 1,
    int PageSize = 25);

public sealed record ManagementSessionPage(
    IReadOnlyList<ManagementSessionSummary> Items,
    int Page,
    int PageSize,
    int TotalCount,
    string? UserId,
    string? ClientId,
    bool ActiveOnly);

public sealed record ManagementSessionSummary(
    string Id,
    string? UserId,
    string? UserName,
    string? Email,
    string? ClientId,
    string? ClientDisplayName,
    string? AuthorizationId,
    string Type,
    string Status,
    DateTimeOffset? CreatedAt,
    DateTimeOffset? ExpiresAt,
    DateTimeOffset? RedeemedAt,
    bool IsActive,
    // client_credentials tokens use the client as subject, not an Identity
    // user. Keep the application primary key for management navigation.
    string? ClientApplicationId = null);

public sealed record ManagementUserSessionRevocation(
    long RevokedTokens,
    long RevokedAuthorizations,
    long RevokedBrowserSessions);
