using Sufficit.Identity.Management.Authorization;

namespace Sufficit.Identity.Management.Authorizations;

/// <summary>
/// Canonical application boundary for OpenID Connect/OAuth authorizations and
/// consents. Opaque payloads and token material never cross this boundary.
/// </summary>
public interface IAuthorizationManagementService
{
    Task<ManagementAuthorizationPage> SearchAsync(
        ManagementAuthorizationSearch query,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default);

    Task RevokeAsync(
        string id,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default);
}

public sealed record ManagementAuthorizationSearch(
    string? Search = null,
    string? UserId = null,
    string? ClientId = null,
    bool ActiveOnly = true,
    int Page = 1,
    int PageSize = 25);

public sealed record ManagementAuthorizationPage(
    IReadOnlyList<ManagementAuthorizationSummary> Items,
    int Page,
    int PageSize,
    int TotalCount,
    string? UserId,
    string? ClientId,
    bool ActiveOnly);

public sealed record ManagementAuthorizationSummary(
    string Id,
    string? UserId,
    string? UserName,
    string? Email,
    string? ClientId,
    string? ClientDisplayName,
    string Type,
    string Status,
    DateTimeOffset? CreatedAt,
    IReadOnlyList<string> Scopes,
    int CredentialCount,
    bool IsActive);
