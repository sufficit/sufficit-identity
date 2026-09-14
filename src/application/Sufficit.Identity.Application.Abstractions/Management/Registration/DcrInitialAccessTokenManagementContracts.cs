using Sufficit.Identity.Management.Authorization;

namespace Sufficit.Identity.Management.Registration;

public sealed record DcrInitialAccessTokenSummary(
    Guid Id,
    string Label,
    string TokenHint,
    string IssuedBy,
    DateTime CreatedAtUtc,
    DateTime ExpiresAtUtc,
    bool SingleUse,
    int RegistrationCount,
    DateTime? LastUsedAtUtc,
    DateTime? RevokedAtUtc,
    string Status,
    IReadOnlyList<string>? AllowedGrantTypes = null,
    IReadOnlyList<string>? AllowedScopes = null);

/// <param name="Label">Who the token is for; required, shown in listings and audit.</param>
/// <param name="LifetimeHours">Default 24, at most 720.</param>
/// <param name="SingleUse">Default true: the token registers one client.</param>
/// <param name="AllowedGrantTypes">Optional subset of the server-wide DCR grant
/// types a registration with this token may request. Empty: no per-token limit.</param>
/// <param name="AllowedScopes">Optional subset of scopes, as above.</param>
public sealed record IssueDcrInitialAccessTokenCommand(
    string? Label,
    int? LifetimeHours = null,
    bool? SingleUse = null,
    IReadOnlyList<string>? AllowedGrantTypes = null,
    IReadOnlyList<string>? AllowedScopes = null);

/// <summary>The token value is returned only here, once.</summary>
public sealed record DcrInitialAccessTokenIssueResult(
    DcrInitialAccessTokenSummary Token,
    string InitialAccessToken);

public interface IDcrInitialAccessTokenManagementService
{
    Task<IReadOnlyList<DcrInitialAccessTokenSummary>> ListAsync(
        ManagementRequestContext context,
        CancellationToken cancellationToken = default);

    Task<DcrInitialAccessTokenIssueResult> IssueAsync(
        IssueDcrInitialAccessTokenCommand command,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default);

    Task RevokeAsync(
        Guid id,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default);
}
