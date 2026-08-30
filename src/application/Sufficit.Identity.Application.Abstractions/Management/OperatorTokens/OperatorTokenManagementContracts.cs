using Sufficit.Identity.Management.Authorization;

namespace Sufficit.Identity.Management.OperatorTokens;

/// <summary>
/// Metadata for a short-lived Management bearer. The reference-token value is
/// deliberately absent and is returned only once by the issuance result.
/// </summary>
public sealed record OperatorTokenSummary(
    string Id,
    string Purpose,
    DateTimeOffset CreatedAtUtc,
    DateTimeOffset ExpiresAtUtc,
    string Status,
    IReadOnlyList<string> Capabilities);

public sealed record OperatorTokenWorkspace(
    bool IssuanceEnabled,
    bool MfaRequired,
    bool MfaSatisfied,
    int DefaultLifetimeSeconds,
    int MaximumLifetimeSeconds,
    int MaximumCapabilities,
    IReadOnlyList<string> AvailableCapabilities,
    IReadOnlyList<OperatorTokenSummary> ActiveTokens);

public sealed record IssueOperatorTokenCommand(
    string Purpose,
    int? LifetimeSeconds,
    IReadOnlyList<string> Capabilities);

public sealed record OperatorTokenIssueResult(
    string AccessToken,
    string TokenType,
    DateTimeOffset ExpiresAtUtc,
    IReadOnlyList<string> Scopes,
    IReadOnlyList<string> Capabilities,
    OperatorTokenSummary Token);

public interface IOperatorTokenManagementService
{
    Task<OperatorTokenWorkspace> GetWorkspaceAsync(
        ManagementRequestContext context,
        CancellationToken cancellationToken = default);

    Task<OperatorTokenIssueResult> IssueAsync(
        IssueOperatorTokenCommand command,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default);

    Task RevokeAsync(
        string id,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default);
}
