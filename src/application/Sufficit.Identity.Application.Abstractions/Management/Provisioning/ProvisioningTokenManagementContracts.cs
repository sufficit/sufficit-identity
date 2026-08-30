using Sufficit.Identity.Management.Authorization;

namespace Sufficit.Identity.Management.Provisioning;

/// <summary>
/// A short-lived access token for a command-line provisioning operation.
/// The access-token value is returned only at issuance time.
/// </summary>
public sealed record ProvisioningTokenIssueResult(
    string AccessToken,
    string TokenType,
    DateTimeOffset ExpiresAtUtc,
    IReadOnlyList<string> Scopes,
    IReadOnlyList<string> Capabilities);

public sealed record ProvisioningTokenIssueRequest(int? LifetimeSeconds = null);

public interface IProvisioningTokenManagementService
{
    Task<ProvisioningTokenIssueResult> IssueAsync(
        ManagementRequestContext context,
        ProvisioningTokenIssueRequest? request = null,
        CancellationToken cancellationToken = default);
}
