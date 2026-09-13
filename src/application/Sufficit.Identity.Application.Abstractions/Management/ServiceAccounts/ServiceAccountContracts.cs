using Sufficit.Identity.Management.Authorization;

// The CONTRACTS compile only in this project (Application.Abstractions, which
// the UI references), and the implementation only in Management. This
// exclusivity is mandatory: without it, the same record would exist in both
// assemblies, and whoever references both — the tests — dies with CS0433.
//
// This used to be guaranteed by #if APPLICATION_CONTRACTS; today it's the file
// boundary, which is easier to violate by accident. When moving a type between
// the two projects, move it — don't copy it.

namespace Sufficit.Identity.Management.ServiceAccounts;

/// <summary>
/// A system account: an OAuth client that authenticates on its own
/// (<c>client_credentials</c>) and receives management capabilities through
/// ROLES declared on its own registration — the <c>identity:client:roles</c>
/// property that <see cref="ServicePrincipalEntitlementResolver"/> reads.
/// </summary>
/// <param name="Roles">The roles declared on the client registration.</param>
/// <param name="Capabilities">
/// What those roles MEAN in this deployment, already resolved by the same map
/// the evaluator uses. The UI shows both because the operator's question is
/// never "what roles does it have?" — it's "what can this account actually do?".
/// </param>
public sealed record ServiceAccountSummary(
    string ClientId,
    string? DisplayName,
    bool CanRequestTokens,
    IReadOnlyList<string> Roles,
    IReadOnlyList<string> Capabilities);

/// <summary>The roles this deployment recognizes, with their meaning.</summary>
public sealed record ServiceAccountRoleOption(
    string Role,
    IReadOnlyList<string> Capabilities,
    bool IsFullAdministrator);

public sealed record ServiceAccountWorkspace(
    IReadOnlyList<ServiceAccountSummary> Accounts,
    IReadOnlyList<ServiceAccountRoleOption> KnownRoles);

public sealed record SetServiceAccountRolesCommand(IReadOnlyList<string>? Roles);

/// <summary>
/// Creates a system account: a confidential client that authenticates on its
/// own (<c>client_credentials</c>) and receives capabilities through its
/// declared roles.
/// </summary>
/// <param name="ClientSecret">
/// Optional. If absent, the server generates a strong secret — the recommended
/// path, because a human-chosen secret is the weak link of a credential that
/// never expires on its own.
/// </param>
public sealed record CreateServiceAccountCommand(
    string ClientId,
    string? DisplayName = null,
    IReadOnlyList<string>? Roles = null,
    string? ClientSecret = null);

/// <summary>
/// The newly created account and the secret, returned EXACTLY ONCE.
/// </summary>
/// <remarks>
/// The secret is persisted only as a hash, so there is no way to display it
/// again later: whoever doesn't copy it now must rotate it. The UI treats this
/// as an explicit step rather than a detail of the response.
/// </remarks>
public sealed record ServiceAccountCreated(
    ServiceAccountSummary Account,
    string ClientSecret);

public interface IServiceAccountManagementService
{
    Task<ServiceAccountWorkspace> GetWorkspaceAsync(
        ManagementRequestContext context,
        CancellationToken cancellationToken = default);

    Task<ServiceAccountSummary> SetRolesAsync(
        string clientId,
        SetServiceAccountRolesCommand command,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default);

    Task<ServiceAccountCreated> CreateAsync(
        CreateServiceAccountCommand command,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default);
}
