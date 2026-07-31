using System.Security.Claims;

namespace Sufficit.Identity.Core.Services;

public sealed record AccountExternalIdentity(
    string LoginProvider,
    string ProviderKey,
    string DisplayName,
    bool CanRemove,
    string? RemovalBlockedReason);

public sealed record AccountExternalProvider(
    string AuthenticationScheme,
    string DisplayName);

public sealed record AccountExternalIdentityOverview(
    IReadOnlyList<AccountExternalIdentity> LinkedIdentities,
    IReadOnlyList<AccountExternalProvider> AvailableProviders);

public sealed record AccountExternalIdentityLink(
    string LoginProvider,
    string ProviderKey,
    string? ProviderDisplayName);

/// <summary>
/// Canonical application boundary for external identities owned by the
/// authenticated account. Contracts use provider-neutral identity concepts;
/// ASP.NET Identity is an implementation detail of the current adapter.
/// </summary>
public interface IAccountExternalIdentityService
{
    Task<AccountExternalIdentityOverview?> GetOverviewAsync(
        ClaimsPrincipal principal,
        CancellationToken cancellationToken = default);

    Task<AccountSelfServiceResult> LinkAsync(
        ClaimsPrincipal principal,
        AccountExternalIdentityLink command,
        CancellationToken cancellationToken = default);

    Task<AccountSelfServiceResult> RemoveAsync(
        ClaimsPrincipal principal,
        string loginProvider,
        string providerKey,
        CancellationToken cancellationToken = default);
}
