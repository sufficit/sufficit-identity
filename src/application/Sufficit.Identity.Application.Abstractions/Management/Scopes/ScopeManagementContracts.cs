using Sufficit.Identity.Management.Authorization;
using Sufficit.Identity.Application.Security;

namespace Sufficit.Identity.Management.Scopes;

/// <summary>
/// Canonical application boundary for custom OAuth scope definitions stored by
/// OpenIddict. Protocol scopes remain built-in and are not duplicated here.
/// </summary>
public interface IScopeManagementService
{
    Task<IReadOnlyList<ManagementScopeSummary>> ListAsync(
        ManagementRequestContext context,
        CancellationToken cancellationToken = default);

    Task<ManagementScopeDetail> GetAsync(
        string id,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default);

    Task<ManagementScopeDetail> CreateAsync(
        CreateManagementScopeCommand command,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default);

    Task<ManagementScopeDetail> UpdateAsync(
        string id,
        UpdateManagementScopeCommand command,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default);

    Task DeleteAsync(
        string id,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default);
}

public sealed record ManagementScopeSummary(
    string Id,
    string Name,
    string? DisplayName,
    string? Description,
    int ResourceCount,
    int ClientCount,
    bool IsManifestManaged);

public sealed record ManagementScopeDetail(
    string Id,
    string Name,
    string? DisplayName,
    string? Description,
    IReadOnlyList<string> Resources,
    IReadOnlyList<string> ClientIds,
    bool IsManifestManaged);

public sealed record CreateManagementScopeCommand(
    string Name,
    string? DisplayName,
    string? Description,
    IReadOnlyList<string> Resources);

public sealed record UpdateManagementScopeCommand(
    string? DisplayName,
    string? Description,
    IReadOnlyList<string> Resources);
