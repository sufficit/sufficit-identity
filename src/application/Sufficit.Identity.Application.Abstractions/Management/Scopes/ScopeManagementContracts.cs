using Sufficit.Identity.Management.Authorization;
using Sufficit.Identity.Application.Security;

namespace Sufficit.Identity.Management.Scopes;

/// <summary>
/// Canonical application boundary for custom OAuth scope definitions stored by
/// OpenIddict. Protocol scopes remain built-in and are not duplicated here.
/// </summary>
public interface IScopeManagementService
{
    Task<ManagementAudienceInventory> ListAudiencesAsync(
        ManagementRequestContext context,
        CancellationToken cancellationToken = default);

    Task<ManagementScopeDetail> UpdateAudienceBindingAsync(
        string scopeId,
        UpdateAudienceBindingCommand command,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default);

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

/// <summary>Audience inventory derived from the canonical scope resource registry.</summary>
public sealed record ManagementAudienceInventory(
    IReadOnlyList<ManagementAudienceSummary> Audiences,
    IReadOnlyList<ManagementScopeDetail> Scopes);

public sealed record ManagementAudienceSummary(
    string Name,
    IReadOnlyList<ManagementScopeDetail> Scopes,
    IReadOnlyList<string> ClientIds);

/// <summary>
/// Changes one binding, never a global audience rename. ExpectedResources prevents
/// an older UI snapshot from overwriting concurrent resource changes.
/// </summary>
public sealed record UpdateAudienceBindingCommand(
    string Audience,
    bool Assigned,
    IReadOnlyList<string> ExpectedResources);
