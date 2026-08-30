using Sufficit.Identity.Management.Authorization;

namespace Sufficit.Identity.Management.Claims;

/// <summary>
/// Canonical application boundary for custom claims assigned to identity
/// accounts. The embedded UI and HTTP API are adapters over this service.
/// </summary>
public interface IClaimManagementService
{
    Task<ManagementClaimMetadata> GetMetadataAsync(
        ManagementRequestContext context,
        CancellationToken cancellationToken = default);

    Task<ManagementClaimPage> SearchAsync(
        ManagementClaimSearch query,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default);

    Task<ManagementClaimAssignment> GetAsync(
        int id,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default);

    Task<ManagementClaimAssignment> CreateAsync(
        CreateManagementClaimCommand command,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default);

    Task<ManagementClaimAssignment> UpdateAsync(
        int id,
        UpdateManagementClaimCommand command,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default);

    Task DeleteAsync(
        int id,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default);
}

public sealed record ManagementClaimMetadata(
    IReadOnlyList<string> SuggestedTypes,
    int TypeMaxLength,
    int ValueMaxLength);

public sealed record ManagementClaimSearch(
    string? Search = null,
    string? UserId = null,
    int Page = 1,
    int PageSize = 25);

public sealed record ManagementClaimPage(
    IReadOnlyList<ManagementClaimAssignment> Items,
    int Page,
    int PageSize,
    int TotalCount,
    string? UserId);

public sealed record ManagementClaimAssignment(
    int Id,
    string UserId,
    string? UserName,
    string? Email,
    string Type,
    string Value);

public sealed record CreateManagementClaimCommand(
    string UserId,
    string Type,
    string Value);

public sealed record UpdateManagementClaimCommand(
    string Type,
    string Value);
