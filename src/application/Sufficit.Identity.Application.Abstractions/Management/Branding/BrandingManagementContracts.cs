using Sufficit.Identity.Management.Authorization;

namespace Sufficit.Identity.Management.Branding;

/// <summary>
/// Canonical application boundary for identity branding administration.
/// Embedded UI and HTTP controllers are adapters over this contract.
/// </summary>
public interface IBrandingManagementService
{
    Task<IReadOnlyList<ManagementBrandingTheme>> ListAsync(
        ManagementRequestContext context,
        CancellationToken cancellationToken = default);

    Task<ManagementBrandingTheme?> GetActiveAsync(
        ManagementRequestContext context,
        CancellationToken cancellationToken = default);

    Task<ManagementBrandingTheme> GetAsync(
        int id,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default);

    Task<ManagementBrandingTheme> CreateAsync(
        SaveManagementBrandingThemeCommand command,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default);

    Task<ManagementBrandingTheme> UpdateAsync(
        int id,
        SaveManagementBrandingThemeCommand command,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default);

    Task<ManagementBrandingTheme> ActivateAsync(
        int id,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default);

    Task DeleteAsync(
        int id,
        ManagementRequestContext context,
        CancellationToken cancellationToken = default);
}

public sealed record ManagementBrandingTheme(
    int Id,
    string Name,
    bool IsActive,
    string? LogoUrl,
    string? FaviconUrl,
    string? HeaderIconUrl,
    string? BackgroundImageUrl,
    string? BrandColor,
    string? BrandHoverColor,
    string? BrandSoftColor,
    string? ThemeColor,
    string? Title,
    string? BrandName,
    string? BrandSubtitle,
    string? AvatarUrlTemplate,
    DateTime CreatedAt,
    DateTime UpdatedAt);

public sealed record SaveManagementBrandingThemeCommand(
    string Name,
    string? LogoUrl,
    string? FaviconUrl,
    string? HeaderIconUrl,
    string? BackgroundImageUrl,
    string? BrandColor,
    string? BrandHoverColor,
    string? BrandSoftColor,
    string? ThemeColor,
    string? Title,
    string? BrandName,
    string? BrandSubtitle,
    string? AvatarUrlTemplate);
