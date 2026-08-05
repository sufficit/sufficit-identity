namespace Sufficit.Identity.Application.Branding;

/// <summary>
/// Immutable presentation projection of the active identity-provider theme.
/// Persistence identity and timestamps deliberately stay inside the runtime.
/// </summary>
public sealed record BrandingTheme(
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

/// <summary>
/// Provides the runtime-owned active theme to presentation adapters.
/// </summary>
public interface IBrandingThemeProvider
{
    Task<BrandingTheme?> GetActiveAsync(
        CancellationToken cancellationToken = default);

    void Invalidate();
}

/// <summary>
/// Resolves a user's avatar URL without exposing theme persistence or template
/// substitution to a UI.
/// </summary>
public interface IUserAvatarUrlResolver
{
    Task<string?> ResolveAsync(
        string? userId,
        CancellationToken cancellationToken = default);
}
