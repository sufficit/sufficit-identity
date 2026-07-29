namespace Sufficit.Identity.Core.Entities;

/// <summary>
/// Branding/theme configuration for the Sufficit Identity UI.
/// Stored in the <c>brandingthemes</c> table. Only one record should have
/// <see cref="IsActive"/> = true at a time (enforced by the management API
/// activate endpoint). The active theme is cached in memory by
/// <c>BrandingThemeProvider</c> and consumed by the UI to override the
/// hardcoded defaults in site.css and App.razor.
/// </summary>
public sealed class BrandingTheme
{
    public int Id { get; set; }

    /// <summary>Human-readable name for this theme (e.g. "Sufficit padrão").</summary>
    public string Name { get; set; } = string.Empty;

    /// <summary>Only one theme should be active at a time.</summary>
    public bool IsActive { get; set; }

    // --- Visual assets (relative paths like _content/Sufficit.Identity.UI/img/logo.png) ---

    /// <summary>Full logo shown on login/register/home cards. Null = use default.</summary>
    public string? LogoUrl { get; set; }

    /// <summary>Favicon for the browser tab. Null = use default.</summary>
    public string? FaviconUrl { get; set; }

    /// <summary>Icon shown in the topbar header. Null = use default.</summary>
    public string? HeaderIconUrl { get; set; }

    /// <summary>Login page background image. Null = use default.</summary>
    public string? BackgroundImageUrl { get; set; }

    // --- Colors (hex format like #cc0000) ---

    public string? BrandColor { get; set; }
    public string? BrandHoverColor { get; set; }
    public string? BrandSoftColor { get; set; }

    /// <summary>Browser theme-color meta tag. Null = use default.</summary>
    public string? ThemeColor { get; set; }

    // --- Identity text ---

    /// <summary>Browser tab title (e.g. "Sufficit Identity"). Null = use default.</summary>
    public string? Title { get; set; }

    /// <summary>Topbar brand name (e.g. "Sufficit"). Null = use default.</summary>
    public string? BrandName { get; set; }

    /// <summary>Topbar brand subtitle (e.g. "Identity"). Null = use default.</summary>
    public string? BrandSubtitle { get; set; }

    /// <summary>
    /// URL template for user avatars in the management area. The placeholder
    /// <c>{userid}</c> is replaced with the user's subject claim at render
    /// time. Example: <c>https://endpoints.sufficit.com.br/contact/avatar?contextid={userid}</c>.
    /// Null = show initials instead.
    /// </summary>
    public string? AvatarUrlTemplate { get; set; }

    // --- Timestamps ---

    public DateTime CreatedAt { get; set; }
    public DateTime UpdatedAt { get; set; }
}
