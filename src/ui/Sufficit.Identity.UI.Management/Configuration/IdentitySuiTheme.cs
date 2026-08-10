using Sufficit.Blazor.UI.Themes;

namespace Sufficit.Identity.UI.Management.Configuration;

/// <summary>
/// Sufficit Identity Management theme for the SUI component library.
///
/// Maps the Management palette — red brand (<c>#cc0000</c>), Inter typography,
/// warm-neutral surfaces — onto the SUI <see cref="ISUITheme"/> contract so the
/// shared SUI components render with the Identity visual identity rather than
/// the library default (blue).
///
/// Tokens mirror <c>wwwroot/app.css</c> <c>:root</c>; the SUI variables emitted
/// by <c>SUIThemeProvider</c> take precedence over the SUI stylesheet defaults,
/// while the app's own <c>--brand</c>/<c>--ink</c>/<c>--surface-*</c> tokens
/// continue to drive the hand-rolled CSS that has not been migrated yet.
/// </summary>
public sealed class IdentitySUITheme : ISUITheme
{
    public SUIPalette Palette { get; } = new()
    {
        Primary = "#cc0000",
        PrimaryContrast = "#ffffff",
        PrimarySoft = "color-mix(in srgb, #cc0000 14%, transparent)",
        Secondary = "#626064",
        SecondaryContrast = "#ffffff",
        Info = "#175cd3",
        Success = "#157f3f",
        Warning = "#92540a",
        Error = "#b42318",
        Dark = "#242223",
        Light = "#f6f6f7",
        Surface = "#ffffff",
        Surface2 = "#f6f6f7",
        Surface3 = "#efeeef",
        TextPrimary = "#343132",
        TextSecondary = "#626064",
        TextDisabled = "#858287",
        Border = "#e2e1e3",
        BorderStrong = "#cfced1",
        Overlay = "rgba(34, 32, 33, .45)",
    };

    public SUITypography Typography { get; } = new()
    {
        FontFamily = "\"Inter\", -apple-system, BlinkMacSystemFont, \"Segoe UI\", Roboto, Helvetica, Arial, sans-serif",
        FontFamilyMono = "\"SFMono-Regular\", Consolas, \"Liberation Mono\", monospace",
    };

    public SUILayout Layout { get; } = new()
    {
        RadiusSm = "6px",
        Radius = "8px",
        RadiusLg = "12px",
        RadiusFull = "9999px",
        Shadow1 = "0 1px 2px rgba(34, 32, 33, .05)",
        Shadow2 = "0 4px 10px rgba(34, 32, 33, .08)",
        Shadow3 = "0 14px 34px rgba(34, 32, 33, .16)",
        Transition = "180ms cubic-bezier(.2, 0, 0, 1)",
        TransitionSlow = "280ms cubic-bezier(.2, 0, 0, 1)",
    };

    public bool IsDark => false;
}
