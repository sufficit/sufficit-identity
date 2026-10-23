using System.Security.Cryptography;
using System.Text;
using Sufficit.Identity.Application.Branding;

namespace Sufficit.Identity.UI.Services;

/// <summary>
/// The active theme's colors and background as a stylesheet served from
/// <see cref="Path"/>, instead of inline <c>&lt;style&gt;</c> blocks in the
/// page head. An inline block needs the response's CSP nonce, and enhanced
/// navigation merges the next page's head — carrying another response's nonce —
/// into a document whose policy only knows the first one, so the browser
/// blocked it on every navigation. A same-origin stylesheet is allowed by
/// <c>style-src 'self'</c> on every page.
/// </summary>
/// <remarks>
/// The values come from <see cref="BrandingTheme"/>, which already admits only
/// <c>#rrggbb</c> colors and URLs without quote, parenthesis or backslash.
/// </remarks>
public static class BrandingStylesheet
{
    public const string Path = "/branding/theme.css";

    /// <summary>The stylesheet for <paramref name="theme"/>, or empty when it changes nothing.</summary>
    public static string Build(BrandingTheme? theme)
    {
        if (theme is null)
        {
            return string.Empty;
        }

        var css = new StringBuilder();
        if (!string.IsNullOrEmpty(theme.BrandColor))
        {
            css.Append(":root{--brand:").Append(theme.BrandColor)
                .Append(";--brand-ring:").Append(theme.BrandColor).Append("40;");
            if (!string.IsNullOrEmpty(theme.BrandHoverColor))
            {
                css.Append("--brand-hover:").Append(theme.BrandHoverColor).Append(';');
            }

            if (!string.IsNullOrEmpty(theme.BrandSoftColor))
            {
                css.Append("--brand-soft:").Append(theme.BrandSoftColor).Append(';');
            }

            css.Append("}\n");
        }

        if (!string.IsNullOrEmpty(theme.BackgroundImageUrl))
        {
            css.Append("body{background:linear-gradient(rgba(255,255,255,.15),rgba(255,255,255,.15)),url(\"")
                .Append(theme.BackgroundImageUrl)
                .Append("\") center/cover fixed no-repeat !important;}\n");
        }

        return css.ToString();
    }

    /// <summary>Content version for the link's query string, so a theme change is never served from cache.</summary>
    public static string Version(string css) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(css)))[..16];
}
