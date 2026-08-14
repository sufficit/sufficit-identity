using Sufficit.Identity.Application.Branding;
using Xunit;

namespace Sufficit.Identity.Tests;

/// <summary>
/// Render-safety contract of <see cref="BrandingTheme"/> (eval 2026-08-14,
/// finding F-1 / improvement A1): instances must be safe to render no matter
/// which construction path produced them — the sanitizing provider, a test
/// stub, or any future caller — because validation happens inside the record
/// constructor itself. A hostile brandingthemes row (written by a direct DB
/// edit, bypassing management-API validation) must degrade to null/default
/// instead of reaching a public page's style block or an attribute.
/// </summary>
public sealed class BrandingThemeSanitizationTests
{
    [Theory]
    [InlineData("#CC0000")]
    [InlineData("#cc0000")]
    [InlineData("#AbCdEf")]
    public void Valid_hex_colors_are_preserved(string color)
    {
        var theme = Theme(brandColor: color, themeColor: color);

        Assert.Equal(color, theme.BrandColor);
        Assert.Equal(color, theme.ThemeColor);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("red")]
    [InlineData("rgb(1,2,3)")]
    [InlineData("#fff")]
    [InlineData("#GGGGGG")]
    [InlineData("#12345")]
    [InlineData("#1234567")]
    [InlineData("#cc0000; background: url(https://evil.example/x)")]
    [InlineData("#cc0000}")]
    public void Invalid_colors_become_null(string? color)
    {
        var theme = Theme(brandColor: color, brandHoverColor: color,
            brandSoftColor: color, themeColor: color);

        Assert.Null(theme.BrandColor);
        Assert.Null(theme.BrandHoverColor);
        Assert.Null(theme.BrandSoftColor);
        Assert.Null(theme.ThemeColor);
    }

    [Theory]
    [InlineData("https://cdn.example.com/logo.png")]
    [InlineData("http://intranet.example.com/logo.png")]
    [InlineData("/static/logo.png")]
    public void Safe_attribute_urls_are_preserved(string url)
    {
        var theme = Theme(logoUrl: url, faviconUrl: url, headerIconUrl: url);

        Assert.Equal(url, theme.LogoUrl);
        Assert.Equal(url, theme.FaviconUrl);
        Assert.Equal(url, theme.HeaderIconUrl);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("javascript:alert(1)")]
    [InlineData("JaVaScRiPt:alert(1)")]
    [InlineData("data:image/svg+xml;base64,PHN2ZyB4bWxucz0iL3Mz")] // no onclick needed
    [InlineData("vbscript:msgbox")]
    [InlineData("//evil.example.com/logo.png")]
    [InlineData("https://x/\\\")'), url(https://evil.example/x)")]
    [InlineData("https://ok.example/a<b")]
    [InlineData("https://ok.example/\u0007")]
    [InlineData("relative/path.png")]
    [InlineData("#fragment-only")]
    public void Unsafe_attribute_urls_become_null(string? url)
    {
        var theme = Theme(logoUrl: url, faviconUrl: url, headerIconUrl: url);

        Assert.Null(theme.LogoUrl);
        Assert.Null(theme.FaviconUrl);
        Assert.Null(theme.HeaderIconUrl);
    }

    [Fact]
    public void Css_background_url_allows_https_and_root_relative_only()
    {
        // CSS url() contexts get no HTML-encoding help, so plain-http absolute
        // URLs are rejected there (matches the pre-A1 provider behavior).
        Assert.Equal("https://bg.example.com/x.jpg",
            Theme(backgroundImageUrl: "https://bg.example.com/x.jpg").BackgroundImageUrl);
        Assert.Equal("/images/bg.jpg",
            Theme(backgroundImageUrl: "/images/bg.jpg").BackgroundImageUrl);

        Assert.Null(Theme(backgroundImageUrl: "http://bg.example.com/x.jpg").BackgroundImageUrl);
        Assert.Null(Theme(backgroundImageUrl: "//bg.example.com/x.jpg").BackgroundImageUrl);
        Assert.Null(Theme(
            backgroundImageUrl: "https://bg.example.com/x.jpg\"); background-image: url(https://evil.example/x)")
            .BackgroundImageUrl);
    }

    [Fact]
    public void Avatar_url_template_is_not_sanitized()
    {
        // The template is consumed by IUserAvatarUrlResolver, which validates
        // it and URL-escapes the substituted user id — braces must survive.
        const string template = "https://endpoints.example/avatar?u={userid}";

        Assert.Equal(template, Theme(avatarUrlTemplate: template).AvatarUrlTemplate);
    }

    [Fact]
    public void Text_fields_pass_through()
    {
        // Text fields render as Razor text nodes (HTML-encoded), not as CSS or
        // attributes, so they are intentionally not rewritten here.
        var theme = Theme(name: "Corporate", title: "Corporate <Login>",
            brandName: "Corp", brandSubtitle: "Sufficit & Co");

        Assert.Equal("Corporate", theme.Name);
        Assert.Equal("Corporate <Login>", theme.Title);
        Assert.Equal("Corp", theme.BrandName);
        Assert.Equal("Sufficit & Co", theme.BrandSubtitle);
    }

    [Fact]
    public void Sanitization_is_deterministic_for_value_equality()
    {
        // Records synthesized equality must not be broken by the sanitizing
        // constructor: identical raw inputs stay Equal. Hex case is preserved
        // (CSS is case-insensitive for colors, but the operator-entered text
        // is not rewritten), so case variants remain distinct values.
        Assert.Equal(
            Theme(brandColor: "#cc0000"),
            Theme(brandColor: "#cc0000"));

        Assert.NotEqual(
            Theme(brandColor: "red"),
            Theme(brandColor: "#cc0000"));
    }

    private static BrandingTheme Theme(
        string name = "Test",
        string? logoUrl = null,
        string? faviconUrl = null,
        string? headerIconUrl = null,
        string? backgroundImageUrl = null,
        string? brandColor = null,
        string? brandHoverColor = null,
        string? brandSoftColor = null,
        string? themeColor = null,
        string? title = null,
        string? brandName = null,
        string? brandSubtitle = null,
        string? avatarUrlTemplate = null) =>
        new(name, logoUrl, faviconUrl, headerIconUrl, backgroundImageUrl,
            brandColor, brandHoverColor, brandSoftColor, themeColor,
            title, brandName, brandSubtitle, avatarUrlTemplate);
}
