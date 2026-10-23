using Sufficit.Identity.Application.Branding;
using Sufficit.Identity.UI.Services;
using Xunit;

namespace Sufficit.Identity.Tests;

public sealed class BrandingStylesheetTests
{
    private static BrandingTheme Theme(string? brand = "#123abc", string? background = null) =>
        new("t", null, null, null, background, brand, "#0a0b0c", "#fdfeff", null, null, null, null, null);

    [Fact]
    public void Colors_and_background_become_a_stylesheet()
    {
        var css = BrandingStylesheet.Build(Theme(background: "https://cdn.example/bg.jpg"));

        Assert.Contains("--brand:#123abc;", css, StringComparison.Ordinal);
        Assert.Contains("--brand-ring:#123abc40;", css, StringComparison.Ordinal);
        Assert.Contains("--brand-hover:#0a0b0c;", css, StringComparison.Ordinal);
        Assert.Contains("--brand-soft:#fdfeff;", css, StringComparison.Ordinal);
        Assert.Contains("url(\"https://cdn.example/bg.jpg\")", css, StringComparison.Ordinal);
    }

    [Fact]
    public void Nothing_to_serve_without_a_theme_or_with_unsafe_values()
    {
        Assert.Equal(string.Empty, BrandingStylesheet.Build(null));
        // The theme record drops what is not #rrggbb or a quote-free https URL.
        Assert.Equal(string.Empty, BrandingStylesheet.Build(Theme(brand: "red;}body{x:y", background: "https://x/\")}")));
    }

    [Fact]
    public void The_version_follows_the_content()
    {
        var css = BrandingStylesheet.Build(Theme());

        Assert.Equal(BrandingStylesheet.Version(css), BrandingStylesheet.Version(css));
        Assert.NotEqual(BrandingStylesheet.Version(css), BrandingStylesheet.Version(BrandingStylesheet.Build(Theme(brand: "#000000"))));
    }
}
