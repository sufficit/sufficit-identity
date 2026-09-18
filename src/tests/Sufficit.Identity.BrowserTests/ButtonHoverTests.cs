using Microsoft.Playwright;
using Microsoft.Playwright.NUnit;
using NUnit.Framework;

namespace Sufficit.Identity.BrowserTests;

/// <summary>
/// SUIButton renders an anchor when it is given an Href, which puts every
/// button on these pages inside the stylesheet's own rule for links. A button
/// is not a link: it must not gain an underline on hover, and it must not
/// move — the only movement here is the press.
///
/// Both had regressed when the provider buttons moved onto .sui-btn and the
/// explicit text-decoration was lost with the old rules.
/// </summary>
[Parallelizable(ParallelScope.None)]
public class ButtonHoverTests : PageTest
{
    private static readonly string[] AnchorButtons =
    [
        "sui-btn sui-btn--filled sui-btn--color-primary sui-btn--medium",
        "sui-btn sui-btn--outlined sui-btn--color-default sui-btn--medium btn-external",
        "sui-btn sui-btn--outlined sui-btn--color-default sui-btn--medium btn-google",
        "sui-btn sui-btn--outlined sui-btn--color-default sui-btn--medium btn-facebook",
        "sui-btn sui-btn--outlined sui-btn--color-default sui-btn--medium btn-passkey",
    ];

    [Test]
    public async Task No_button_gains_a_link_underline_or_moves_when_hovered()
    {
        await GivenAnchorButtonsAsync();

        for (var index = 0; index < AnchorButtons.Length; index++)
        {
            var selector = $"#anchor-{index}";
            await Page.HoverAsync(selector);

            var decoration = await Page.EvaluateAsync<string>(
                "s => getComputedStyle(document.querySelector(s)).textDecorationLine", selector);
            var transform = await Page.EvaluateAsync<string>(
                "s => getComputedStyle(document.querySelector(s)).transform", selector);

            Assert.That(decoration, Is.EqualTo("none"), $"{AnchorButtons[index]} underlines on hover.");
            Assert.That(transform, Is.EqualTo("none"), $"{AnchorButtons[index]} moves on hover.");

            await Page.Mouse.MoveAsync(0, 0);
        }
    }

    [Test]
    public async Task A_plain_link_still_underlines_on_hover()
    {
        // The rule above must not silence the page's ordinary links: "forgot
        // your password" and its neighbours rely on it.
        await GivenAnchorButtonsAsync();
        await Page.HoverAsync("#plain-link");

        var decoration = await Page.EvaluateAsync<string>(
            "() => getComputedStyle(document.querySelector('#plain-link')).textDecorationLine");

        Assert.That(decoration, Is.EqualTo("underline"));
    }

    private async Task GivenAnchorButtonsAsync()
    {
        var css = await File.ReadAllTextAsync(Path.Combine(
            ResolvePublicUiSource(), "wwwroot", "css", "site.css"));

        var anchors = string.Join("\n", AnchorButtons.Select((cls, index) =>
            $"""<a id="anchor-{index}" href="/" class="{cls}"><span class="sui-btn__label">Entrar</span></a>"""));

        await Page.SetContentAsync($$"""
            <!DOCTYPE html>
            <html><head><style>{{css}}</style></head>
            <body><div class="page identity-public"><div class="auth-card">
              {{anchors}}
              <a id="plain-link" href="/account/forgotpassword">Esqueceu a senha?</a>
            </div></div></body></html>
            """);
    }

    private static string ResolvePublicUiSource()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null
            && !Directory.Exists(Path.Combine(
                directory.FullName, "src", "ui", "Sufficit.Identity.UI")))
        {
            directory = directory.Parent;
        }

        Assert.That(directory, Is.Not.Null, "Repository root not found.");
        return Path.Combine(directory!.FullName, "src", "ui", "Sufficit.Identity.UI");
    }
}
