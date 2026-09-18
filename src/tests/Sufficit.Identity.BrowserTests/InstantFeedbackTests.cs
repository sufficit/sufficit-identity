using Microsoft.Playwright;
using Microsoft.Playwright.NUnit;
using NUnit.Framework;

namespace Sufficit.Identity.BrowserTests;

/// <summary>
/// The passkey button has to answer the click in the browser: its handler runs
/// on the Blazor circuit and its first step opens the platform dialog, so
/// anything that waits for the server arrives too late to look like a reaction.
/// These run against the script and the stylesheet themselves — no server, no
/// authenticator — because what is being checked is exactly the part that does
/// not involve either.
/// </summary>
[Parallelizable(ParallelScope.None)]
public class InstantFeedbackTests : PageTest
{
    [Test]
    public async Task The_button_is_marked_busy_within_the_click_itself()
    {
        await GivenLoginLikeButtonAsync();

        // Observed from inside the click handler: whatever the browser does
        // afterwards, the mark is already there when the page's own listeners
        // run — which is what makes the press feel answered.
        var markedDuringClick = await Page.EvaluateAsync<bool>(@"
            () => new Promise(resolve => {
                const button = document.querySelector('.btn-passkey');
                button.addEventListener('click', () => {
                    resolve(button.classList.contains('is-busy'));
                }, { once: true });
                button.click();
            })");

        Assert.That(markedDuringClick, Is.True);
        await Expect(Page.Locator(".btn-passkey")).ToHaveAttributeAsync("aria-busy", "true");
    }

    [Test]
    public async Task The_busy_button_shows_a_spinner_and_stops_further_clicks()
    {
        await GivenLoginLikeButtonAsync();
        await Page.Locator(".btn-passkey").ClickAsync();

        var spinner = await Page.EvaluateAsync<string>(@"
            () => getComputedStyle(document.querySelector('.btn-passkey'), '::before')
                .animationName");
        var pointerEvents = await Page.EvaluateAsync<string>(@"
            () => getComputedStyle(document.querySelector('.btn-passkey')).pointerEvents");

        Assert.That(spinner, Is.EqualTo("spin"));
        Assert.That(pointerEvents, Is.EqualTo("none"));
    }

    private async Task GivenLoginLikeButtonAsync()
    {
        var root = ResolvePublicUiSource();
        var css = await File.ReadAllTextAsync(
            Path.Combine(root, "wwwroot", "css", "site.css"));
        var script = await File.ReadAllTextAsync(
            Path.Combine(root, "wwwroot", "js", "instant-feedback.js"));

        await Page.SetContentAsync($$"""
            <!DOCTYPE html>
            <html><head><style>{{css}}</style></head>
            <body>
              <button type="button" class="btn btn-passkey btn-block" data-instant-busy>
                <span>Sign in with passkey</span>
              </button>
              <script>{{script}}</script>
            </body></html>
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
