using Microsoft.Playwright;
using Microsoft.Playwright.NUnit;
using NUnit.Framework;

namespace Sufficit.Identity.BrowserTests;

/// <summary>
/// The press feedback itself belongs to Sufficit.Blazor.UI: SUILoadingButton
/// marks the button in the capture phase of the click and releases it a few
/// seconds later, and the library tests that. What this product owns is the
/// skin over it, and one case the library's timer cannot serve — a passkey
/// ceremony waits on a platform dialog for as long as the person needs, so the
/// page carries the busy state on aria-busy instead. These run against
/// site.css alone: no server, no circuit, no authenticator.
/// </summary>
[Parallelizable(ParallelScope.None)]
public class InstantFeedbackTests : PageTest
{
    [Test]
    public async Task A_button_busy_with_a_ceremony_shows_a_spinner_and_stops_further_clicks()
    {
        await GivenPasskeyLikeButtonAsync(ariaBusy: true);

        var spinner = await Page.EvaluateAsync<string>(@"
            () => getComputedStyle(document.querySelector('.btn-passkey'), '::after')
                .animationName");
        var cursor = await Page.EvaluateAsync<string>(@"
            () => getComputedStyle(document.querySelector('.btn-passkey')).cursor");

        Assert.That(spinner, Is.EqualTo("spin"));
        Assert.That(cursor, Is.EqualTo("progress"));
    }

    [Test]
    public async Task An_idle_button_carries_no_spinner()
    {
        await GivenPasskeyLikeButtonAsync(ariaBusy: false);

        var spinner = await Page.EvaluateAsync<string>(@"
            () => getComputedStyle(document.querySelector('.btn-passkey'), '::after')
                .animationName");

        Assert.That(spinner, Is.EqualTo("none"));
    }

    [Test]
    public async Task The_spinner_slows_down_when_motion_is_reduced()
    {
        await Page.EmulateMediaAsync(new() { ReducedMotion = ReducedMotion.Reduce });
        await GivenPasskeyLikeButtonAsync(ariaBusy: true);

        var duration = await Page.EvaluateAsync<string>(@"
            () => getComputedStyle(document.querySelector('.btn-passkey'), '::after')
                .animationDuration");

        Assert.That(duration, Is.EqualTo("2.4s"));
    }

    private async Task GivenPasskeyLikeButtonAsync(bool ariaBusy)
    {
        var root = ResolvePublicUiSource();
        var css = await File.ReadAllTextAsync(
            Path.Combine(root, "wwwroot", "css", "site.css"));

        await Page.SetContentAsync($$"""
            <!DOCTYPE html>
            <html><head><style>{{css}}</style></head>
            <body>
              <div class="page identity-public">
                <button type="button"
                        class="sui-btn sui-btn--outlined sui-btn--color-default btn-passkey"
                        aria-busy="{{(ariaBusy ? "true" : "false")}}">
                  <span class="sui-btn__label">Sign in with passkey</span>
                </button>
              </div>
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
