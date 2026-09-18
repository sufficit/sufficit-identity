using Xunit;

namespace Sufficit.Identity.Tests;

/// <summary>
/// A click on the passkey button starts work that only becomes visible after a
/// round trip to the Blazor circuit — and the first thing the handler does is
/// open the platform's passkey dialog, which does not return until the user
/// answers it. On a phone that gap reads as a click that did not register.
///
/// The general answer now lives in Sufficit.Blazor.UI: SUILoadingButton marks
/// the button inside the click itself. What stays here is the part the library
/// cannot know — a ceremony has no round-trip-shaped duration, so the page
/// keeps the busy state on aria-busy for as long as the dialog is open.
/// </summary>
public sealed partial class ManagementUiArchitectureTests
{
    [Fact]
    public void The_passkey_button_answers_the_click_before_the_server_does()
    {
        var publicUi = ResolvePublicUiSource();
        var login = File.ReadAllText(Path.Combine(
            publicUi, "Pages", "Account", "Login.razor"));

        // SUILoadingButton, whose InstantFeedback defaults to on, is what marks
        // the button in the capture phase of the click.
        Assert.Contains("<SUILoadingButton", login, StringComparison.Ordinal);
        // And the ceremony keeps its own busy state, which outlives the
        // library's release timer.
        Assert.Contains("aria-busy=", login, StringComparison.Ordinal);
        // The handler yields before opening the dialog; without it the busy
        // state would only reach the browser after the ceremony ended.
        Assert.Contains("await Task.Yield();", login, StringComparison.Ordinal);
    }

    [Fact]
    public void The_public_ui_no_longer_ships_its_own_copy_of_the_mechanism()
    {
        var publicUi = ResolvePublicUiSource();
        var app = File.ReadAllText(Path.Combine(
            publicUi, "Components", "App.razor"));

        Assert.DoesNotContain("instant-feedback.js", app, StringComparison.Ordinal);
        Assert.False(
            File.Exists(Path.Combine(publicUi, "wwwroot", "js", "instant-feedback.js")),
            "The local press-feedback script is superseded by SUILoadingButton.");
    }

    [Fact]
    public void The_busy_state_is_styled_and_respects_reduced_motion()
    {
        var publicUi = ResolvePublicUiSource();
        var css = File.ReadAllText(Path.Combine(
            publicUi, "wwwroot", "css", "site.css"));

        Assert.Contains(".sui-btn[aria-busy=\"true\"]", css, StringComparison.Ordinal);
        Assert.Contains("prefers-reduced-motion", css, StringComparison.Ordinal);
    }
}
