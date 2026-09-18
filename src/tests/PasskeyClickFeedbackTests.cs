using Xunit;

namespace Sufficit.Identity.Tests;

/// <summary>
/// A click on the passkey button starts work that only becomes visible after a
/// round trip to the Blazor circuit — and the first thing the handler does is
/// open the platform's passkey dialog, which does not return until the user
/// answers it. On a phone that gap reads as a click that did not register, so
/// the feedback is produced in the browser instead of waiting for the server.
/// </summary>
public sealed partial class ManagementUiArchitectureTests
{
    [Fact]
    public void The_passkey_button_answers_the_click_before_the_server_does()
    {
        var publicUi = ResolvePublicUiSource();
        var login = File.ReadAllText(Path.Combine(
            publicUi, "Pages", "Account", "Login.razor"));

        // Marked for the capture-phase listener, so the busy state is on the
        // element before Blazor is told about the click at all.
        Assert.Contains("data-instant-busy", login, StringComparison.Ordinal);
        // And the component renders the same class once its state catches up,
        // so the re-render agrees with what the browser already did.
        Assert.Contains("is-busy", login, StringComparison.Ordinal);
        // The handler yields before opening the dialog; without it the busy
        // state would only reach the browser after the ceremony ended.
        Assert.Contains("await Task.Yield();", login, StringComparison.Ordinal);
    }

    [Fact]
    public void The_feedback_script_loads_before_the_framework_it_compensates_for()
    {
        var publicUi = ResolvePublicUiSource();
        var app = File.ReadAllText(Path.Combine(
            publicUi, "Components", "App.razor"));

        var feedback = app.IndexOf("js/instant-feedback.js", StringComparison.Ordinal);
        var framework = app.IndexOf("blazor.web.js", StringComparison.Ordinal);

        Assert.True(feedback >= 0, "The instant feedback script is not referenced.");
        Assert.True(
            feedback < framework,
            "The feedback script must load before the Blazor framework.");
        Assert.True(File.Exists(Path.Combine(
            publicUi, "wwwroot", "js", "instant-feedback.js")));
    }

    [Fact]
    public void The_busy_state_is_styled_and_respects_reduced_motion()
    {
        var publicUi = ResolvePublicUiSource();
        var css = File.ReadAllText(Path.Combine(
            publicUi, "wwwroot", "css", "site.css"));

        Assert.Contains(".btn.is-busy", css, StringComparison.Ordinal);
        Assert.Contains("prefers-reduced-motion", css, StringComparison.Ordinal);
    }
}
