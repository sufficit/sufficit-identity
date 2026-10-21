using Xunit;

namespace Sufficit.Identity.Tests;

public sealed partial class ManagementUiArchitectureTests
{
    // A token shown once opens in a dialog instead of a panel further down
    // the page, and every surface goes through the same component so the
    // guard against an accidental close is not reimplemented per page.
    [Theory]
    [InlineData("Pages", "OperatorTokens.razor")]
    [InlineData("Pages", "Provisioning.razor")]
    [InlineData(null, "RegistrationTokenPanel.razor")]
    public void One_time_tokens_open_in_the_shared_dialog(string? folder, string file)
    {
        var components = Path.Combine(ResolveManagementUiSource(), "Components");
        var page = File.ReadAllText(folder is null
            ? Path.Combine(components, file)
            : Path.Combine(components, folder, file));

        Assert.Contains("OneTimeTokenDialog.ShowAsync(", page, StringComparison.Ordinal);
        Assert.DoesNotContain("-token-value", page, StringComparison.Ordinal);
        Assert.DoesNotContain("navigator.clipboard", page, StringComparison.Ordinal);
    }

    [Fact]
    public void One_time_token_dialog_guards_an_accidental_close()
    {
        var components = Path.Combine(ResolveManagementUiSource(), "Components");
        var dialog = File.ReadAllText(Path.Combine(components, "OneTimeTokenDialog.razor"));
        var script = File.ReadAllText(Path.Combine(components, "OneTimeTokenDialog.razor.js"));

        Assert.Contains("readonly", dialog, StringComparison.Ordinal);
        Assert.Contains("[JSInvokable]", dialog, StringComparison.Ordinal);
        Assert.Contains("OneTimeToken.DiscardTitle", dialog, StringComparison.Ordinal);
        // Window capture runs before the host's document listener.
        Assert.Contains("window.addEventListener('keydown', onKeyDown, true)", script, StringComparison.Ordinal);
        Assert.Contains("window.addEventListener('click', onClick, true)", script, StringComparison.Ordinal);
    }
}
