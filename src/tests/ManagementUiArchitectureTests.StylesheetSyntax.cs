using System.Text.RegularExpressions;
using Xunit;

namespace Sufficit.Identity.Tests;

public sealed partial class ManagementUiArchitectureTests
{
    // A selector list that ends in a comma and then meets a comment or a
    // blank line was split by an insertion: the selectors above lose their
    // rule and attach to whatever comes next (21/10: the operator token cards
    // lost border and background this way).
    [Theory]
    [InlineData("Sufficit.Identity.UI.Management", "wwwroot/app.css")]
    [InlineData("Sufficit.Identity.UI.Management", "wwwroot/users.css")]
    [InlineData("Sufficit.Identity.UI", "wwwroot/css/site.css")]
    [InlineData("Sufficit.Identity.UI.Management", "Components/Pages/OperatorTokens.razor.css")]
    [InlineData("Sufficit.Identity.UI.Management", "Components/Pages/Provisioning.razor.css")]
    [InlineData("Sufficit.Identity.UI.Management", "Components/RegistrationTokenPanel.razor.css")]
    [InlineData("Sufficit.Identity.UI.Management", "Components/OneTimeTokenDialog.razor.css")]
    public void Stylesheet_selector_lists_are_not_split(string project, string file)
    {
        var path = Path.Combine(
            ResolveIdentityRepository(), "src", "ui", project, file);
        var css = File.ReadAllText(path);

        var splits = SplitSelectorList().Matches(css)
            .Select(match => css[..match.Index].Count(c => c == '\n') + 1)
            .ToArray();

        Assert.True(splits.Length == 0, $"{file}: selector list split at line(s) {string.Join(", ", splits)}");
    }

    // Pages migrated to isolated CSS keep their rules next to the markup;
    // the global sheet must not grow them back.
    [Theory]
    [InlineData(".operator-token-layout")]
    [InlineData(".operator-token-capability")]
    [InlineData(".temporary-token-panel__heading")]
    [InlineData(".provisioning-grid")]
    [InlineData(".one-time-token-dialog__value")]
    [InlineData(".registration-tokens")]
    public void Migrated_component_styles_stay_out_of_the_global_sheet(string selector)
    {
        var css = File.ReadAllText(Path.Combine(
            ResolveManagementUiSource(), "wwwroot", "app.css"));

        Assert.DoesNotMatch(
            new Regex(Regex.Escape(selector) + @"(?![\w-])"),
            css);
    }

    [GeneratedRegex(@",[ \t]*\r?\n[ \t]*(/\*|\r?\n)")]
    private static partial Regex SplitSelectorList();
}
