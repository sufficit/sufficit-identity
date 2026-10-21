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

    [GeneratedRegex(@",[ \t]*\r?\n[ \t]*(/\*|\r?\n)")]
    private static partial Regex SplitSelectorList();
}
