using System.Text.RegularExpressions;
using Xunit;

namespace Sufficit.Identity.Tests;

public sealed partial class ManagementUiArchitectureTests
{
    private static readonly Regex RawControl = new(
        @"<(button|select|textarea|table|details)\b|<input\b(?![^>]*type=""hidden"")|<Input(Text|TextArea|Select|Checkbox|Number|Date|Radio)\b",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    /// <summary>
    /// The only raw controls left on purpose, each where Sufficit.Blazor.UI has
    /// no equivalent. Adding one here is a decision, not a shortcut: prefer
    /// filling the gap in the library.
    /// </summary>
    private static readonly Dictionary<string, (int Count, string Reason)> AllowedRawControls = new()
    {
        // Full-screen backdrop that closes the sidebar on narrow screens; the
        // library only has it inside SUIDrawer, which would replace the shell.
        [Path.Combine("Layout", "MainLayout.razor")] = (1, "sidebar backdrop"),
        // Registration chart: each bar is a custom visual with aria-pressed;
        // there is no chart component.
        [Path.Combine("Pages", "Users.razor")] = (1, "registration chart bars"),
        // Dismiss button of Blazor's #blazor-error-ui, framework markup.
        ["App.razor"] = (1, "blazor error UI dismiss"),
    };

    // Every management surface takes its controls from Sufficit.Blazor.UI: a
    // raw button, field, select, table or disclosure brought back would be
    // styled by the page instead of the library (owner rule: always SUI).
    [Fact]
    public void Management_ui_uses_only_sui_controls()
    {
        var components = Path.Combine(ResolveManagementUiSource(), "Components");
        var offenders = new List<string>();

        foreach (var file in Directory.EnumerateFiles(components, "*.razor", SearchOption.AllDirectories))
        {
            var relative = Path.GetRelativePath(components, file);
            var text = File.ReadAllText(file);
            var count = RawControl.Matches(text).Count;
            var allowed = AllowedRawControls.TryGetValue(relative, out var exception) ? exception.Count : 0;
            if (count != allowed)
            {
                offenders.Add($"{relative}: {count} raw control(s), {allowed} allowed");
            }

            if (text.Contains("class=\"button ", StringComparison.Ordinal)
                || text.Contains("class=\"form-control", StringComparison.Ordinal))
            {
                offenders.Add($"{relative}: hand-styled button or field class");
            }
        }

        Assert.True(offenders.Count == 0,
            "Use Sufficit.Blazor.UI components (or fill the gap in the library):\n"
            + string.Join("\n", offenders));
    }
}
