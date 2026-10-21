using System.Text.RegularExpressions;
using Xunit;

namespace Sufficit.Identity.Tests;

public sealed partial class ManagementUiArchitectureTests
{
    // ToLocalTime() uses the server's zone and "dd/MM" fixes one culture's
    // order: both right only where server and readers share a zone and a
    // language. Screens format instants through BrowserTime / LocalTime.
    [Fact]
    public void Screens_do_not_format_instants_in_the_server_zone_or_a_fixed_culture()
    {
        var ui = Path.Combine(ResolveIdentityRepository(), "src", "ui");
        var offenders = Directory
            .EnumerateFiles(ui, "*.razor", SearchOption.AllDirectories)
            .Where(path => !path.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}")
                && !path.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}"))
            .SelectMany(path => File.ReadAllLines(path)
                .Select((line, index) => (path, line, index)))
            .Where(item => ServerZoneOrFixedCulture().IsMatch(item.line))
            // The sign-in stamp's no-JS fallback is explicitly labelled UTC.
            .Where(item => !item.line.Contains("+ \" UTC\"", StringComparison.Ordinal))
            .Select(item => $"{Path.GetRelativePath(ui, item.path)}:{item.index + 1}")
            .ToArray();

        Assert.True(offenders.Length == 0, "Format instants with BrowserTime/LocalTime: " + string.Join(", ", offenders));
    }

    [GeneratedRegex(@"\.ToLocalTime\(\)|ToString\(""dd/MM|:dd/MM")]
    private static partial Regex ServerZoneOrFixedCulture();
}
