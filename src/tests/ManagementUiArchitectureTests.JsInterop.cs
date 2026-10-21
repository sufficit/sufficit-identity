using System.Text.RegularExpressions;
using Xunit;

namespace Sufficit.Identity.Tests;

public sealed partial class ManagementUiArchitectureTests
{
    // InvokeAsync/InvokeVoidAsync take params object?[]: a bare array literal
    // binds as the argument list itself, so JS receives each element as a
    // separate argument. 21/10: the sign-in page asked JS to forget "error"
    // ... and the function got the string "error" instead of the key list.
    [Fact]
    public void Js_interop_calls_do_not_spread_an_array_by_accident()
    {
        var ui = Path.Combine(ResolveIdentityRepository(), "src", "ui");
        var offenders = Directory
            .EnumerateFiles(ui, "*.*", SearchOption.AllDirectories)
            .Where(path => (path.EndsWith(".razor", StringComparison.Ordinal)
                    || path.EndsWith(".cs", StringComparison.Ordinal))
                && !path.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}")
                && !path.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}"))
            .Where(path => SpreadArrayArgument().IsMatch(File.ReadAllText(path)))
            .Select(path => Path.GetRelativePath(ui, path))
            .ToArray();

        Assert.True(offenders.Length == 0, "Cast the array to object: " + string.Join(", ", offenders));
    }

    [GeneratedRegex(@"Invoke(?:Void)?Async(?:<[^>]+>)?\(\s*""[^""]+"",\s*new(?:\s+\w+)?\s*\[\]")]
    private static partial Regex SpreadArrayArgument();
}
