using Xunit;

namespace Sufficit.Identity.Tests;

/// <summary>
/// Keeps source files at a size a person can hold in their head.
/// </summary>
/// <remarks>
/// This repository accumulated files of 1,400 to 2,100 lines — one held 51
/// types, another mixed contracts and implementation behind conditional
/// compilation. Large files are a management problem before they are a
/// technical one: they hide dead code, make reviews shallow, and turn every
/// merge into a conflict.
/// <para>The limit is a ratchet, not an aesthetic rule. It is set just above
/// the largest file that survived the 2026-08-30 decomposition, so the work
/// already done cannot silently regress. When a file legitimately needs to
/// grow past it, the fix is to split it — C# partial classes make that a pure
/// move — not to raise the number.</para>
/// </remarks>
public sealed class SourceFileSizeContractTests
{
    private const int MaximumLines = 1000;

    /// <summary>
    /// Generated code is excluded: EF migrations and designer files are
    /// machine-written and are not read or maintained by hand.
    /// </summary>
    private static readonly string[] ExcludedSegments =
    [
        Path.DirectorySeparatorChar + "bin" + Path.DirectorySeparatorChar,
        Path.DirectorySeparatorChar + "obj" + Path.DirectorySeparatorChar,
        Path.DirectorySeparatorChar + "Migrations" + Path.DirectorySeparatorChar,
    ];

    [Fact]
    public void No_source_file_exceeds_the_maximum_line_count()
    {
        var root = RepositorySourceRoot();
        var offenders = Directory
            .EnumerateFiles(root, "*.cs", SearchOption.AllDirectories)
            .Where(path => !ExcludedSegments.Any(segment =>
                path.Contains(segment, StringComparison.Ordinal)))
            .Where(path => !path.EndsWith(".Designer.cs", StringComparison.Ordinal))
            .Select(path => (Path: path, Lines: File.ReadAllLines(path).Length))
            .Where(file => file.Lines > MaximumLines)
            .OrderByDescending(file => file.Lines)
            .Select(file =>
                $"{Path.GetRelativePath(root, file.Path)}: {file.Lines} linhas")
            .ToArray();

        Assert.True(
            offenders.Length == 0,
            $"Arquivos acima de {MaximumLines} linhas devem ser divididos "
            + "(classes parciais tornam isso um movimento puro):"
            + Environment.NewLine
            + string.Join(Environment.NewLine, offenders));
    }

    private static string RepositorySourceRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null
            && !Directory.Exists(Path.Combine(directory.FullName, "src")))
        {
            directory = directory.Parent;
        }

        Assert.NotNull(directory);
        return Path.Combine(directory!.FullName, "src");
    }
}
