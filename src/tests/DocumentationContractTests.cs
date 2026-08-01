using System.Text.RegularExpressions;
using Xunit;

namespace Sufficit.Identity.Tests;

public sealed partial class DocumentationContractTests
{
    private static readonly string[] AllowedPrefixes =
    [
        "ARCHITECTURE",
        "DESIGN",
        "EVALUATION",
        "INVESTIGATION",
        "PLAN",
        "RUNBOOK",
        "USAGE",
    ];

    [Fact]
    public void Documentation_names_express_their_purpose()
    {
        var docsRoot = Path.Combine(ResolveRepositoryRoot(), "docs");
        var markdownFiles = EnumerateCanonicalMarkdown(docsRoot).ToArray();

        Assert.NotEmpty(markdownFiles);

        foreach (var path in markdownFiles)
        {
            var name = Path.GetFileName(path);
            if (string.Equals(name, "README.md", StringComparison.Ordinal))
            {
                continue;
            }

            var prefix = name.Split('-', 2)[0];
            Assert.Contains(prefix, AllowedPrefixes);
            Assert.Matches(
                "^[A-Z]+-[A-Z0-9]+(?:-[A-Z0-9]+)*\\.md$",
                name);
        }

        var topLevelDocuments = Directory
            .EnumerateFiles(docsRoot, "*.md", SearchOption.TopDirectoryOnly)
            .Select(path => Path.GetFileName(path)!)
            .OrderBy(name => name, StringComparer.Ordinal)
            .ToArray();

        Assert.Equal(["README.md"], topLevelDocuments);
    }

    [Fact]
    public void Canonical_documentation_links_resolve()
    {
        var repositoryRoot = ResolveRepositoryRoot();
        var docsRoot = Path.Combine(repositoryRoot, "docs");

        foreach (var sourcePath in EnumerateDocumentation(repositoryRoot, docsRoot))
        {
            var source = File.ReadAllText(sourcePath);
            foreach (Match match in MarkdownLinkPattern().Matches(source))
            {
                var target = match.Groups["target"].Value.Trim('<', '>');
                if (ShouldIgnore(target))
                {
                    continue;
                }

                var pathOnly = target.Split(['#', '?'], 2)[0];
                if (string.IsNullOrWhiteSpace(pathOnly))
                {
                    continue;
                }

                var decodedPath = Uri.UnescapeDataString(pathOnly)
                    .Replace('/', Path.DirectorySeparatorChar);
                var resolvedPath = Path.GetFullPath(Path.Combine(
                    Path.GetDirectoryName(sourcePath)!,
                    decodedPath));

                Assert.True(
                    File.Exists(resolvedPath) || Directory.Exists(resolvedPath),
                    $"{Path.GetRelativePath(repositoryRoot, sourcePath)} links to missing path '{target}'.");
            }
        }
    }

    private static IEnumerable<string> EnumerateCanonicalMarkdown(string docsRoot) =>
        Directory
            .EnumerateFiles(docsRoot, "*.md", SearchOption.AllDirectories)
            .Where(path => !path.Contains(
                $"{Path.DirectorySeparatorChar}archive{Path.DirectorySeparatorChar}",
                StringComparison.Ordinal));

    private static IEnumerable<string> EnumerateDocumentation(
        string repositoryRoot,
        string docsRoot) =>
        EnumerateCanonicalMarkdown(docsRoot)
            .Append(Path.Combine(repositoryRoot, "README.md"))
            .Concat(Directory.EnumerateFiles(
                Path.Combine(repositoryRoot, "src"),
                "*.md",
                SearchOption.AllDirectories));

    private static bool ShouldIgnore(string target) =>
        target.StartsWith('#')
        || target.StartsWith('/')
        || target.StartsWith("http://", StringComparison.OrdinalIgnoreCase)
        || target.StartsWith("https://", StringComparison.OrdinalIgnoreCase)
        || target.StartsWith("mailto:", StringComparison.OrdinalIgnoreCase);

    private static string ResolveRepositoryRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);

        while (directory is not null
               && !File.Exists(Path.Combine(
                   directory.FullName,
                   "Sufficit.Identity.sln")))
        {
            directory = directory.Parent;
        }

        return directory?.FullName
            ?? throw new DirectoryNotFoundException(
                "Could not locate the Sufficit Identity repository root.");
    }

    [GeneratedRegex(@"\[[^\]]*\]\((?<target><[^>]+>|[^)\s]+)\)")]
    private static partial Regex MarkdownLinkPattern();
}
