using System.Diagnostics;
using System.Text;
using System.Text.RegularExpressions;
using Markdig;
using Markdig.Syntax;
using Markdig.Syntax.Inlines;
using Xunit;

namespace Sufficit.Identity.Tests;

/// <summary>
/// Every Markdown file in the repository must be reachable by following relative links from
/// README.md, and maintained documents must not link to Markdown files that do not exist.
/// Paths listed in <c>.markdown-coverage-ignore</c> (historical records) are exempt from both
/// rules; links pointing at them from maintained documents are still validated.
/// </summary>
public sealed class MarkdownCoverageTests
{
    private const string Entrypoint = "README.md";
    private const string IgnoreFile = ".markdown-coverage-ignore";

    [Fact]
    public void RepositoryMarkdownIsReachableFromReadme()
    {
        var root = Git(AppContext.BaseDirectory, "rev-parse", "--show-toplevel").Trim();
        var graph = MarkdownGraph.FromRepository(root);
        var ignore = MarkdownCoverageIgnore.Load(Path.Combine(root, IgnoreFile));

        var orphans = ignore.Filter(graph.Unreachable(Entrypoint));
        var missing = graph.MissingTargets(ignore.Filter(graph.Paths));
        var errors = new StringBuilder();
        if (orphans.Count > 0)
            errors.Append($"Markdown files unreachable from {Entrypoint} ({orphans.Count}):\n  - ")
                .AppendJoin("\n  - ", orphans)
                .Append("\nLink each one from a document already in the hierarchy (its guide, index, project README or ")
                .Append($"\"Related documents\" section), or list the path in {IgnoreFile} when it is intentionally unindexed.\n");
        if (missing.Count > 0)
            errors.Append("Markdown links to missing documents:\n  - ")
                .AppendJoin("\n  - ", missing.Select(x => $"{x.Key} -> {string.Join(", ", x.Value)}"));
        Assert.True(errors.Length == 0, errors.ToString());
    }

    internal static string Git(string directory, params string[] args)
    {
        var start = new ProcessStartInfo("git") { WorkingDirectory = directory, RedirectStandardOutput = true, RedirectStandardError = true };
        foreach (var arg in args) start.ArgumentList.Add(arg);
        using var process = Process.Start(start)!;
        var output = process.StandardOutput.ReadToEnd();
        var error = process.StandardError.ReadToEnd();
        process.WaitForExit();
        if (process.ExitCode != 0) throw new InvalidOperationException($"git {string.Join(' ', args)}: {error}");
        return output;
    }

    // --- behavior of the checker itself ---

    [Fact]
    public void ReportsOrphansAndDisconnectedCycles()
    {
        var graph = new MarkdownGraph(new Dictionary<string, string>
        {
            ["README.md"] = "[Guide](guide.md)", ["guide.md"] = "[Root](README.md)",
            ["orphan.md"] = "[Self](orphan.md)", ["cycle-a.md"] = "[B](cycle-b.md)", ["cycle-b.md"] = "[A](cycle-a.md)",
        });
        Assert.Equal(["cycle-a.md", "cycle-b.md", "orphan.md"], graph.Unreachable("README.md"));
    }

    [Fact]
    public void FollowsRelativeRootEncodedReferenceAndHtmlLinks()
    {
        var graph = new MarkdownGraph(new Dictionary<string, string>
        {
            ["README.md"] = "[Guide](docs/) [Other][other]\n\n[other]: /OTHER.MD#section\n",
            ["OTHER.MD"] = "",
            ["docs/README.md"] = "[Details](./nested/../a%20b.md?view=1#section)",
            ["docs/a b.md"] = "<p>See <a href=\"../end.md\">End</a></p>\n",
            ["end.md"] = "",
        });
        Assert.Empty(graph.Unreachable("README.md"));
    }

    [Fact]
    public void IgnoresCodeImagesCommentsAndPlainMentions()
    {
        const string content = "plain.md\n`[Code](inline.md)`\n![Image](image.md)\n"
            + "<!-- [Hidden](comment.md) <a href=\"comment.md\">Hidden</a> -->\n\n"
            + "```markdown\n[Example](fenced.md)\n```\n\n    [Indented](indented.md)\n\n"
            + "<pre><a href=\"pre.md\">Example</a></pre>\n";
        string[] targets = ["comment.md", "fenced.md", "image.md", "indented.md", "inline.md", "plain.md", "pre.md"];
        var documents = targets.ToDictionary(x => x, _ => "");
        documents["README.md"] = content;
        Assert.Equal(targets, new MarkdownGraph(documents).Unreachable("README.md"));
    }

    [Fact]
    public void IgnoresExternalLinksAnchorsAndPathsOutsideRepository()
    {
        var graph = new MarkdownGraph(new Dictionary<string, string>
        {
            ["README.md"] = "[Web](https://example.com/remote.md) [Relative web](//example.com/remote.md) "
                + "[Mail](mailto:remote.md) [File](file:///remote.md) [Anchor](#remote.md) "
                + "[Outside](../remote.md) [Encoded outside](%2E%2E/remote.md) [Code](Program.cs)",
            ["remote.md"] = "",
        });
        Assert.Equal(["remote.md"], graph.Unreachable("README.md"));
        Assert.Empty(graph.MissingTargets(["README.md"]));
    }

    [Fact]
    public void ReportsMissingTargetsOnlyForRequestedSources()
    {
        var graph = new MarkdownGraph(new Dictionary<string, string>
        {
            ["README.md"] = "[Index](docs/README.md)",
            ["docs/README.md"] = "[Deleted](deleted.md) [Renamed](old%20name.md#intro)",
            ["history.md"] = "[Old evidence](obsolete.md)",
        });
        var missing = graph.MissingTargets(["README.md", "docs/README.md"]);
        Assert.Equal(["docs/README.md"], missing.Keys);
        Assert.Equal(["docs/deleted.md", "docs/old name.md"], missing["docs/README.md"]);
    }

    [Fact]
    public void IgnoreFileMatchesDirectoriesAndPatterns()
    {
        var file = Path.Combine(Directory.CreateTempSubdirectory().FullName, IgnoreFile);
        File.WriteAllText(file, "# history\ndocs/activities/\n\n/AGENTS.md\nsrc/*/NOTES.md\n");
        var ignore = MarkdownCoverageIgnore.Load(file);
        Assert.Equal(["docs/AGENTS.md", "docs/activitiesX.md", "src/api/deep/NOTES.md"], ignore.Filter(
            ["AGENTS.md", "docs/AGENTS.md", "docs/activities/2026-x.md", "docs/activitiesX.md", "src/api/NOTES.md", "src/api/deep/NOTES.md"]));
    }

    [Fact]
    public void RepositoryInventoryUsesWorkingTreeFiles()
    {
        var root = Directory.CreateTempSubdirectory().FullName;
        void Write(string name, string content) => File.WriteAllText(Path.Combine(root, name), content);
        Git(root, "init", "--quiet");
        Write(".gitignore", "ignored.md\n");
        Write("README.md", "[New](new.md)");
        Write("deleted.md", "");
        Git(root, "add", "README.md", "deleted.md");
        File.Delete(Path.Combine(root, "deleted.md"));
        Write("new.md", "");
        Write("ignored.md", "");
        Write("other.txt", "");

        var graph = MarkdownGraph.FromRepository(root);
        Assert.Equal(["README.md", "new.md"], graph.Paths);
        Assert.Empty(graph.Unreachable("README.md"));
    }
}

/// <summary>Document path (slash-separated, repository relative) → local Markdown documents it links to.</summary>
internal sealed partial class MarkdownGraph
{
    private readonly HashSet<string> documents;
    private readonly Dictionary<string, List<string>> links = [];

    public MarkdownGraph(IReadOnlyDictionary<string, string> sources)
    {
        documents = [.. sources.Keys];
        foreach (var (name, content) in sources)
            links[name] = Destinations(content).Select(href => LocalTarget(name, href)).OfType<string>().Distinct().ToList();
    }

    /// <summary>Tracked and new, non-ignored Markdown files; files deleted from the working tree are excluded.</summary>
    public static MarkdownGraph FromRepository(string root)
    {
        var files = MarkdownCoverageTests.Git(root, "ls-files", "--cached", "--others", "--exclude-standard", "-z").Split('\0');
        var sources = new Dictionary<string, string>();
        foreach (var name in files.Where(x => x.EndsWith(".md", StringComparison.OrdinalIgnoreCase)).Distinct())
        {
            var path = Path.Combine(root, name);
            if (File.Exists(path)) sources[name] = File.ReadAllText(path);
        }
        return new MarkdownGraph(sources);
    }

    public List<string> Paths => [.. documents.Order(StringComparer.Ordinal)];

    public List<string> Unreachable(string entrypoint)
    {
        var visited = new HashSet<string>();
        var pending = new Stack<string>([entrypoint]);
        while (pending.TryPop(out var current))
            if (documents.Contains(current) && visited.Add(current))
                foreach (var target in links[current]) pending.Push(target);
        return [.. Paths.Where(x => !visited.Contains(x))];
    }

    public SortedDictionary<string, List<string>> MissingTargets(IEnumerable<string> sources)
    {
        var missing = new SortedDictionary<string, List<string>>(StringComparer.Ordinal);
        foreach (var source in sources)
        {
            var absent = links.GetValueOrDefault(source, []).Where(x => !documents.Contains(x)).Order(StringComparer.Ordinal).ToList();
            if (absent.Count > 0) missing[source] = absent;
        }
        return missing;
    }

    /// <summary>
    /// Link destinations as a CommonMark renderer sees them: inline, reference-style and HTML anchors
    /// count; code spans, fenced or indented code, images and comments do not.
    /// </summary>
    private static IEnumerable<string> Destinations(string content)
    {
        var document = Markdown.Parse(content);
        var html = new StringBuilder();
        foreach (var node in document.Descendants())
            switch (node)
            {
                case LinkInline { IsImage: false, Url: { } url }: yield return url; break;
                case HtmlBlock block: html.AppendLine(block.Lines.ToString()); break;
                case HtmlInline inline: html.Append(inline.Tag); break;
            }
        var raw = PreOrCode().Replace(HtmlComment().Replace(html.ToString(), ""), "");
        foreach (Match match in AnchorHref().Matches(raw)) yield return match.Groups[1].Value;
    }

    /// <summary>Directory links count when the directory has a README.md; links leaving the repository are ignored.</summary>
    private string? LocalTarget(string source, string href)
    {
        if (href.Length == 0 || External().IsMatch(href)) return null;
        var destination = Uri.UnescapeDataString(href.Split('#', 2)[0].Split('?', 2)[0]);
        var joined = destination.StartsWith('/') ? destination.TrimStart('/') : CombineSlash(DirectoryOf(source), destination);
        var target = Clean(joined);
        if (target is null) return null;
        if (target.EndsWith(".md", StringComparison.OrdinalIgnoreCase)) return target;
        var readme = target.Length == 0 ? "README.md" : target + "/README.md";
        return documents.Contains(readme) ? readme : null;
    }

    private static string DirectoryOf(string path) => path.Contains('/') ? path[..path.LastIndexOf('/')] : "";

    private static string CombineSlash(string directory, string relative) => directory.Length == 0 ? relative : directory + "/" + relative;

    /// <summary>Resolves "." and ".." segments; null when the path escapes the repository root.</summary>
    private static string? Clean(string path)
    {
        var parts = new List<string>();
        foreach (var segment in path.Split('/'))
        {
            if (segment is "" or ".") continue;
            if (segment == "..")
            {
                if (parts.Count == 0) return null;
                parts.RemoveAt(parts.Count - 1);
            }
            else parts.Add(segment);
        }
        return string.Join('/', parts);
    }

    [GeneratedRegex(@"^(?:[a-z][a-z\d+.-]*:|//|[?#])", RegexOptions.IgnoreCase)] private static partial Regex External();
    [GeneratedRegex(@"<a\s[^>]*?href\s*=\s*[""']([^""']*)[""']", RegexOptions.IgnoreCase | RegexOptions.Singleline)] private static partial Regex AnchorHref();
    [GeneratedRegex(@"<!--.*?-->", RegexOptions.Singleline)] private static partial Regex HtmlComment();
    [GeneratedRegex(@"<(pre|code)\b.*?</(pre|code)>", RegexOptions.IgnoreCase | RegexOptions.Singleline)] private static partial Regex PreOrCode();
}

/// <summary>
/// Repository-relative patterns: "dir/" exempts a whole directory, anything else is a glob where
/// "*" and "?" never cross "/" ("AGENTS.md", "docs/*/NOTES.md"). Blank lines and "#" comments are skipped.
/// </summary>
internal sealed class MarkdownCoverageIgnore(IReadOnlyList<string> patterns)
{
    public static MarkdownCoverageIgnore Load(string file) => new(!File.Exists(file) ? [] : File.ReadAllLines(file)
        .Select(x => x.Trim()).Where(x => x.Length > 0 && !x.StartsWith('#')).Select(x => x.TrimStart('/')).ToList());

    public bool Matches(string name) => patterns.Any(pattern => pattern.EndsWith('/')
        ? name.StartsWith(pattern, StringComparison.Ordinal)
        : Regex.IsMatch(name, "^" + Regex.Escape(pattern).Replace(@"\*", "[^/]*").Replace(@"\?", "[^/]") + "$"));

    public List<string> Filter(IEnumerable<string> names) => [.. names.Where(x => !Matches(x))];
}
