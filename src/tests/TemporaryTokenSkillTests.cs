using System.Reflection;
using System.Text.RegularExpressions;
using Sufficit.Identity.Management.Authorization;
using Xunit;

namespace Sufficit.Identity.Tests;

/// <summary>
/// Keeps the agent-facing skill honest about what this service actually offers.
/// </summary>
/// <remarks>
/// The skill at <c>.claude/skills/identity-temporary-token/SKILL.md</c> tells an
/// agent which capabilities it may request. A capability that is renamed or
/// removed in code leaves the skill advertising something the issuance page will
/// refuse — and the agent discovers it in front of the user, mid-task, after the
/// link has already been sent. Prose drifts; this makes the drift fail here
/// instead.
/// </remarks>
public sealed class TemporaryTokenSkillTests
{
    private static string SkillText()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null
            && !Directory.Exists(Path.Combine(directory.FullName, ".claude")))
        {
            directory = directory.Parent;
        }

        Assert.NotNull(directory);
        var path = Path.Combine(
            directory!.FullName, ".claude", "skills", "identity-temporary-token", "SKILL.md");
        Assert.True(File.Exists(path), $"missing: {path}");
        return File.ReadAllText(path);
    }

    private static HashSet<string> DeclaredCapabilities() =>
        typeof(ManagementCapabilities)
            .GetFields(BindingFlags.Public | BindingFlags.Static | BindingFlags.FlattenHierarchy)
            .Where(field => field is { IsLiteral: true, IsInitOnly: false }
                && field.FieldType == typeof(string))
            .Select(field => (string)field.GetRawConstantValue()!)
            .ToHashSet(StringComparer.Ordinal);

    [Fact]
    public void Every_capability_the_skill_offers_exists_in_code()
    {
        var declared = DeclaredCapabilities();
        Assert.NotEmpty(declared);

        // Table rows only. The prose deliberately names `identity.management`
        // as something NOT to request, and a guard that cannot tell an offer
        // from a warning would force the warning to be deleted — removing the
        // one line that stops an agent from trying it.
        var offered = SkillText()
            .Split('\n')
            .Where(line => line.TrimStart().StartsWith("|", StringComparison.Ordinal))
            .SelectMany(line => Regex.Matches(line, @"`(identity\.[a-z.]+)`")
                .Select(match => match.Groups[1].Value))
            .Distinct(StringComparer.Ordinal)
            .ToArray();

        Assert.NotEmpty(offered);

        var unknown = offered.Where(name => !declared.Contains(name)).ToArray();

        Assert.True(
            unknown.Length == 0,
            "the skill offers capabilities this service does not define: "
                + string.Join(", ", unknown));
    }

    [Fact]
    public void The_skill_does_not_point_agents_at_the_wrong_api_prefix()
    {
        var text = SkillText();

        // The UI is served under /management/; the API is not. Getting this
        // backwards produces a 404 that reads like "the endpoint was removed".
        Assert.Contains("/api/overview", text, StringComparison.Ordinal);
        Assert.DoesNotContain("https://identity.sufficit.com.br/management/api/", text, StringComparison.Ordinal);
    }
}
