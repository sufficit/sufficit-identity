using System.Text.RegularExpressions;
using Xunit;

namespace Sufficit.Identity.Tests;

/// <summary>
/// Guards the deployment-neutral trees against hardcoded web destinations.
/// The failure this prevents: a tenant's site baked into generic product
/// code (the device close fallback once hardcoded a marketing URL in
/// <c>UserCode.razor</c>) — the kind of thing configuration, client
/// registration data or the deployment's own hosts should provide.
/// </summary>
/// <remarks>
/// A new URL fails this test on purpose: make it configuration or per-client
/// registration data. Only if the literal genuinely belongs in code (an
/// integration endpoint the deployment SELECTS, a spec namespace in a
/// comment) does it join <see cref="Allowed"/> — with a reason, as a
/// reviewable decision rather than an accident.
/// </remarks>
public sealed class HardcodedUrlGuardTests
{
    private static readonly Regex UrlLiteral =
        new("""https?://[^\s"'<>\\)]+""", RegexOptions.Compiled);

    /// <summary>Source trees that must stay free of baked-in destinations.</summary>
    private static readonly string[] GuardedTrees =
    [
        Path.Combine("src", "ui", "Sufficit.Identity.UI"),
        Path.Combine("src", "application", "Sufficit.Identity.Application.Abstractions"),
    ];

    private static readonly string[] GuardedExtensions =
        [".cs", ".razor", ".js", ".css"];

    private static readonly string[] SkippedDirectories =
        ["bin", "obj", "_framework"];

    /// <summary>
    /// Literals that may appear, each with its reason. Prefix match, so a
    /// query string on a provider script still matches its entry.
    /// </summary>
    private static readonly (string Prefix, string Reason)[] Allowed =
    [
        // Threat illustration inside a security comment (Login.razor), not a
        // destination the code ever contacts or renders.
        ("https://evil.example",
            "illustrative host in a phishing-threat comment"),
        // Human-verification provider scripts: which one loads is selected by
        // the deployment's HumanVerification configuration (provider + site
        // key), so the endpoint is an integration the deployment opts into —
        // never a redirect destination of its own.
        ("https://challenges.cloudflare.com/turnstile/v0/api.js",
            "script endpoint of the configured human-verification provider"),
        ("https://www.google.com/recaptcha/api.js",
            "script endpoint of the configured human-verification provider"),
        // This is a WS-Federation claim type identifier, not a destination.
        // It is denied explicitly so a scope entitlement cannot mint roles.
        ("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/role",
            "standard role claim type identifier used only for deny-list matching"),
    ];

    [Fact]
    public void Generic_ui_and_abstractions_contain_no_hardcoded_urls()
    {
        var repository = ResolveRepository();
        var violations = new List<string>();

        foreach (var tree in GuardedTrees)
        {
            var root = Path.Combine(repository, tree);
            Assert.True(Directory.Exists(root), $"guarded tree missing: {tree}");

            foreach (var file in Directory.EnumerateFiles(
                         root, "*", SearchOption.AllDirectories))
            {
                if (!GuardedExtensions.Contains(Path.GetExtension(file), StringComparer.OrdinalIgnoreCase))
                    continue;
                if (SkippedDirectories.Any(directory =>
                        file.Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)
                            .Contains(directory, StringComparer.OrdinalIgnoreCase)))
                    continue;

                var lines = File.ReadAllLines(file);
                for (var index = 0; index < lines.Length; index++)
                {
                    foreach (var match in UrlLiteral.Matches(lines[index]))
                    {
                        var url = match.ToString()!;
                        if (Allowed.Any(entry =>
                                url.StartsWith(entry.Prefix, StringComparison.OrdinalIgnoreCase)))
                            continue;

                        violations.Add(
                            $"{Path.GetRelativePath(repository, file)}:{index + 1} {url}");
                    }
                }
            }
        }

        Assert.True(
            violations.Count == 0,
            "Hardcoded web destination(s) in deployment-neutral code — move the " +
            "value to deployment configuration or per-client registration data. " +
            "It only belongs here as a reviewed allowlist entry with a reason:\n" +
            string.Join('\n', violations));
    }

    private static string ResolveRepository()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(
            Path.Combine(directory.FullName, "Sufficit.Identity.sln")))
            directory = directory.Parent;
        Assert.True(directory is not null, "repository root not found");
        return directory!.FullName;
    }
}
