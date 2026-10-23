using System.Text.RegularExpressions;
using Xunit;

namespace Sufficit.Identity.Tests;

/// <summary>
/// Host pages render no inline <c>&lt;style&gt;</c> of their own, and hand the
/// per-request CSP nonce to <c>SUIThemeProvider</c>, the one component that
/// does.
/// </summary>
/// <remarks>
/// Nonce-based CSP (eval 2026-08-30, F-3) removes <c>'unsafe-inline'</c> from
/// <c>style-src</c>. Production reports showed two ways an inline style still
/// got blocked: a <c>SUIThemeProvider</c> rendered without its nonce in the
/// management console, and the public pages' theme block, which enhanced
/// navigation merged into the document carrying the next response's nonce. The
/// theme moved to a stylesheet (<c>BrandingStylesheet</c>); Blazor's default
/// reconnect overlay, which injects its own nonce-less style, is replaced by a
/// <c>components-reconnect-modal</c> element styled from the page's CSS.
/// </remarks>
public sealed class CspNonceContractTests
{
    private static readonly Regex StyleElement = new(
        "<style(?<attributes>[^>]*)>",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex ThemeProvider = new(
        "<SUIThemeProvider(?<attributes>[^>]*)>",
        RegexOptions.Compiled);

    public static TheoryData<string> HostPages() =>
    [
        Path.Combine("src", "ui", "Sufficit.Identity.UI", "Components", "App.razor"),
        Path.Combine("src", "ui", "Sufficit.Identity.UI.Management", "Components", "App.razor"),
        Path.Combine("src", "ui", "Sufficit.Identity.UI.Vault", "Components", "App.razor"),
    ];

    [Theory]
    [MemberData(nameof(HostPages))]
    public void Host_pages_render_no_inline_style_element(string relativePath)
    {
        var markup = ReadHostPage(relativePath);

        Assert.True(
            !StyleElement.IsMatch(markup),
            $"{relativePath} renders an inline <style>. Serve it as a same-origin "
            + "stylesheet instead (see BrandingStylesheet): enhanced navigation "
            + "brings the next response's nonce into a document that only trusts "
            + "the first one.");
    }

    [Theory]
    [MemberData(nameof(HostPages))]
    public void The_theme_provider_receives_the_csp_nonce(string relativePath)
    {
        var markup = ReadHostPage(relativePath);
        var offenders = ThemeProvider.Matches(markup)
            .Where(match => !match.Groups["attributes"].Value.Contains("Nonce=", StringComparison.Ordinal))
            .Select(match => match.Value)
            .ToArray();

        Assert.True(
            offenders.Length == 0,
            $"{relativePath} renders SUIThemeProvider without Nonce=: its <style> "
            + "is blocked once the policy is enforced. Offending tags: "
            + string.Join(", ", offenders));
    }

    [Theory]
    [MemberData(nameof(HostPages))]
    public void Host_pages_bring_their_own_reconnect_modal(string relativePath)
    {
        Assert.Contains("<ReconnectModal ", ReadHostPage(relativePath), StringComparison.Ordinal);
    }

    private static string ReadHostPage(string relativePath)
    {
        var path = Path.Combine(ResolveIdentityRepository(), relativePath);
        Assert.True(File.Exists(path), $"Host page not found: {relativePath}");
        return File.ReadAllText(path);
    }

    private static string ResolveIdentityRepository()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null
            && !File.Exists(Path.Combine(directory.FullName, "Sufficit.Identity.sln")))
        {
            directory = directory.Parent;
        }

        Assert.NotNull(directory);
        return directory!.FullName;
    }
}
