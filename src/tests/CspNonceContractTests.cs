using System.Text.RegularExpressions;
using Xunit;

namespace Sufficit.Identity.Tests;

/// <summary>
/// Every inline <c>&lt;style&gt;</c> rendered by a host page must carry the
/// per-request CSP nonce.
/// </summary>
/// <remarks>
/// Nonce-based CSP (eval 2026-08-30, F-3) removes <c>'unsafe-inline'</c> from
/// <c>style-src</c>, so an inline style without a nonce is silently dropped by
/// the browser once the policy is enforced. Only the public UI was wired up;
/// the management and vault shells render no inline style today, which is
/// exactly the fragile kind of "correct by accident" — nothing stopped the next
/// person from adding one. This test is that stop, and it covers every host
/// page rather than the one that happened to need it first.
/// <para>Known gap outside our control: Blazor's own
/// <c>DefaultReconnectDisplay</c> injects a nonce-less <c>&lt;style&gt;</c> at
/// runtime, so the reconnect overlay loses its styling under an enforced
/// policy. That is cosmetic and cannot be fixed from here.</para>
/// </remarks>
public sealed class CspNonceContractTests
{
    private static readonly Regex StyleElement = new(
        "<style(?<attributes>[^>]*)>",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public static TheoryData<string> HostPages() =>
    [
        Path.Combine("src", "ui", "Sufficit.Identity.UI", "Components", "App.razor"),
        Path.Combine("src", "ui", "Sufficit.Identity.UI.Management", "Components", "App.razor"),
        Path.Combine("src", "ui", "Sufficit.Identity.UI.Vault", "Components", "App.razor"),
    ];

    [Theory]
    [MemberData(nameof(HostPages))]
    public void Inline_styles_in_host_pages_carry_the_csp_nonce(string relativePath)
    {
        var path = Path.Combine(ResolveIdentityRepository(), relativePath);
        Assert.True(File.Exists(path), $"Host page not found: {relativePath}");

        var markup = File.ReadAllText(path);
        var offenders = StyleElement.Matches(markup)
            .Where(match => !match.Groups["attributes"].Value
                .Contains("nonce", StringComparison.OrdinalIgnoreCase))
            .Select(match => match.Value)
            .ToArray();

        Assert.True(
            offenders.Length == 0,
            $"{relativePath} renders an inline <style> without a CSP nonce. "
            + "Emit nonce=\"@CspNonceValue\" (see Sufficit.Identity.UI/Components/App.razor) "
            + "or the element is dropped once Csp:UseNonce is enabled and the "
            + "policy is enforced. Offending tags: "
            + string.Join(", ", offenders));
    }

    [Fact]
    public void The_public_host_page_still_wires_the_nonce()
    {
        // Guards the reference implementation the message above points at: if
        // this plumbing is ever removed, the guidance would send the next
        // person to a file that no longer shows how.
        var markup = File.ReadAllText(Path.Combine(
            ResolveIdentityRepository(),
            "src", "ui", "Sufficit.Identity.UI", "Components", "App.razor"));

        Assert.Contains("CspNonce.From", markup, StringComparison.Ordinal);
        Assert.Contains("nonce=\"@CspNonceValue\"", markup, StringComparison.Ordinal);
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
