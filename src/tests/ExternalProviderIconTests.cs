using System.Text.RegularExpressions;
using Xunit;

namespace Sufficit.Identity.Tests;

/// <summary>
/// GitHub shipped without a mark because the sign-in page chose icons with a
/// chain of two <c>if</c>s and there was no third branch. The marks live in one
/// component now, and this checks that every provider the host can put on the
/// sign-in page is actually in it.
/// </summary>
public sealed partial class ManagementUiArchitectureTests
{
    [Fact]
    public void Every_sign_in_provider_has_a_brand_mark()
    {
        var registration = File.ReadAllText(Path.Combine(
            ResolveIdentityRepository(),
            "src", "sts", "ServiceCollectionExtensions.ExternalProviders.cs"));
        var icons = File.ReadAllText(Path.Combine(
            ResolvePublicUiSource(), "Components", "ProviderIcon.razor"));

        // Schemes registered with an empty display name never reach the
        // sign-in list — GitLab is registered that way on purpose, as an
        // integration rather than a way in.
        var signInProviders = Regex
            .Matches(registration, @"builder\.Add(?<provider>\w+?)\(\s*(?:options|"")")
            .Select(match => match.Groups["provider"].Value)
            .Where(provider => provider is not "OAuth")
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

        Assert.NotEmpty(signInProviders);

        foreach (var provider in signInProviders)
        {
            Assert.Contains(
                $"\"{provider.ToLowerInvariant()}\" => new MarkupString(",
                icons,
                StringComparison.Ordinal);
        }
    }

    [Fact]
    public void Both_provider_lists_render_the_shared_mark()
    {
        var publicUi = ResolvePublicUiSource();

        foreach (var page in new[]
        {
            Path.Combine("Pages", "Account", "Login.razor"),
            Path.Combine("Pages", "Manage", "ExternalLogins.razor"),
        })
        {
            var markup = File.ReadAllText(Path.Combine(publicUi, page));
            Assert.Contains("<ProviderIcon Provider=", markup, StringComparison.Ordinal);
            // The inline branches the marks replaced must not come back.
            Assert.DoesNotContain(
                "scheme.Name.Equals(\"Google\"",
                markup,
                StringComparison.Ordinal);
        }
    }
}
