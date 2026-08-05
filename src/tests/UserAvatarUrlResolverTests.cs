using Sufficit.Identity.Application.Branding;
using Sufficit.Identity.Core.Branding;
using Xunit;

namespace Sufficit.Identity.Tests;

public sealed class UserAvatarUrlResolverTests
{
    [Fact]
    public async Task Active_theme_template_is_resolved_for_opaque_user_subject()
    {
        var provider = new StubBrandingThemeProvider(
            Theme(
                "https://endpoints.tests.local/contact/avatar"
                + "?contextid={userid}"));
        var resolver = new UserAvatarUrlResolver(provider);

        var result = await resolver.ResolveAsync("  user/one  ");

        Assert.Equal(
            "https://endpoints.tests.local/contact/avatar"
            + "?contextid=user%2Fone",
            result);
        Assert.Equal(1, provider.ReadCount);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public async Task Missing_user_subject_does_not_read_branding(
        string? userId)
    {
        var provider = new StubBrandingThemeProvider(
            Theme("/avatar/{userid}"));
        var resolver = new UserAvatarUrlResolver(provider);

        var result = await resolver.ResolveAsync(userId);

        Assert.Null(result);
        Assert.Equal(0, provider.ReadCount);
    }

    [Fact]
    public async Task Missing_active_template_returns_no_avatar()
    {
        var provider = new StubBrandingThemeProvider(
            Theme(" "));
        var resolver = new UserAvatarUrlResolver(provider);

        var result = await resolver.ResolveAsync("user-1");

        Assert.Null(result);
    }

    private static BrandingTheme Theme(string? avatarUrlTemplate) =>
        new(
            "Test",
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            avatarUrlTemplate);

    private sealed class StubBrandingThemeProvider(
        BrandingTheme? theme) : IBrandingThemeProvider
    {
        public int ReadCount { get; private set; }

        public Task<BrandingTheme?> GetActiveAsync(
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ReadCount++;
            return Task.FromResult(theme);
        }

        public void Invalidate()
        {
        }
    }
}
