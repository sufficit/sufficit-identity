using Sufficit.Identity.Management.Users;
using Xunit;

namespace Sufficit.Identity.Tests;

/// <summary>
/// The <c>picture</c> claim is untrusted input rendered inside the operator
/// console.
/// </summary>
/// <remarks>
/// It arrives from an external identity provider, or from whatever a user typed
/// into a self-service profile. Rendering it unfiltered would make an
/// operator's browser fetch an address chosen by the account being inspected —
/// on the one screen where the accounts under inspection are the ones already
/// suspected of something.
/// </remarks>
public sealed class AvatarPictureHostsTests
{
    private static readonly string[] Allowed =
        ["https://images.example", "https://cdn.example"];

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("not-a-url")]
    [InlineData("/relative/path.png")]
    [InlineData("data:image/png;base64,AAAA")]
    [InlineData("javascript:alert(1)")]
    public void Values_that_are_not_absolute_https_urls_are_dropped(string? value)
        => Assert.Null(AvatarPictureHosts.Normalize(value, Allowed));

    [Fact]
    public void Plain_http_is_dropped_even_on_an_allowed_host()
        => Assert.Null(AvatarPictureHosts.Normalize(
            "http://images.example/a/portrait", Allowed));

    [Theory]
    [InlineData("https://evil.example/portrait.png")]
    [InlineData("https://images.example.evil.example/portrait.png")]
    [InlineData("https://notimages.example/portrait.png")]
    public void Hosts_outside_the_allowlist_are_dropped(string value)
        => Assert.Null(AvatarPictureHosts.Normalize(value, Allowed));

    /// <summary>
    /// Userinfo appended to the authority must not smuggle an allowed origin.
    /// </summary>
    /// <remarks>
    /// <c>https://images.example@evil.example/x</c> reads as the allowed host
    /// to a human and resolves to <c>evil.example</c> in a browser. Comparing
    /// <see cref="Uri.Authority"/> — which excludes userinfo — is what makes
    /// this fail closed.
    /// </remarks>
    [Fact]
    public void Userinfo_cannot_disguise_a_foreign_host()
        => Assert.Null(AvatarPictureHosts.Normalize(
            "https://images.example@evil.example/portrait.png", Allowed));

    /// <summary>
    /// With nothing configured, no avatar is fetched from anywhere.
    /// </summary>
    /// <remarks>
    /// This is the shipped default. A deployment that never configures an
    /// origin renders initials for every account and makes no outbound request
    /// on the operator's behalf — the feature is opt-in, not opt-out.
    /// </remarks>
    [Fact]
    public void An_empty_allowlist_rejects_everything()
        => Assert.Null(AvatarPictureHosts.Normalize(
            "https://images.example/portrait.png", []));

    [Fact]
    public void An_allowed_origin_is_returned()
    {
        const string value = "https://cdn.example/a-/portrait";
        Assert.Equal(value, AvatarPictureHosts.Normalize(value, Allowed));
    }

    /// <summary>
    /// Origin comparison ignores case in the host, as DNS does.
    /// </summary>
    [Fact]
    public void Host_casing_does_not_change_the_verdict()
        => Assert.NotNull(AvatarPictureHosts.Normalize(
            "https://CDN.Example/portrait.png", Allowed));
}
