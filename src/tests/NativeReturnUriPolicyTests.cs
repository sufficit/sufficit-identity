using Sufficit.Identity.Application.Accounts;
using Xunit;

namespace Sufficit.Identity.Tests;

public sealed class NativeReturnUriPolicyTests
{
    [Theory]
    // A private-use URI scheme is the mechanism RFC 8252 section 7.1 defines
    // for native applications, and the value survives verbatim.
    [InlineData("example-app://auth-complete")]
    [InlineData("com.example.app:/oauth/done")]
    [InlineData("https://app.example.com/auth-complete")]
    [InlineData("http://127.0.0.1:8765/done")]
    [InlineData("http://localhost:8765/done")]
    public void Registration_accepts_tokenless_callbacks(string candidate)
    {
        Assert.True(NativeReturnUriPolicy.TryValidateRegistration(
            candidate,
            out var normalized,
            out _,
            out _));
        Assert.Equal(candidate, normalized);
    }

    [Theory]
    [InlineData("", "native_return_uri_invalid")]
    [InlineData("   ", "native_return_uri_invalid")]
    [InlineData("/relative/only", "native_return_uri_invalid")]
    [InlineData("example-app://done#fragment", "native_return_uri_fragment")]
    [InlineData("javascript:alert(1)", "native_return_uri_scheme_denied")]
    [InlineData("data:text/html,<script>", "native_return_uri_scheme_denied")]
    [InlineData("file:///etc/passwd", "native_return_uri_scheme_denied")]
    [InlineData("http://attacker.example/", "native_return_uri_https_required")]
    public void Registration_rejects_unsafe_or_malformed_callbacks(
        string candidate,
        string expectedReason)
    {
        Assert.False(NativeReturnUriPolicy.TryValidateRegistration(
            candidate,
            out var normalized,
            out var reasonCode,
            out _));
        Assert.Null(normalized);
        Assert.Equal(expectedReason, reasonCode);
    }

    [Fact]
    public void Registration_rejects_a_callback_past_the_length_bound()
    {
        var candidate = "example-app://"
            + new string('a', NativeReturnUriPolicy.MaximumLength);

        Assert.False(NativeReturnUriPolicy.TryValidateRegistration(
            candidate,
            out _,
            out var reasonCode,
            out _));
        Assert.Equal("native_return_uri_too_long", reasonCode);
    }

    [Theory]
    // RFC 8252 section 8.1: simple string comparison against the registration.
    [InlineData("example-app://auth-complete", "example-app://auth-complete")]
    [InlineData("  example-app://auth-complete  ", "example-app://auth-complete")]
    [InlineData("EXAMPLE-APP://auth-complete", null)]
    [InlineData("example-app://auth-complete/extra", null)]
    [InlineData("example-app://auth-complete?x=1", null)]
    [InlineData("other-app://auth-complete", null)]
    [InlineData("", null)]
    public void Match_requires_an_exact_registered_value(
        string candidate,
        string? expected) =>
        Assert.Equal(
            expected,
            NativeReturnUriPolicy.Match(
                ["example-app://auth-complete"],
                candidate));

    [Fact]
    public void Match_returns_nothing_when_the_client_registered_nothing() =>
        Assert.Null(NativeReturnUriPolicy.Match([], "example-app://auth-complete"));
}
