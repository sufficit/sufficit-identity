using System.Security.Claims;
using OpenIddict.Abstractions;
using Sufficit.Identity.STS;
using Xunit;

namespace Sufficit.Identity.Tests;

public sealed class AuthorizationReauthenticationPolicyTests
{
    private static readonly DateTimeOffset Now =
        new(2026, 9, 9, 18, 0, 0, TimeSpan.Zero);

    [Fact]
    public void Request_without_max_age_accepts_the_existing_session()
    {
        var request = new OpenIddictRequest();
        var principal = PrincipalAuthenticatedAt(Now.AddDays(-1));

        Assert.False(AuthorizationReauthenticationPolicy.IsRequired(
            request,
            principal,
            Now));
    }

    [Fact]
    public void Zero_max_age_always_requires_a_new_ceremony_without_receipt()
    {
        Assert.True(AuthorizationReauthenticationPolicy.IsRequired(
            new OpenIddictRequest { MaxAge = 0 }, PrincipalAuthenticatedAt(Now), Now));
    }

    [Theory]
    [InlineData(899, false)]
    [InlineData(900, false)]
    [InlineData(901, true)]
    public void Max_age_uses_authentication_time_not_token_time(
        int ageSeconds,
        bool expected)
    {
        var request = new OpenIddictRequest { MaxAge = 900 };
        var principal = PrincipalAuthenticatedAt(
            Now.AddSeconds(-ageSeconds));

        Assert.Equal(
            expected,
            AuthorizationReauthenticationPolicy.IsRequired(
                request,
                principal,
                Now));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("not-a-date")]
    [InlineData("9223372036854775807")]
    public void Missing_or_invalid_authentication_time_fails_closed(
        string? authenticationTime)
    {
        var request = new OpenIddictRequest { MaxAge = 900 };
        var claims = authenticationTime is null
            ? Array.Empty<Claim>()
            : [new Claim("auth_time", authenticationTime)];
        var principal = new ClaimsPrincipal(
            new ClaimsIdentity(claims, "test"));

        Assert.True(AuthorizationReauthenticationPolicy.IsRequired(
            request,
            principal,
            Now));
    }

    private static ClaimsPrincipal PrincipalAuthenticatedAt(
        DateTimeOffset authenticatedAt) =>
        new(new ClaimsIdentity(
            [new Claim("auth_time", authenticatedAt.ToUnixTimeSeconds().ToString())],
            "test"));
}
