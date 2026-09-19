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

    [Fact]
    public void Prompt_login_always_requires_a_new_ceremony_without_receipt()
    {
        Assert.True(AuthorizationReauthenticationPolicy.IsRequired(
            new OpenIddictRequest
            {
                Prompt = OpenIddictConstants.PromptValues.Login,
            },
            PrincipalAuthenticatedAt(Now),
            Now));
    }

    [Fact]
    public void A_remembered_second_factor_requires_the_ceremony()
    {
        // Owner's decision, 2026-09-20: a trusted-device cookie operates
        // Management but does not mint tokens. The ceremony runs here rather
        // than leaving the relying party to reject an insufficient token —
        // an app that checks amr and redirects without prompt=login would
        // otherwise get the same session and the same token forever.
        var remembered = new ClaimsPrincipal(new ClaimsIdentity(
            [
                new Claim("amr", "pwd"),
                new Claim("amr", "mfa"),
                new Claim("auth_time", Now.ToUnixTimeSeconds().ToString()),
                new Claim(
                    Sufficit.Identity.Application.Security.MfaEvidencePolicy
                        .RememberedSecondFactorClaimType,
                    "true"),
            ],
            "test"));

        Assert.True(AuthorizationReauthenticationPolicy.IsRequired(
            new OpenIddictRequest(),
            remembered,
            Now));
    }

    [Fact]
    public void A_second_factor_presented_in_this_session_does_not()
    {
        // The other half of the loop guard: once the ceremony has run, the
        // session that comes back has no mark, so the next pass does nothing
        // and the request proceeds.
        var fresh = new ClaimsPrincipal(new ClaimsIdentity(
            [
                new Claim("amr", "pwd"),
                new Claim("amr", "otp"),
                new Claim("amr", "mfa"),
                new Claim("auth_time", Now.ToUnixTimeSeconds().ToString()),
            ],
            "test"));

        Assert.False(AuthorizationReauthenticationPolicy.IsRequired(
            new OpenIddictRequest(),
            fresh,
            Now));
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
