using System.Security.Claims;
using OpenIddict.Abstractions;
using Sufficit.Identity.STS;
using Xunit;
using Sufficit.Identity.Application.Security;

namespace Sufficit.Identity.Tests;

public sealed class AuthorizationReauthenticationPolicyTests
{
    /// <summary>
    /// The deployment's real spelling of assurance levels, so a test that
    /// passes an acr_values is asking for something the server recognises.
    /// </summary>
    private static readonly IAuthenticationContextClassMapper Classes =
        new ConfigurableAuthenticationContextClassMapper(
            new AuthenticationContextOptions());

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
            Now,
            Classes));
    }

    [Fact]
    public void Zero_max_age_always_requires_a_new_ceremony_without_receipt()
    {
        Assert.True(AuthorizationReauthenticationPolicy.IsRequired(
            new OpenIddictRequest { MaxAge = 0 }, PrincipalAuthenticatedAt(Now), Now,
            Classes));
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
            Now,
            Classes));
    }

    [Theory]
    // Asking for what the session already has changes nothing.
    [InlineData("urn:identity:acr:loa1", "Loa1", false)]
    [InlineData("urn:identity:acr:loa2", "Loa2", false)]
    // A phishing-resistant session is above loa3, which is the strongest
    // level this server lets a client ask for.
    [InlineData("urn:identity:acr:loa3", "PhishingResistant", false)]
    // Asking for more than the session has runs the ceremony.
    [InlineData("urn:identity:acr:loa2", "Loa1", true)]
    [InlineData("urn:identity:acr:loa3", "Loa2", true)]
    // The strongest recognised value in the list is the one that counts, and
    // a vocabulary this deployment does not speak is ignored rather than
    // refused: acr_values is voluntary (OIDC Core 3.1.2.1).
    [InlineData("urn:identity:acr:loa1 urn:identity:acr:loa3", "Loa2", true)]
    [InlineData("urn:example:gold urn:identity:acr:loa1", "Loa1", false)]
    [InlineData("urn:example:gold", "Loa1", false)]
    [InlineData("", "Loa1", false)]
    public void Acr_values_asks_for_an_assurance_level(
        string acrValues,
        string sessionLevel,
        bool expected)
    {
        var principal = new ClaimsPrincipal(new ClaimsIdentity(
            [
                new Claim("auth_time", Now.ToUnixTimeSeconds().ToString()),
                new Claim("aal", sessionLevel),
            ],
            "test"));

        Assert.Equal(
            expected,
            AuthorizationReauthenticationPolicy.IsRequired(
                new OpenIddictRequest { AcrValues = acrValues },
                principal,
                Now,
                Classes));
    }

    [Fact]
    public void Every_advertised_acr_value_can_be_asked_for()
    {
        // Discovery promises acr_values_supported; a value the policy cannot
        // parse would be advertised and then silently ignored.
        foreach (var level in new[]
        {
            CaepAssuranceLevel.Loa1,
            CaepAssuranceLevel.Loa2,
            CaepAssuranceLevel.Loa3,
        })
        {
            Assert.Equal(level, Classes.Parse(Classes.Map(level)));
        }
    }

    [Fact]
    public void A_session_without_an_assurance_level_is_treated_as_the_floor()
    {
        // Same answer an unauthenticated principal would get: assume nothing.
        var principal = new ClaimsPrincipal(new ClaimsIdentity(
            [new Claim("auth_time", Now.ToUnixTimeSeconds().ToString())],
            "test"));

        Assert.True(AuthorizationReauthenticationPolicy.IsRequired(
            new OpenIddictRequest { AcrValues = "urn:identity:acr:loa2" },
            principal,
            Now,
            Classes));
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
            Now,
            Classes));
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
            Now,
            Classes));
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
                Now,
            Classes));
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
            Now,
            Classes));
    }

    private static ClaimsPrincipal PrincipalAuthenticatedAt(
        DateTimeOffset authenticatedAt) =>
        new(new ClaimsIdentity(
            [new Claim("auth_time", authenticatedAt.ToUnixTimeSeconds().ToString())],
            "test"));
}
