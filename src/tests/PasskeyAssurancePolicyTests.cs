using System.Text.Json;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Sufficit.Identity.Application.Accounts;
using Sufficit.Identity.STS;
using Sufficit.Identity.Tests.Infrastructure;
using Xunit;

namespace Sufficit.Identity.Tests;

public sealed class PasskeyAssurancePolicyTests
{
    private const byte UserPresent = 0x01;
    private const byte UserVerified = 0x04;

    /// <summary>
    /// A minimal WebAuthn assertion: 32 bytes of rpIdHash, the flags byte,
    /// then the signature counter (WebAuthn Level 3, 6.1).
    /// </summary>
    private static string Assertion(byte flags)
    {
        var authenticatorData = new byte[37];
        authenticatorData[32] = flags;
        return JsonSerializer.Serialize(new
        {
            id = "credential",
            type = "public-key",
            response = new
            {
                authenticatorData = Base64UrlTextEncoder.Encode(authenticatorData),
                clientDataJSON = Base64UrlTextEncoder.Encode([1, 2, 3]),
                signature = Base64UrlTextEncoder.Encode([4, 5, 6]),
            },
        });
    }

    [Fact]
    public void Possession_alone_does_not_claim_a_second_factor()
    {
        var policy = new PasskeyAssurancePolicy(new AccountPasskeyOptions());

        var touched = policy.Read(Assertion(UserPresent));
        Assert.NotNull(touched);
        Assert.True(touched.Value.UserPresent);
        Assert.False(touched.Value.UserVerified);
        // amr=mfa asserts that a second, different factor was presented. An
        // authenticator that only confirmed somebody touched it proved one.
        Assert.DoesNotContain("mfa", policy.AuthenticationMethods(touched.Value));
        Assert.Contains("hwk", policy.AuthenticationMethods(touched.Value));

        var verified = policy.Read(Assertion(UserPresent | UserVerified));
        Assert.NotNull(verified);
        Assert.True(verified.Value.UserVerified);
        Assert.Contains("mfa", policy.AuthenticationMethods(verified.Value));
    }

    [Fact]
    public void User_verification_is_required_by_default_and_can_be_relaxed()
    {
        var strict = new PasskeyAssurancePolicy(new AccountPasskeyOptions());
        Assert.True(strict.RequireUserVerification);
        Assert.Equal("required", strict.UserVerificationRequirement);

        var relaxed = new PasskeyAssurancePolicy(
            new AccountPasskeyOptions { RequireUserVerification = false });
        Assert.False(relaxed.RequireUserVerification);
        Assert.Equal("preferred", relaxed.UserVerificationRequirement);
    }

    [Theory]
    [InlineData("")]
    [InlineData("not json")]
    [InlineData("{}")]
    [InlineData("""{"response":{}}""")]
    [InlineData("""{"response":{"authenticatorData":"AAAA"}}""")]
    public void An_unreadable_assertion_reports_nothing_rather_than_guessing(
        string credentialJson) =>
        Assert.Null(
            new PasskeyAssurancePolicy(new AccountPasskeyOptions())
                .Read(credentialJson));
}

[Collection(StsCollection.Name)]
public sealed class PasskeyAssuranceCompositionTests(
    SufficitIdentityTestFactory factory)
{
    [Fact]
    public async Task Sign_in_refuses_an_assertion_that_proved_only_possession()
    {
        using var scope = factory.Services.CreateScope();
        var passkeys = scope.ServiceProvider
            .GetRequiredService<IPasskeyAuthenticationService>();

        // Touched, not verified. The refusal happens before the ceremony runs,
        // so nothing is issued and there is no cookie to undo afterwards.
        var authenticatorData = new byte[37];
        authenticatorData[32] = 0x01;
        var result = await passkeys.SignInAsync(JsonSerializer.Serialize(new
        {
            id = "credential",
            type = "public-key",
            response = new
            {
                authenticatorData = Base64UrlTextEncoder.Encode(authenticatorData),
                clientDataJSON = Base64UrlTextEncoder.Encode([1, 2, 3]),
                signature = Base64UrlTextEncoder.Encode([4, 5, 6]),
            },
        }));

        Assert.False(result.Succeeded);
        Assert.Contains(
            result.Errors,
            error => error.Code == "passkey-user-verification-required");
    }

    [Fact]
    public void The_ceremony_is_asked_for_the_evidence_the_server_claims()
    {
        using var scope = factory.Services.CreateScope();
        var services = scope.ServiceProvider;

        var policy = services.GetRequiredService<IPasskeyAssurancePolicy>();
        Assert.True(policy.RequireUserVerification);

        // Identity puts this into the request options the browser hands to the
        // authenticator. Its own default is already "required", which is why
        // the defect was never visible in the ceremony — what was missing is
        // that nothing tied the value to the claim the server makes, so
        // relaxing one would silently leave the other asserting mfa.
        var passkeys = services
            .GetRequiredService<IOptions<IdentityPasskeyOptions>>()
            .Value;
        Assert.Equal(
            policy.UserVerificationRequirement,
            passkeys.UserVerificationRequirement);
        Assert.Equal("required", passkeys.UserVerificationRequirement);
    }

    [Fact]
    public void Relaxing_the_option_relaxes_the_ceremony_and_the_claim()
    {
        var relaxed = new AccountPasskeyOptions { RequireUserVerification = false };
        var policy = new PasskeyAssurancePolicy(relaxed);

        var services = new ServiceCollection();
        services.Configure<IdentityPasskeyOptions>(passkeys =>
            passkeys.UserVerificationRequirement =
                new PasskeyAssurancePolicy(relaxed).UserVerificationRequirement);

        var configured = services.BuildServiceProvider()
            .GetRequiredService<IOptions<IdentityPasskeyOptions>>()
            .Value;

        // Both move together: the ceremony stops demanding the factor and the
        // server stops claiming it.
        Assert.Equal("preferred", configured.UserVerificationRequirement);
        Assert.DoesNotContain(
            "mfa",
            policy.AuthenticationMethods(new PasskeyAssertionEvidence(
                UserPresent: true,
                UserVerified: false)));
    }
}
