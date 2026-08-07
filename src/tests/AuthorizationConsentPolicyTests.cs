using Sufficit.Identity.STS.Consent;
using Xunit;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Sufficit.Identity.Tests;

public sealed class AuthorizationConsentPolicyTests
{
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("legacy-unknown")]
    public void Unknown_or_missing_type_requires_interactive_consent(
        string? consentType)
    {
        Assert.Equal(
            AuthorizationConsentRequirement.Interactive,
            AuthorizationConsentPolicy.Evaluate(
                consentType,
                hasExistingAuthorization: true,
                forcesReconsent: false));
    }

    [Theory]
    [InlineData(false, false, true)]
    [InlineData(true, false, false)]
    [InlineData(true, true, true)]
    public void Explicit_type_observes_authorization_and_reconsent(
        bool hasExistingAuthorization,
        bool forcesReconsent,
        bool expectsInteraction)
    {
        Assert.Equal(
            expectsInteraction
                ? AuthorizationConsentRequirement.Interactive
                : AuthorizationConsentRequirement.None,
            AuthorizationConsentPolicy.Evaluate(
                ConsentTypes.Explicit,
                hasExistingAuthorization,
                forcesReconsent));
    }

    [Fact]
    public void Implicit_type_preserves_the_existing_noninteractive_contract()
    {
        Assert.Equal(
            AuthorizationConsentRequirement.None,
            AuthorizationConsentPolicy.Evaluate(
                ConsentTypes.Implicit,
                hasExistingAuthorization: false,
                forcesReconsent: false));
    }

    [Fact]
    public void Systematic_type_always_requires_interaction()
    {
        Assert.Equal(
            AuthorizationConsentRequirement.Interactive,
            AuthorizationConsentPolicy.Evaluate(
                ConsentTypes.Systematic,
                hasExistingAuthorization: true,
                forcesReconsent: false));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void External_type_requires_a_preexisting_authorization(
        bool hasExistingAuthorization)
    {
        Assert.Equal(
            hasExistingAuthorization
                ? AuthorizationConsentRequirement.None
                : AuthorizationConsentRequirement.ExistingAuthorization,
            AuthorizationConsentPolicy.Evaluate(
                ConsentTypes.External,
                hasExistingAuthorization,
                forcesReconsent: false));
    }
}
