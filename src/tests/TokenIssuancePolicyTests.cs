using System.Security.Claims;
using Microsoft.Extensions.Logging.Abstractions;
using OpenIddict.Abstractions;
using Sufficit.Identity.STS;
using Xunit;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Sufficit.Identity.Tests;

public sealed class TokenIssuancePolicyTests
{
    [Fact]
    public void Sensitive_unmapped_claim_is_suppressed_during_compatibility()
    {
        var policy = new ApplicationClaimDestinationPolicy(new ClaimScopeMapOptions
        {
            IncludeUnmappedClaimsInAccessTokens = true,
        });
        var identity = new ClaimsIdentity();
        var claim = new Claim("authenticator_key", "must-not-leak");
        identity.AddClaim(claim);

        Assert.Empty(policy.GetDestinations(claim, includeIdentityToken: true));
    }

    [Fact]
    public void Claim_destination_matrix_keeps_scope_and_token_destinations_separate()
    {
        var policy = new ApplicationClaimDestinationPolicy(new ClaimScopeMapOptions
        {
            ClaimToScope = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["department"] = "profile",
            },
            IncludeUnmappedClaimsInAccessTokens = true,
        });

        var mappedIdentity = new ClaimsIdentity();
        mappedIdentity.AddClaim(new Claim("department", "support"));
        mappedIdentity.SetScopes(Scopes.Profile);
        var mapped = policy.GetDestinations(
            mappedIdentity.FindFirst("department")!,
            includeIdentityToken: true);

        var mappedWithoutScopeIdentity = new ClaimsIdentity();
        mappedWithoutScopeIdentity.AddClaim(new Claim("department", "support"));
        var mappedWithoutScope = policy.GetDestinations(
            mappedWithoutScopeIdentity.FindFirst("department")!,
            includeIdentityToken: true);

        var unmappedIdentity = new ClaimsIdentity();
        unmappedIdentity.AddClaim(new Claim("locale", "pt-BR"));
        var unmapped = policy.GetDestinations(
            unmappedIdentity.FindFirst("locale")!,
            includeIdentityToken: true);

        Assert.Equal(
            [Destinations.AccessToken, Destinations.IdentityToken],
            mapped.ToArray());
        Assert.Empty(mappedWithoutScope);
        Assert.Equal([Destinations.AccessToken], unmapped.ToArray());
    }

    [Fact]
    public void Personal_token_observe_mode_reports_future_denial_without_breaking_scope_shape()
    {
        var policy = CreatePersonalTokenPolicy(new PersonalTokenIssuanceOptions
        {
            Mode = SecurityPolicyEnforcementMode.Observe,
            RequiredScope = "personal_tokens.manage",
            RequireRecentAuthentication = true,
            MaximumLifetimeDays = 30,
        });

        var decision = policy.Evaluate(new PersonalTokenIssuanceContext(
            "subject",
            "legacy-client",
            ["api.read"],
            [Scopes.Profile],
            [Scopes.Profile, Scopes.Email],
            AuthenticationTime: null,
            Now: DateTimeOffset.UnixEpoch,
            Expiration: DateTimeOffset.UnixEpoch.AddDays(90),
            HasSenderConstraint: false));

        Assert.False(decision.ShouldReject);
        Assert.True(decision.WouldReject);
        Assert.Equal([Scopes.Profile], decision.EffectiveScopes);
        Assert.Contains("required_scope_missing", decision.ReasonCodes);
        Assert.Contains("requested_scope_not_delegated", decision.ReasonCodes);
        Assert.Contains("recent_authentication_required", decision.ReasonCodes);
        Assert.Contains("lifetime_exceeds_policy", decision.ReasonCodes);
    }

    [Fact]
    public void Personal_token_enforcement_attenuates_to_caller_and_server_authority()
    {
        var policy = CreatePersonalTokenPolicy(new PersonalTokenIssuanceOptions
        {
            Mode = SecurityPolicyEnforcementMode.Enforce,
            RequiredScope = "personal_tokens.manage",
            RequireRecentAuthentication = true,
            MaximumAuthenticationAgeMinutes = 15,
            MaximumLifetimeDays = 30,
        });
        var now = DateTimeOffset.UtcNow;

        var allowed = policy.Evaluate(new PersonalTokenIssuanceContext(
            "subject",
            "eligible-client",
            ["personal_tokens.manage", Scopes.Profile, "not-server-allowed"],
            [Scopes.Profile],
            [Scopes.Profile, Scopes.Email],
            now.AddMinutes(-2),
            now,
            now.AddDays(7),
            HasSenderConstraint: false));
        var rejected = policy.Evaluate(new PersonalTokenIssuanceContext(
            "subject",
            "eligible-client",
            ["personal_tokens.manage", Scopes.Profile],
            [Scopes.Email],
            [Scopes.Profile, Scopes.Email],
            now.AddMinutes(-2),
            now,
            now.AddDays(7),
            HasSenderConstraint: false));

        Assert.False(allowed.ShouldReject);
        Assert.Equal([Scopes.Profile], allowed.EffectiveScopes);
        Assert.True(rejected.ShouldReject);
        Assert.Equal("invalid_scope", rejected.ErrorCode);
        Assert.Empty(rejected.EffectiveScopes);
    }

    [Fact]
    public void Subject_token_provenance_enforcement_rejects_missing_and_ambiguous_party()
    {
        var policy = new SubjectTokenProvenancePolicy(
            NullLogger<SubjectTokenProvenancePolicy>.Instance);
        var allowedClients = new HashSet<string>(StringComparer.Ordinal) { "source-client" };

        var missing = policy.Evaluate(
            new ClaimsPrincipal(new ClaimsIdentity()),
            allowedClients,
            SecurityPolicyEnforcementMode.Enforce);

        var identity = new ClaimsIdentity();
        identity.SetClaim(Claims.AuthorizedParty, "source-client");
        identity.SetClaim(Claims.ClientId, "different-client");
        var ambiguous = policy.Evaluate(
            new ClaimsPrincipal(identity),
            allowedClients,
            SecurityPolicyEnforcementMode.Enforce);

        Assert.True(missing.ShouldReject);
        Assert.Equal("subject_authorized_party_missing", missing.ReasonCode);
        Assert.True(ambiguous.ShouldReject);
        Assert.Equal("subject_authorized_party_ambiguous", ambiguous.ReasonCode);
    }

    [Fact]
    public void Subject_token_provenance_accepts_single_allowed_party()
    {
        var policy = new SubjectTokenProvenancePolicy(
            NullLogger<SubjectTokenProvenancePolicy>.Instance);
        var identity = new ClaimsIdentity();
        identity.SetClaim(Claims.AuthorizedParty, "source-client");

        var decision = policy.Evaluate(
            new ClaimsPrincipal(identity),
            new HashSet<string>(StringComparer.Ordinal) { "source-client" },
            SecurityPolicyEnforcementMode.Enforce);

        Assert.False(decision.ShouldReject);
        Assert.False(decision.WouldReject);
        Assert.Equal("source-client", decision.AuthorizedParty);
    }

    private static PersonalTokenIssuancePolicy CreatePersonalTokenPolicy(
        PersonalTokenIssuanceOptions options) =>
        new(
            options,
            new TokenIssuancePolicyKernel(),
            NullLogger<PersonalTokenIssuancePolicy>.Instance);
}
