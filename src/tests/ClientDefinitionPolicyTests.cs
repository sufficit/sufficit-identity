using Sufficit.Identity.Application.Security;
using Xunit;

namespace Sufficit.Identity.Tests;

public sealed class ClientDefinitionPolicyTests
{
    private static IClientDefinitionValidator CreateValidator() =>
        new ClientDefinitionValidator(
            new ReservedScopePolicy(["identity.management", "scim"]));

    private sealed class LegacyGrants(bool password) : ILegacyGrantAvailability
    {
        public bool PasswordGrantEnabled { get; } = password;
    }

    private static ClientDefinitionRequest GrantRequest(string grantType) =>
        new(
            ClientDefinitionSource.Management,
            "legacy-grant-client",
            "confidential",
            [grantType],
            [],
            [],
            RequirePkce: false,
            HasClientSecret: true);

    [Theory]
    [InlineData("implicit")]
    [InlineData("gt:implicit")]
    public void Shared_validator_never_accepts_the_implicit_grant(string grantType)
    {
        // Removed from OAuth 2.1 and from this server. Advertising it as
        // supported invited a client definition the runtime would refuse.
        foreach (var validator in new[]
        {
            CreateValidator(),
            new ClientDefinitionValidator(
                new ReservedScopePolicy([]),
                legacyGrants: new LegacyGrants(password: true)),
        })
        {
            var result = validator.Validate(GrantRequest(grantType));
            Assert.False(result.IsValid);
            Assert.Contains(result.Issues, issue =>
                issue.Code is "unsupported_grant_type");
        }
    }

    [Theory]
    [InlineData("password")]
    [InlineData("gt:password")]
    public void Shared_validator_gates_the_password_grant_on_the_deployment(
        string grantType)
    {
        var refused = new ClientDefinitionValidator(
                new ReservedScopePolicy([]),
                legacyGrants: new LegacyGrants(password: false))
            .Validate(GrantRequest(grantType));
        Assert.False(refused.IsValid);
        Assert.Contains(refused.Issues, issue =>
            issue.Code is "unsupported_grant_type");

        // No availability declared at all is the same answer: the validator
        // must not accept a legacy grant merely because nobody said otherwise.
        var byDefault = CreateValidator().Validate(GrantRequest(grantType));
        Assert.False(byDefault.IsValid);
        Assert.Contains(byDefault.Issues, issue =>
            issue.Code is "unsupported_grant_type");

        var allowed = new ClientDefinitionValidator(
                new ReservedScopePolicy([]),
                legacyGrants: new LegacyGrants(password: true))
            .Validate(GrantRequest(grantType));
        Assert.DoesNotContain(allowed.Issues, issue =>
            issue.Code is "unsupported_grant_type");
    }

    [Fact]
    public void Shared_validator_rejects_reserved_scope_and_public_client_credentials()
    {
        var result = CreateValidator().Validate(new ClientDefinitionRequest(
            ClientDefinitionSource.Management,
            "public-service",
            "public",
            ["client_credentials"],
            ["identity.management"],
            [],
            RequirePkce: false,
            HasClientSecret: false));

        Assert.False(result.IsValid);
        Assert.Contains(result.Issues, issue =>
            issue.Code is "scope_reserved");
        Assert.Contains(result.Issues, issue =>
            issue.Code is "client_credentials_requires_confidential");
    }

    [Theory]
    [InlineData("public", "authorization_code", true)]
    [InlineData("confidential", "authorization_code", true)]
    [InlineData("public", "refresh_token", false)]
    [InlineData("confidential", "client_credentials", false)]
    public void Shared_validator_projects_pkce_from_grant_independent_of_client_type(
        string clientType,
        string grantType,
        bool requiresPkce)
    {
        var validator = CreateValidator();
        var result = validator.Validate(new ClientDefinitionRequest(
            ClientDefinitionSource.Provisioning,
            "matrix-client",
            clientType,
            [grantType],
            ["openid"],
            [],
            RequirePkce: false,
            HasClientSecret: clientType == "confidential"));

        Assert.Equal(
            requiresPkce,
            validator.RequiresProofKeyForCodeExchange([grantType]));
        Assert.Equal(
            requiresPkce,
            result.Issues.Any(issue => issue.Code is "pkce_required"));
    }

    [Fact]
    public void Shared_validator_honors_dynamic_source_allow_lists()
    {
        var result = CreateValidator().Validate(new ClientDefinitionRequest(
            ClientDefinitionSource.DynamicRegistration,
            null,
            "confidential",
            ["client_credentials"],
            ["profile", "unlisted"],
            [],
            RequirePkce: false,
            HasClientSecret: true,
            AllowedGrantTypes: new HashSet<string>(
                ["authorization_code"],
                StringComparer.Ordinal),
            AllowedScopes: new HashSet<string>(
                ["profile"],
                StringComparer.Ordinal)));

        Assert.False(result.IsValid);
        Assert.Contains(result.Issues, issue =>
            issue.Code is "grant_type_not_allowed");
        Assert.Contains(result.Issues, issue =>
            issue.Code is "scope_not_allowed");
    }

    [Fact]
    public void Shared_scope_grant_policy_rejects_offline_access_without_refresh()
    {
        var result = CreateValidator().Validate(new ClientDefinitionRequest(
            ClientDefinitionSource.Management,
            "interactive",
            "public",
            ["authorization_code"],
            ["openid", "offline_access"],
            [new Uri("https://client.example.invalid/callback")],
            RequirePkce: true,
            HasClientSecret: false));

        Assert.Contains(result.Issues, issue =>
            issue.Code is "offline_access_requires_refresh_token");
    }
}
