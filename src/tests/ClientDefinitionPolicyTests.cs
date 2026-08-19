using Sufficit.Identity.Application.Security;
using Xunit;

namespace Sufficit.Identity.Tests;

public sealed class ClientDefinitionPolicyTests
{
    private static IClientDefinitionValidator CreateValidator() =>
        new ClientDefinitionValidator(
            new ReservedScopePolicy(["identity.management", "scim"]));

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

    [Fact]
    public void Provisioning_can_authorize_a_reserved_service_scope_explicitly()
    {
        var result = CreateValidator().Validate(new ClientDefinitionRequest(
            ClientDefinitionSource.Provisioning,
            "sufficit_landing_pages_vault",
            "confidential",
            ["client_credentials"],
            ["identity.management"],
            [],
            RequirePkce: false,
            HasClientSecret: true,
            ActorSubject: "operator-1",
            AuthorizeSensitiveTransitions: true));

        Assert.DoesNotContain(result.Issues, issue => issue.Code is "scope_reserved");
        Assert.True(result.IsValid);
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
