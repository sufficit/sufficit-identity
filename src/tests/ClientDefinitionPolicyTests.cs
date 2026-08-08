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
    public void Shared_validator_rejects_public_authorization_code_without_pkce()
    {
        var result = CreateValidator().Validate(new ClientDefinitionRequest(
            ClientDefinitionSource.Provisioning,
            "public-web",
            "public",
            ["authorization_code"],
            ["openid"],
            [new Uri("https://client.example.invalid/callback")],
            RequirePkce: false,
            HasClientSecret: false));

        Assert.False(result.IsValid);
        Assert.Contains(result.Issues, issue => issue.Code is "pkce_required");
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
