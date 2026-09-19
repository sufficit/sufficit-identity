using System.Net;
using System.Net.Http.Json;
using System.Security.Claims;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;
using Sufficit.Identity.Scim;
using Sufficit.Identity.Tests.Infrastructure;
using Xunit;

namespace Sufficit.Identity.Tests;

/// <summary>
/// SCIM used to be one decision for the whole surface: whoever could
/// provision could also delete every account and set anyone's password. These
/// pin each operation to its own terms.
/// </summary>
public sealed class ScimOperationAuthorizationTests
{
    private const string DestructiveScope = "scim.destructive";

    private static IScimOperationAuthorizationPolicy Policy(
        ScimClientPolicyMode mode = ScimClientPolicyMode.Enforce,
        bool requireMfaForDestructive = true,
        bool requireSenderConstraint = true,
        bool gateMembership = false) =>
        new ScimOperationAuthorizationPolicy(Options.Create(new ScimOptions
        {
            OperationPolicyMode = mode,
            RequireMfaForDestructive = requireMfaForDestructive,
            RequireSenderConstraintForDestructive = requireSenderConstraint,
            RequirePermissionForMembership = gateMembership,
        }));

    private static ClaimsPrincipal Caller(
        string? scope = null,
        bool clientCredentials = false,
        bool mfa = false,
        bool senderConstrained = false)
    {
        var claims = new List<Claim>();
        if (scope is not null)
        {
            claims.Add(new Claim("scope", scope));
        }

        if (clientCredentials)
        {
            claims.Add(new Claim("client_id", "provisioning-client"));
        }
        else
        {
            claims.Add(new Claim("sub", "operator-1"));
        }

        if (mfa)
        {
            claims.Add(new Claim("amr", "pwd mfa"));
        }

        if (senderConstrained)
        {
            claims.Add(new Claim("cnf", """{"jkt":"abc"}"""));
        }

        return new ClaimsPrincipal(new ClaimsIdentity(claims, "test"));
    }

    [Theory]
    [InlineData(ScimOperation.Read)]
    [InlineData(ScimOperation.Provision)]
    public void Reading_and_provisioning_need_nothing_extra(ScimOperation operation) =>
        Assert.True(Policy()
            .Evaluate(operation, Caller(clientCredentials: true))
            .Allowed);

    [Theory]
    [InlineData(ScimOperation.Delete)]
    [InlineData(ScimOperation.PasswordMutation)]
    public void Deleting_and_setting_a_password_need_their_own_scope(
        ScimOperation operation)
    {
        // The whole point: a directory sync that creates and updates accounts
        // needs neither to remove them nor to become their owner.
        var withoutScope = Policy().Evaluate(
            operation,
            Caller(scope: "scim", clientCredentials: true, senderConstrained: true));
        Assert.False(withoutScope.Allowed);
        Assert.Equal("destructive_scope_missing", withoutScope.ReasonCode);

        Assert.True(Policy().Evaluate(
            operation,
            Caller(
                scope: $"scim {DestructiveScope}",
                clientCredentials: true,
                senderConstrained: true)).Allowed);
    }

    [Fact]
    public void An_application_proves_the_token_is_its_own_instead_of_a_second_factor()
    {
        // A client-credentials token has no person behind it and can never
        // carry amr. What it can carry is a binding to a key its holder must
        // prove, so a copy taken from a log is not enough.
        var bearer = Policy().Evaluate(
            ScimOperation.Delete,
            Caller(scope: DestructiveScope, clientCredentials: true));
        Assert.False(bearer.Allowed);
        Assert.Equal("sender_constraint_required", bearer.ReasonCode);

        Assert.True(Policy().Evaluate(
            ScimOperation.Delete,
            Caller(
                scope: DestructiveScope,
                clientCredentials: true,
                senderConstrained: true)).Allowed);

        // A deployment that cannot bind its tokens yet can say so, and the
        // scope still applies.
        Assert.True(Policy(requireSenderConstraint: false).Evaluate(
            ScimOperation.Delete,
            Caller(scope: DestructiveScope, clientCredentials: true)).Allowed);
    }

    [Fact]
    public void A_person_presents_a_second_factor()
    {
        var withoutMfa = Policy().Evaluate(
            ScimOperation.PasswordMutation,
            Caller(scope: DestructiveScope));
        Assert.False(withoutMfa.Allowed);
        Assert.Equal("mfa_required", withoutMfa.ReasonCode);

        Assert.True(Policy().Evaluate(
            ScimOperation.PasswordMutation,
            Caller(scope: DestructiveScope, mfa: true)).Allowed);
    }

    [Fact]
    public void Membership_is_ordinary_provisioning_unless_a_deployment_says_otherwise()
    {
        // A directory sync moves people between groups all day; treating that
        // as destructive by default would break every one of them.
        Assert.True(Policy().Evaluate(
            ScimOperation.MembershipMutation,
            Caller(scope: "scim", clientCredentials: true)).Allowed);

        Assert.False(Policy(gateMembership: true).Evaluate(
            ScimOperation.MembershipMutation,
            Caller(scope: "scim", clientCredentials: true)).Allowed);
    }

    [Fact]
    public void Observe_records_the_refusal_without_making_it()
    {
        // The default, because an existing provisioning client holds neither
        // the scope nor a bound token and would otherwise stop working on
        // upgrade.
        Assert.True(Policy(mode: ScimClientPolicyMode.Observe).Evaluate(
            ScimOperation.Delete,
            Caller(scope: "scim", clientCredentials: true)).Allowed);
    }

    [Fact]
    public async Task Enforced_deletion_is_refused_through_the_endpoint()
    {
        // The policy is consulted by the provisioning service, not by a
        // filter on the route, because what a request does is in its payload.
        // This proves the service actually asks.
        using var parent = new ManagementTestFactory();
        await ((IAsyncLifetime)parent).InitializeAsync();
        using var factory = ScimFactory(parent, enforceOperations: true);
        var client = factory.CreateClient();

        using var created = await client.PostAsJsonAsync(
            "/scim/v2/users",
            new
            {
                schemas = new[] { ScimSchemas.User },
                userName = $"scim-op-{Guid.NewGuid():N}@tests.local",
                active = true,
            });
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        var id = (await created.Content.ReadFromJsonAsync<ScimUserResource>())!.Id;

        using var deleted = await client.DeleteAsync($"/scim/v2/users/{id}");
        Assert.Equal(HttpStatusCode.Forbidden, deleted.StatusCode);
    }

    [Fact]
    public async Task The_same_deletion_succeeds_while_the_policy_observes()
    {
        // The control: nothing else about the request changed.
        using var parent = new ManagementTestFactory();
        await ((IAsyncLifetime)parent).InitializeAsync();
        using var factory = ScimFactory(parent, enforceOperations: false);
        var client = factory.CreateClient();

        using var created = await client.PostAsJsonAsync(
            "/scim/v2/users",
            new
            {
                schemas = new[] { ScimSchemas.User },
                userName = $"scim-op-{Guid.NewGuid():N}@tests.local",
                active = true,
            });
        var id = (await created.Content.ReadFromJsonAsync<ScimUserResource>())!.Id;

        using var deleted = await client.DeleteAsync($"/scim/v2/users/{id}");
        Assert.Equal(HttpStatusCode.NoContent, deleted.StatusCode);
    }

    private static WebApplicationFactory<ManagementTestFactory> ScimFactory(
        ManagementTestFactory parent,
        bool enforceOperations) =>
        parent.WithWebHostBuilder(builder =>
            builder.ConfigureAppConfiguration((_, configuration) =>
                configuration.AddInMemoryCollection(
                    new Dictionary<string, string?>
                    {
                        ["Sufficit:Identity:Scim:Enabled"] = "true",
                        ["Sufficit:Identity:Scim:RequireAuthorization"] = "false",
                        ["Sufficit:Identity:Scim:RequireAllowedClient"] = "false",
                        ["Sufficit:Identity:Scim:RequireMfa"] = "false",
                        ["Sufficit:Identity:Scim:OperationPolicyMode"] =
                            enforceOperations ? "Enforce" : "Observe",
                    })));
}
