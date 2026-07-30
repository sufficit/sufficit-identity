using System.Security.Claims;
using Microsoft.Extensions.Options;
using Sufficit.Identity.Management;
using Sufficit.Identity.Management.Authorization;
using Sufficit.Identity.Server.Management;
using Xunit;

namespace Sufficit.Identity.Tests;

public sealed class ManagementApplicationAuthorizationTests
{
    [Fact]
    public async Task Configured_provider_operator_role_receives_all_capabilities()
    {
        var evaluator = CreateEvaluator(operatorRoles: ["provider-operator"]);
        var principal = PrincipalWithRole("provider-operator");

        foreach (var capability in ManagementCapabilities.All)
        {
            var decision = await evaluator.EvaluateAsync(
                principal,
                capability,
                new ManagementResource(ManagementResourceTypes.UserCollection));

            Assert.True(decision.IsAllowed, capability);
        }
    }

    [Fact]
    public async Task OAuth_scope_grants_only_the_exact_provider_capability()
    {
        var evaluator = CreateEvaluator();
        var principal = PrincipalWithClaims(
            new Claim(
                "scope",
                $"{ManagementCapabilities.UsersRead} unrelated.scope"));

        var allowed = await evaluator.EvaluateAsync(
            principal,
            ManagementCapabilities.UsersRead,
            new ManagementResource(ManagementResourceTypes.UserCollection));
        var denied = await evaluator.EvaluateAsync(
            principal,
            ManagementCapabilities.UsersCreate,
            new ManagementResource(ManagementResourceTypes.UserCollection));

        Assert.True(allowed.IsAllowed);
        Assert.Equal(
            ManagementAuthorizationOutcome.Denied,
            denied.Outcome);
        Assert.Equal("capability_not_granted", denied.ReasonCode);
    }

    [Fact]
    public async Task Unknown_capability_is_denied_even_when_present_as_a_claim()
    {
        const string unknownCapability = "identity.business-role.manage";
        var evaluator = CreateEvaluator();

        var decision = await evaluator.EvaluateAsync(
            PrincipalWithClaims(
                new Claim("permission", unknownCapability)),
            unknownCapability,
            new ManagementResource(ManagementResourceTypes.UserCollection));

        Assert.Equal(
            ManagementAuthorizationOutcome.Denied,
            decision.Outcome);
        Assert.Equal("capability_not_granted", decision.ReasonCode);
    }

    [Fact]
    public async Task Configured_mfa_returns_step_up_until_evidence_is_present()
    {
        var evaluator = CreateEvaluator(
            requireMfa: true,
            operatorRoles: ["provider-operator"]);

        var withoutMfa = await evaluator.EvaluateAsync(
            PrincipalWithRole("provider-operator"),
            ManagementCapabilities.ClientsDelete,
            new ManagementResource(ManagementResourceTypes.Client));
        var withMfa = await evaluator.EvaluateAsync(
            PrincipalWithRole(
                "provider-operator",
                new Claim("amr", "pwd mfa")),
            ManagementCapabilities.ClientsDelete,
            new ManagementResource(ManagementResourceTypes.Client));

        Assert.Equal(
            ManagementAuthorizationOutcome.StepUpRequired,
            withoutMfa.Outcome);
        Assert.True(withMfa.IsAllowed);
    }

    [Fact]
    public async Task Unauthenticated_operator_is_denied()
    {
        var evaluator = CreateEvaluator();

        var decision = await evaluator.EvaluateAsync(
            new ClaimsPrincipal(new ClaimsIdentity()),
            ManagementCapabilities.UsersRead,
            new ManagementResource(ManagementResourceTypes.UserCollection));

        Assert.Equal(
            ManagementAuthorizationOutcome.Denied,
            decision.Outcome);
        Assert.Equal("operator_not_authenticated", decision.ReasonCode);
    }

    [Fact]
    public async Task Sufficit_host_maps_only_administrator_to_provider_operator()
    {
        var resolver = new SufficitOperatorManagementEntitlementResolver(
            Options.Create(new ManagementOptions()));

        var manager = await resolver.ResolveAsync(
            PrincipalWithRole(
                "manager",
                new Claim("directive", "clientadmin:tenant-1")));
        var administrator = await resolver.ResolveAsync(
            PrincipalWithRole("administrator"));

        Assert.Empty(manager.Capabilities);
        Assert.Equal(
            ManagementCapabilities.All.Order(StringComparer.Ordinal),
            administrator.Capabilities.Order(StringComparer.Ordinal));
    }

    private static CapabilityManagementAuthorizationEvaluator CreateEvaluator(
        bool requireMfa = false,
        string[]? operatorRoles = null)
    {
        var options = Options.Create(new ManagementOptions
        {
            RequireMfa = requireMfa,
            Authorization = new ManagementAuthorizationOptions
            {
                OperatorRoles = operatorRoles ?? ["identity-administrator"]
            }
        });
        return new CapabilityManagementAuthorizationEvaluator(
            new ScopeAndRoleManagementEntitlementResolver(options),
            new ConfigurationManagementAccessPolicyProvider(options));
    }

    private static ClaimsPrincipal PrincipalWithRole(
        string role,
        params Claim[] additionalClaims) =>
        PrincipalWithClaims(
            new Claim(ClaimTypes.Role, role),
            additionalClaims);

    private static ClaimsPrincipal PrincipalWithClaims(
        Claim firstClaim,
        params Claim[] additionalClaims) =>
        new(new ClaimsIdentity(
            [
                new Claim(ClaimTypes.NameIdentifier, "operator-1"),
                firstClaim,
                .. additionalClaims
            ],
            authenticationType: "test",
            nameType: ClaimTypes.Name,
            roleType: ClaimTypes.Role));
}
