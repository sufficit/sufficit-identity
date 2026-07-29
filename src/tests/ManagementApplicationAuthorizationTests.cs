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
    public async Task Administrator_receives_global_management_capabilities()
    {
        var evaluator = CreateEvaluator();
        var principal = PrincipalWithRole("administrator");

        foreach (var capability in new[]
                 {
                     ManagementCapabilities.ClientsRead,
                     ManagementCapabilities.ClientsCreate,
                     ManagementCapabilities.ClientsDelete,
                     ManagementCapabilities.BrandingRead,
                     ManagementCapabilities.BrandingManage,
                     ManagementCapabilities.UsersRead,
                     ManagementCapabilities.UsersCreate,
                     ManagementCapabilities.UsersUpdate,
                     ManagementCapabilities.UsersDisable,
                     ManagementCapabilities.UsersDelete,
                     ManagementCapabilities.UsersResetPassword,
                     ManagementCapabilities.UsersPermissionsManage,
                     ManagementCapabilities.AuditRead,
                 })
        {
            var decision = await evaluator.EvaluateAsync(
                principal,
                capability,
                new ManagementResource(ManagementResourceTypes.Client));
            Assert.True(decision.IsAllowed, capability);
        }
    }

    [Fact]
    public async Task Manager_is_limited_to_contexts_from_normalized_grants()
    {
        const string allowedContext = "4082aef4-42d3-4b1b-a321-f405af935940";
        var options = Options.Create(new ManagementOptions());
        var resolver = new RoleAndClaimManagementEntitlementResolver(options);
        var evaluator = new RoleBasedManagementAuthorizationEvaluator(
            resolver,
            new ConfigurationManagementAccessPolicyProvider(options));
        var principal = PrincipalWithRole(
            "manager",
            new Claim("management_context", allowedContext));

        var allowed = await evaluator.EvaluateAsync(
            principal,
            ManagementCapabilities.UsersRead,
            new ManagementResource(
                ManagementResourceTypes.UserCollection,
                ContextId: allowedContext));
        var denied = await evaluator.EvaluateAsync(
            principal,
            ManagementCapabilities.UsersRead,
            new ManagementResource(
                ManagementResourceTypes.UserCollection,
                ContextId: "f96802a6-8d90-4143-a939-dd5258f3cfaa"));
        var missing = await evaluator.EvaluateAsync(
            principal,
            ManagementCapabilities.UsersRead,
            new ManagementResource(ManagementResourceTypes.UserCollection));

        Assert.True(allowed.IsAllowed);
        Assert.Equal("capability_not_granted", denied.ReasonCode);
        Assert.Equal("context_required", missing.ReasonCode);
    }

    [Fact]
    public async Task Context_policy_can_require_mfa_without_changing_global_policy()
    {
        const string contextId = "4082aef4-42d3-4b1b-a321-f405af935940";
        var options = Options.Create(new ManagementOptions
        {
            Authorization = new ManagementAuthorizationOptions
            {
                Contexts = new Dictionary<
                    string,
                    ManagementContextAccessPolicyOptions>(
                    StringComparer.OrdinalIgnoreCase)
                {
                    [contextId] = new() { RequireMfa = true }
                }
            }
        });
        var evaluator = new RoleBasedManagementAuthorizationEvaluator(
            new RoleAndClaimManagementEntitlementResolver(options),
            new ConfigurationManagementAccessPolicyProvider(options));

        var decision = await evaluator.EvaluateAsync(
            PrincipalWithRole(
                "manager",
                new Claim("management_context", contextId)),
            ManagementCapabilities.UsersRead,
            new ManagementResource(
                ManagementResourceTypes.UserCollection,
                ContextId: contextId));

        Assert.Equal(
            ManagementAuthorizationOutcome.StepUpRequired,
            decision.Outcome);
    }

    [Fact]
    public async Task Sufficit_adapter_reads_scalar_and_json_directives()
    {
        const string firstContext = "4082aef4-42d3-4b1b-a321-f405af935940";
        const string secondContext = "f96802a6-8d90-4143-a939-dd5258f3cfaa";
        var resolver = new SufficitDirectiveManagementEntitlementResolver(
            Options.Create(new ManagementOptions()));
        var principal = PrincipalWithRole(
            "manager",
            new Claim("directive", $"phonecalls:{firstContext}"),
            new Claim(
                "directive",
                $"[\"clientadmin:{secondContext}\",\"broken\","
                + "\"policyupdate:00000000-0000-0000-0000-000000000000\"]"));

        var grants = await resolver.ResolveAsync(principal);

        Assert.False(grants.HasGlobalAdministratorAccess);
        Assert.Equal(
            new[] { firstContext, secondContext },
            grants.ManagedContextIds.Order(StringComparer.Ordinal));
    }

    [Fact]
    public async Task Sufficit_adapter_never_turns_manager_wildcard_into_global_access()
    {
        var resolver = new SufficitDirectiveManagementEntitlementResolver(
            Options.Create(new ManagementOptions()));
        var manager = await resolver.ResolveAsync(
            PrincipalWithRole(
                "manager",
                new Claim(
                    "directive",
                    "phonecalls:00000000-0000-0000-0000-000000000000")));
        var administrator = await resolver.ResolveAsync(
            PrincipalWithRole("administrator"));

        Assert.False(manager.HasGlobalAdministratorAccess);
        Assert.Empty(manager.ManagedContextIds);
        Assert.True(administrator.HasGlobalAdministratorAccess);
    }

    [Fact]
    public async Task Manager_is_denied_global_client_capabilities()
    {
        var decision = await CreateEvaluator().EvaluateAsync(
            PrincipalWithRole("manager"),
            ManagementCapabilities.ClientsCreate,
            new ManagementResource(ManagementResourceTypes.Client));

        Assert.Equal(ManagementAuthorizationOutcome.Denied, decision.Outcome);
        Assert.Equal("capability_not_granted", decision.ReasonCode);
    }

    [Fact]
    public async Task Configured_mfa_returns_step_up_until_evidence_is_present()
    {
        var evaluator = CreateEvaluator(requireMfa: true);

        var withoutMfa = await evaluator.EvaluateAsync(
            PrincipalWithRole("administrator"),
            ManagementCapabilities.ClientsDelete,
            new ManagementResource(ManagementResourceTypes.Client));
        var withMfa = await evaluator.EvaluateAsync(
            PrincipalWithRole("administrator", new Claim("amr", "pwd mfa")),
            ManagementCapabilities.ClientsDelete,
            new ManagementResource(ManagementResourceTypes.Client));

        Assert.Equal(
            ManagementAuthorizationOutcome.StepUpRequired,
            withoutMfa.Outcome);
        Assert.True(withMfa.IsAllowed);
    }

    private static RoleBasedManagementAuthorizationEvaluator CreateEvaluator(
        bool requireMfa = false)
    {
        var options = Options.Create(new ManagementOptions
        {
            RequireMfa = requireMfa
        });
        return new RoleBasedManagementAuthorizationEvaluator(
            new RoleAndClaimManagementEntitlementResolver(options),
            new ConfigurationManagementAccessPolicyProvider(options));
    }

    private static ClaimsPrincipal PrincipalWithRole(
        string role,
        params Claim[] additionalClaims) =>
        new(new ClaimsIdentity(
            [
                new Claim(ClaimTypes.NameIdentifier, "operator-1"),
                new Claim(ClaimTypes.Role, role),
                .. additionalClaims
            ],
            authenticationType: "test",
            nameType: ClaimTypes.Name,
            roleType: ClaimTypes.Role));
}
