using System.Security.Claims;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using Sufficit.Identity.Management;
using Sufficit.Identity.Management.Authorization;
using Sufficit.Identity.Management.Overview;
using Sufficit.Identity.Server.Management;
using Xunit;

namespace Sufficit.Identity.Tests;

public sealed class ManagementApplicationAuthorizationTests
{
    [Fact]
    public async Task Configured_provider_operator_role_receives_all_capabilities()
    {
        var evaluator = CreateEvaluator(adminRoles: ["provider-operator"]);
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
    public async Task OAuth_scope_never_grants_management_capabilities()
    {
        // M1 fix: the OAuth `scope` claim is a different namespace from
        // management capabilities. A scope value that happens to match a
        // capability string must NOT grant that capability.
        var evaluator = CreateEvaluator();
        var principal = PrincipalWithClaims(
            new Claim(
                "scope",
                $"{ManagementCapabilities.UsersRead} identity.management"));

        var denied = await evaluator.EvaluateAsync(
            principal,
            ManagementCapabilities.UsersRead,
            new ManagementResource(ManagementResourceTypes.UserCollection));

        Assert.False(denied.IsAllowed);
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
            adminRoles: ["provider-operator"]);

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

    [Fact]
    public async Task Overview_projects_runtime_modules_and_effective_access()
    {
        var options = Options.Create(new ManagementOptions
        {
            RoutePrefix = "/management-api/",
            RequiredScope = "identity_management",
            RequireMfa = false
        });
        var resolver = new ScopeAndRoleManagementEntitlementResolver(options);
        var accessPolicies =
            new ConfigurationManagementAccessPolicyProvider(options);
        var evaluator = new CapabilityManagementAuthorizationEvaluator(
            resolver,
            accessPolicies,
            new DefaultManagementObjectAccessPolicy());
        var service = new ManagementOverviewService(
            resolver,
            accessPolicies,
            evaluator,
            options,
            new TestHostEnvironment());

        var overview = await service.GetAsync(
            new ManagementRequestContext(
                PrincipalWithClaims(new Claim(
                    "permission",
                    ManagementCapabilities.UsersRead)),
                "overview-test"));

        Assert.Equal("Test", overview.EnvironmentName);
        Assert.Equal("management-api", overview.Api.RoutePrefix);
        Assert.Equal("identity_management", overview.Api.RequiredScope);
        Assert.Equal(
            [ManagementCapabilities.UsersRead],
            overview.Operator.Capabilities);
        Assert.True(overview.Modules.Single(
            module => module.Key == "users").CanAccess);
        Assert.False(overview.Modules.Single(
            module => module.Key == "clients").CanAccess);
        var provisioning = overview.Modules.Single(
            module => module.Key == "provisioning");
        Assert.True(provisioning.IsAvailable);
        Assert.Equal(
            ManagementCapabilities.ProvisioningPreview,
            provisioning.RequiredCapability);
        Assert.False(provisioning.CanAccess);
        Assert.Equal(
            "capability_not_granted",
            provisioning.ReasonCode);
    }

    // ---- H3: object-level authorization boundary (IManagementObjectAccessPolicy) ----

    [Fact]
    public async Task Object_access_policy_default_is_permissive()
    {
        // With the shipped default policy, a capable operator is allowed against
        // any resource (regression: the new boundary must not change behavior
        // until a deployment opts into a non-permissive impl).
        var evaluator = CreateEvaluator(adminRoles: ["identity-administrator"]);
        var principal = PrincipalWithRole("identity-administrator");

        var decision = await evaluator.EvaluateAsync(
            principal,
            ManagementCapabilities.UsersRead,
            new ManagementResource(ManagementResourceTypes.User, "user-123"));

        Assert.Equal(ManagementAuthorizationOutcome.Allowed, decision.Outcome);
    }

    [Fact]
    public async Task Object_access_policy_denial_takes_precedence_after_capability_and_mfa()
    {
        // A non-permissive object policy returning Denied is surfaced unchanged
        // by the evaluator, with the policy's own ReasonCode — proving the
        // boundary is consulted and respected (the foundation for BOLA/tenant
        // scoping). Capability + MFA still pass; only the object check denies.
        var evaluator = CreateEvaluator(
            adminRoles: ["identity-administrator"],
            objectAccess: new DenyingObjectAccessPolicy("object_not_accessible"));
        var principal = PrincipalWithRole("identity-administrator");

        var decision = await evaluator.EvaluateAsync(
            principal,
            ManagementCapabilities.UsersDelete,
            new ManagementResource(ManagementResourceTypes.User, "other-tenant-user"));

        Assert.Equal(ManagementAuthorizationOutcome.Denied, decision.Outcome);
        Assert.Equal("object_not_accessible", decision.ReasonCode);
    }

    [Fact]
    public async Task Object_access_policy_runs_only_after_capability_passes()
    {
        // Capability denial short-circuits before the object policy is ever
        // consulted: an operator without the capability gets
        // capability_not_granted even when the object policy would allow.
        // (Uses an object policy that throws if called, to prove it was skipped.)
        var evaluator = CreateEvaluator(
            adminRoles: ["identity-administrator"],
            objectAccess: new ThrowingObjectAccessPolicy());
        // principal has NO admin role and NO capability claim → capability check fails.
        var principal = PrincipalWithRole("no-capabilities");

        var decision = await evaluator.EvaluateAsync(
            principal,
            ManagementCapabilities.UsersDelete,
            new ManagementResource(ManagementResourceTypes.User, "user-1"));

        Assert.Equal(ManagementAuthorizationOutcome.Denied, decision.Outcome);
        Assert.Equal("capability_not_granted", decision.ReasonCode);
    }

    /// <summary>Stub object policy that denies every resource with a fixed reason.</summary>
    private sealed class DenyingObjectAccessPolicy(string reason)
        : IManagementObjectAccessPolicy
    {
        public ValueTask<ManagementAuthorizationDecision> EvaluateAsync(
            ClaimsPrincipal principal,
            string capability,
            ManagementResource resource,
            CancellationToken cancellationToken = default)
            => ValueTask.FromResult(ManagementAuthorizationDecision.Denied(reason));
    }

    /// <summary>Stub object policy that throws if ever called (proves short-circuit).</summary>
    private sealed class ThrowingObjectAccessPolicy : IManagementObjectAccessPolicy
    {
        public ValueTask<ManagementAuthorizationDecision> EvaluateAsync(
            ClaimsPrincipal principal,
            string capability,
            ManagementResource resource,
            CancellationToken cancellationToken = default)
            => throw new InvalidOperationException(
                "Object access policy must not be consulted when capability is denied.");
    }

    private static CapabilityManagementAuthorizationEvaluator CreateEvaluator(
        bool requireMfa = false,
        string[]? adminRoles = null,
        IManagementObjectAccessPolicy? objectAccess = null)
    {
        var options = Options.Create(new ManagementOptions
        {
            RequireMfa = requireMfa,
            Authorization = new ManagementAuthorizationOptions
            {
                FullAdministratorRoles = adminRoles ?? ["identity-administrator"],
                CapabilityClaimTypes = ["permission"]
            }
        });
        return new CapabilityManagementAuthorizationEvaluator(
            new ScopeAndRoleManagementEntitlementResolver(options),
            new ConfigurationManagementAccessPolicyProvider(options),
            objectAccess ?? new DefaultManagementObjectAccessPolicy());
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

    private sealed class TestHostEnvironment : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = "Test";

        public string ApplicationName { get; set; } = "Sufficit.Identity.Tests";

        public string ContentRootPath { get; set; } = "/tmp";

        public IFileProvider ContentRootFileProvider { get; set; } =
            new NullFileProvider();
    }
}
