using System.Security.Claims;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;
using Sufficit.Identity.Management;
using Sufficit.Identity.Management.Authorization;
using Sufficit.Identity.Management.Overview;
using Sufficit.Identity.Management.Vault;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.Server.Management;
using Sufficit.Identity.Tests.Infrastructure;
using Xunit;

namespace Sufficit.Identity.Tests;

public sealed class ManagementApplicationAuthorizationTests
{
    [Fact]
    public async Task Management_scope_accepts_openiddict_principal_metadata()
    {
        var requirement = new ScopeRequirement("identity.management");
        var principal = PrincipalWithClaims(new Claim("sub", "operator-1"));
        principal.SetScopes("openid", "identity.management");
        var context = new AuthorizationHandlerContext(
            [requirement],
            principal,
            resource: null);

        await new ScopeHandler().HandleAsync(context);

        Assert.True(context.HasSucceeded);
    }

    [Fact]
    public async Task Management_scope_still_accepts_public_scope_claim()
    {
        var requirement = new ScopeRequirement("identity.management");
        var context = new AuthorizationHandlerContext(
            [requirement],
            PrincipalWithClaims(new Claim(
                "scope",
                "openid identity.management")),
            resource: null);

        await new ScopeHandler().HandleAsync(context);

        Assert.True(context.HasSucceeded);
    }

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
    public async Task Vault_secret_read_does_not_grant_secret_mutation()
    {
        var evaluator = CreateEvaluator();
        var decision = await evaluator.EvaluateAsync(
            PrincipalWithClaims(new Claim(
                "permission", ManagementCapabilities.VaultSecretsRead)),
            ManagementCapabilities.VaultSecretsManage,
            new ManagementResource(ManagementResourceTypes.VaultSecrets,
                "providers/google/client-secret"));

        Assert.False(decision.IsAllowed);
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

    [Fact]
    public async Task Concrete_object_policy_enforces_context_and_item_identity()
    {
        var options = Options.Create(new ManagementOptions
        {
            Authorization = new ManagementAuthorizationOptions
            {
                ObjectAccess = new ManagementObjectAccessOptions
                {
                    Mode = ManagementPolicyEnforcementMode.Enforce,
                    LegacyContextId = "legacy-global",
                    ContextClaimType = "identity_context",
                },
            },
        });
        var policy = new ConfigurationManagementObjectAccessPolicy(
            options,
            new AllowProtectedPrincipalPolicy(),
            NullLogger<ConfigurationManagementObjectAccessPolicy>.Instance);
        var wrongContext = PrincipalWithClaims(
            new Claim("identity_context", "tenant-b"));
        var rightContext = PrincipalWithClaims(
            new Claim("identity_context", "tenant-a"));

        var denied = await policy.EvaluateAsync(
            wrongContext,
            ManagementCapabilities.UsersRead,
            new ManagementResource(
                ManagementResourceTypes.User,
                "user-1",
                "tenant-a"));
        var allowed = await policy.EvaluateAsync(
            rightContext,
            ManagementCapabilities.UsersRead,
            new ManagementResource(
                ManagementResourceTypes.User,
                "user-1",
                "tenant-a"));
        var missingId = await policy.EvaluateAsync(
            rightContext,
            ManagementCapabilities.UsersRead,
            new ManagementResource(
                ManagementResourceTypes.User,
                ContextId: "tenant-a"));

        Assert.Equal("context_not_accessible", denied.ReasonCode);
        Assert.True(allowed.IsAllowed);
        Assert.Equal("resource_id_required", missingId.ReasonCode);

        var missingVaultSecretId = await policy.EvaluateAsync(
            rightContext,
            ManagementCapabilities.VaultSecretsRead,
            new ManagementResource(
                ManagementResourceTypes.VaultSecrets,
                ContextId: "tenant-a"));
        Assert.Equal("resource_id_required", missingVaultSecretId.ReasonCode);
    }

    [Fact]
    public async Task Vault_namespace_claims_are_context_bound_and_break_glass_requires_mfa()
    {
        var options = Options.Create(new ManagementOptions
        {
            Authorization = new ManagementAuthorizationOptions(),
        });
        var policy = new ConfigurationVaultSecretNamespaceAccessPolicy(options);
        var scoped = PrincipalWithClaims(
            new Claim("identity_vault_namespace", "tenant-a:providers"),
            new Claim("identity_vault_namespace", "tenant-b:billing"));

        var allowed = await policy.ResolveAsync(
            scoped,
            "tenant-a",
            "providers");
        var guessed = await policy.ResolveAsync(
            scoped,
            "tenant-a",
            "billing");
        var list = await policy.ResolveAsync(
            scoped,
            "tenant-a",
            requiredNamespace: null);
        Assert.True(allowed.Authorization.IsAllowed);
        Assert.Equal(
            "vault_namespace_not_accessible",
            guessed.Authorization.ReasonCode);
        Assert.Equal(["providers"], list.Namespaces);

        var breakGlassWithoutMfa = PrincipalWithClaims(
            new Claim(
                "identity_vault_break_glass",
                "identity.vault.secrets"));
        var deniedBreakGlass = await policy.ResolveAsync(
            breakGlassWithoutMfa,
            "tenant-a",
            "providers");
        Assert.False(deniedBreakGlass.Authorization.IsAllowed);

        var breakGlass = PrincipalWithClaims(
            new Claim(
                "identity_vault_break_glass",
                "identity.vault.secrets"),
            new Claim("amr", "pwd mfa"));
        var emergency = await policy.ResolveAsync(
            breakGlass,
            "tenant-a",
            "providers");
        Assert.True(emergency.Authorization.IsAllowed);
        Assert.Equal("vault_break_glass", emergency.Authorization.ReasonCode);
        Assert.Null(emergency.Namespaces);

        var objectPolicy = new ConfigurationManagementObjectAccessPolicy(
            options,
            new AllowProtectedPrincipalPolicy(),
            NullLogger<ConfigurationManagementObjectAccessPolicy>.Instance);
        var contextBypass = await objectPolicy.EvaluateAsync(
            breakGlass,
            ManagementCapabilities.VaultSecretsRead,
            new ManagementResource(
                ManagementResourceTypes.VaultSecrets,
                "providers/google/client-secret",
                "tenant-a"));
        Assert.True(contextBypass.IsAllowed);
        Assert.Equal("vault_break_glass", contextBypass.ReasonCode);
    }

    [Fact]
    public async Task Protected_principal_policy_denies_equal_tier_and_audits_break_glass()
    {
        using var factory = new ManagementTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        await using var scope = factory.Services.CreateAsyncScope();
        var users = scope.ServiceProvider.GetRequiredService<
            UserManager<ApplicationUser>>();
        var target = await users.FindByNameAsync(TestDataSeeder.DefaultUsername)
            ?? throw new InvalidOperationException("Seed user not found.");
        var added = await users.AddClaimAsync(
            target,
            new Claim("identity_principal_tier", "2"));
        Assert.True(added.Succeeded);
        var options = Options.Create(new ManagementOptions
        {
            Authorization = new ManagementAuthorizationOptions
            {
                ProtectedPrincipals = new ProtectedPrincipalAccessOptions
                {
                    Mode = ManagementPolicyEnforcementMode.Enforce,
                },
            },
        });
        var policy = new ConfigurationProtectedPrincipalAccessPolicy(
            users,
            options,
            NullLogger<ConfigurationProtectedPrincipalAccessPolicy>.Instance);

        var equalTier = await policy.EvaluateAsync(
            PrincipalWithClaims(new Claim("identity_principal_tier", "2")),
            ManagementCapabilities.UsersResetPassword,
            target.Id);
        var higherTier = await policy.EvaluateAsync(
            PrincipalWithClaims(new Claim("identity_principal_tier", "3")),
            ManagementCapabilities.UsersResetPassword,
            target.Id);
        var breakGlass = await policy.EvaluateAsync(
            PrincipalWithClaims(
                new Claim("identity_principal_tier", "1"),
                new Claim("identity_break_glass", "identity.management"),
                new Claim("amr", "pwd mfa")),
            ManagementCapabilities.UsersResetPassword,
            target.Id);

        Assert.Equal("protected_principal_higher_or_equal", equalTier.ReasonCode);
        Assert.True(higherTier.IsAllowed);
        Assert.Equal("protected_principal_break_glass", breakGlass.ReasonCode);
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

    private sealed class AllowProtectedPrincipalPolicy
        : IProtectedPrincipalAccessPolicy
    {
        public ValueTask<ManagementAuthorizationDecision> EvaluateAsync(
            ClaimsPrincipal principal,
            string capability,
            string targetUserId,
            CancellationToken cancellationToken = default) =>
            ValueTask.FromResult(ManagementAuthorizationDecision.Allowed());
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
            [new Claim(ClaimTypes.Role, role), .. additionalClaims]);

    private static ClaimsPrincipal PrincipalWithClaims(
        params Claim[] claims) =>
        new(new ClaimsIdentity(
            [
                new Claim(ClaimTypes.NameIdentifier, "operator-1"),
                .. claims
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
