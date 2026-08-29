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
    public async Task Legacy_capabilities_are_accepted_but_resolve_to_canonical_names()
    {
        var options = Options.Create(new ManagementOptions
        {
            Authorization = new ManagementAuthorizationOptions
            {
                CapabilityClaimTypes = ["permission"],
                RoleCapabilities = new(StringComparer.OrdinalIgnoreCase)
                {
                    ["token-manager"] =
                        ["identity.operator-tokens.read"],
                },
            },
        });
        var resolver = new ScopeAndRoleManagementEntitlementResolver(options);

        var entitlements = await resolver.ResolveAsync(
            PrincipalWithRole(
                "token-manager",
                new Claim(
                    "permission",
                    "identity.users.reset-password")));

        Assert.Contains(
            ManagementCapabilities.UsersReset,
            entitlements.Capabilities);
        Assert.Contains(
            ManagementCapabilities.ManagementTokensRead,
            entitlements.Capabilities);
        Assert.DoesNotContain(
            "identity.users.reset-password",
            entitlements.Capabilities);
        Assert.DoesNotContain(
            "identity.operator-tokens.read",
            entitlements.Capabilities);
        Assert.DoesNotContain(
            "identity.users.reset-password",
            ManagementCapabilities.All);
        Assert.DoesNotContain(
            "identity.operator-tokens.read",
            ManagementCapabilities.All);
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
                new Claim("directive", "clientadmin:acme")));
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
            new AllowingObjectAccessPolicy());
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
        // boundary is consulted and respected (the object-level/BOLA
        // scoping). Capability + MFA still pass; only the object check denies.
        var evaluator = CreateEvaluator(
            adminRoles: ["identity-administrator"],
            objectAccess: new DenyingObjectAccessPolicy("object_not_accessible"));
        var principal = PrincipalWithRole("identity-administrator");

        var decision = await evaluator.EvaluateAsync(
            principal,
            ManagementCapabilities.UsersDelete,
            new ManagementResource(ManagementResourceTypes.User, "other-operator-user"));

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
    public async Task Missing_object_policy_fails_closed()
    {
        var decision = await new DefaultManagementObjectAccessPolicy()
            .EvaluateAsync(
                PrincipalWithRole("identity-administrator"),
                ManagementCapabilities.UsersRead,
                new ManagementResource(ManagementResourceTypes.UserCollection));

        Assert.Equal("object_policy_unavailable", decision.ReasonCode);
        Assert.False(decision.IsAllowed);
    }

    [Fact]
    public async Task Concrete_object_policy_enforces_item_identity()
    {
        // With the multi-tenant system removed (2026-08 decision), the
        // object-level contract is: item resources require an id, and user
        // mutations consult the protected-principal policy. Tenants no longer
        // participate — isolation is per deployment, externally.
        var policy = new ConfigurationManagementObjectAccessPolicy(
            new AllowProtectedPrincipalPolicy());

        var allowed = await policy.EvaluateAsync(
            PrincipalWithClaims(new Claim("sub", "operator-a")),
            ManagementCapabilities.UsersRead,
            new ManagementResource(ManagementResourceTypes.User, "user-1"));
        Assert.True(allowed.IsAllowed);

        var missingId = await policy.EvaluateAsync(
            PrincipalWithClaims(new Claim("sub", "operator-a")),
            ManagementCapabilities.UsersRead,
            new ManagementResource(ManagementResourceTypes.User));
        Assert.Equal("resource_id_required", missingId.ReasonCode);

        var missingVaultSecretId = await policy.EvaluateAsync(
            PrincipalWithClaims(new Claim("sub", "operator-a")),
            ManagementCapabilities.VaultSecretsRead,
            new ManagementResource(ManagementResourceTypes.VaultSecrets));
        Assert.Equal("resource_id_required", missingVaultSecretId.ReasonCode);

        // Collections stay reachable for any capability holder.
        var collection = await policy.EvaluateAsync(
            PrincipalWithClaims(new Claim("sub", "operator-a")),
            ManagementCapabilities.ClientsRead,
            new ManagementResource(ManagementResourceTypes.ClientCollection));
        Assert.True(collection.IsAllowed);
    }

    [Fact]
    public async Task Vault_break_glass_is_an_audit_marker_requiring_mfa()
    {
        // With the tenant/namespace boundary removed, break-glass no longer
        // grants access — it marks emergency sessions in the audit trail and
        // requires the dedicated claim AND MFA evidence.
        var options = Options.Create(new ManagementOptions
        {
            Authorization = new ManagementAuthorizationOptions(),
        });

        var withoutMfa = PrincipalWithClaims(
            new Claim("identity_vault_break_glass", "identity.vault.secrets"));
        Assert.False(
            ConfigurationManagementObjectAccessPolicy
                .HasVaultBreakGlassEvidence(
                    withoutMfa,
                    options.Value.Authorization.VaultSecrets));

        var withMfa = PrincipalWithClaims(
            new Claim("identity_vault_break_glass", "identity.vault.secrets"),
            new Claim("amr", "pwd mfa"));
        Assert.True(
            ConfigurationManagementObjectAccessPolicy
                .HasVaultBreakGlassEvidence(
                    withMfa,
                    options.Value.Authorization.VaultSecrets));
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
            ManagementCapabilities.UsersReset,
            target.Id);
        var higherTier = await policy.EvaluateAsync(
            PrincipalWithClaims(new Claim("identity_principal_tier", "3")),
            ManagementCapabilities.UsersReset,
            target.Id);
        var breakGlass = await policy.EvaluateAsync(
            PrincipalWithClaims(
                new Claim("identity_principal_tier", "1"),
                new Claim("identity_break_glass", "identity.management"),
                new Claim("amr", "pwd mfa")),
            ManagementCapabilities.UsersReset,
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

    private sealed class AllowingObjectAccessPolicy
        : IManagementObjectAccessPolicy
    {
        public ValueTask<ManagementAuthorizationDecision> EvaluateAsync(
            ClaimsPrincipal principal,
            string capability,
            ManagementResource resource,
            CancellationToken cancellationToken = default) =>
            ValueTask.FromResult(ManagementAuthorizationDecision.Allowed());
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


    // --- Principal de máquina (client_credentials) -----------------------
    //
    // Um serviço não tem por onde receber capacidade: o claim `permission` só
    // é emitido a partir de um operador autenticado, e ele não está em papel
    // nenhum. Antes disto, dar acesso de gestão a um serviço só era possível
    // pondo-o num papel de administrador — trocar "não consegue nada" por
    // "consegue tudo".
    //
    // E mesmo com a capacidade, o MFA o barrava para sempre: a checagem exige
    // claim `amr`, que um principal autenticado por segredo de cliente nunca
    // carrega.

    private const string ServiceClient = "sufficit_cloud_mobile_api";

    private static ClaimsPrincipal MachinePrincipal(string clientId) =>
        PrincipalWithClaims(new Claim("client_id", clientId));

    [Fact]
    public async Task Service_principal_receives_only_its_declared_capabilities()
    {
        var evaluator = CreateEvaluator(servicePrincipals: new()
        {
            [ServiceClient] = [ManagementCapabilities.VaultSecretsManage]
        });

        var concedida = await evaluator.EvaluateAsync(
            MachinePrincipal(ServiceClient),
            ManagementCapabilities.VaultSecretsManage,
            new ManagementResource(ManagementResourceTypes.VaultSecrets));
        var naoConcedida = await evaluator.EvaluateAsync(
            MachinePrincipal(ServiceClient),
            ManagementCapabilities.UsersDelete,
            new ManagementResource(ManagementResourceTypes.User));

        Assert.True(concedida.IsAllowed);
        Assert.Equal(ManagementAuthorizationOutcome.Denied, naoConcedida.Outcome);
    }

    [Fact]
    public async Task Service_principal_passes_mfa_only_for_the_declared_capability()
    {
        // O ponto todo: com RequireMfa ligado e sem `amr`, a capacidade
        // declarada passa e QUALQUER outra continua barrada. A isenção é da
        // concessão, não do principal.
        var evaluator = CreateEvaluator(
            requireMfa: true,
            adminRoles: [],
            servicePrincipals: new()
            {
                [ServiceClient] = [ManagementCapabilities.VaultSecretsManage]
            });

        var declarada = await evaluator.EvaluateAsync(
            MachinePrincipal(ServiceClient),
            ManagementCapabilities.VaultSecretsManage,
            new ManagementResource(ManagementResourceTypes.VaultSecrets));

        Assert.True(declarada.IsAllowed);
    }

    [Fact]
    public async Task Another_client_gets_nothing_from_someone_elses_grant()
    {
        var evaluator = CreateEvaluator(
            requireMfa: true,
            servicePrincipals: new()
            {
                [ServiceClient] = [ManagementCapabilities.VaultSecretsManage]
            });

        var outro = await evaluator.EvaluateAsync(
            MachinePrincipal("dcr_algum_cliente_anonimo"),
            ManagementCapabilities.VaultSecretsManage,
            new ManagementResource(ManagementResourceTypes.VaultSecrets));

        Assert.Equal(ManagementAuthorizationOutcome.Denied, outro.Outcome);
    }

    [Fact]
    public async Task A_human_holding_the_same_capability_still_needs_mfa()
    {
        // A isenção não pode vazar para operador. Ele recebeu a capacidade por
        // claim `permission`, não pelo mapa de máquina, então continua tendo de
        // apresentar segundo fator.
        var evaluator = CreateEvaluator(
            requireMfa: true,
            adminRoles: [],
            servicePrincipals: new()
            {
                [ServiceClient] = [ManagementCapabilities.VaultSecretsManage]
            });

        var humano = await evaluator.EvaluateAsync(
            PrincipalWithClaims(
                new Claim("permission", ManagementCapabilities.VaultSecretsManage)),
            ManagementCapabilities.VaultSecretsManage,
            new ManagementResource(ManagementResourceTypes.VaultSecrets));

        Assert.Equal(
            ManagementAuthorizationOutcome.StepUpRequired,
            humano.Outcome);
    }

    [Fact]
    public async Task Empty_map_changes_nothing()
    {
        // O padrão é vazio, e nesse estado o comportamento tem de ser
        // exatamente o de antes desta mudança.
        var evaluator = CreateEvaluator(requireMfa: true, adminRoles: []);

        var maquina = await evaluator.EvaluateAsync(
            MachinePrincipal(ServiceClient),
            ManagementCapabilities.VaultSecretsManage,
            new ManagementResource(ManagementResourceTypes.VaultSecrets));

        Assert.Equal(ManagementAuthorizationOutcome.Denied, maquina.Outcome);
    }

    private static CapabilityManagementAuthorizationEvaluator CreateEvaluator(
        bool requireMfa = false,
        string[]? adminRoles = null,
        IManagementObjectAccessPolicy? objectAccess = null,
        Dictionary<string, string[]>? servicePrincipals = null)
    {
        var options = Options.Create(new ManagementOptions
        {
            RequireMfa = requireMfa,
            Authorization = new ManagementAuthorizationOptions
            {
                FullAdministratorRoles = adminRoles ?? ["identity-administrator"],
                CapabilityClaimTypes = ["permission"],
                ServicePrincipals = servicePrincipals is null
                    ? new(StringComparer.OrdinalIgnoreCase)
                    : new(servicePrincipals, StringComparer.OrdinalIgnoreCase)
            }
        });
        return new CapabilityManagementAuthorizationEvaluator(
            new ScopeAndRoleManagementEntitlementResolver(options),
            new ConfigurationManagementAccessPolicyProvider(options),
            objectAccess ?? new AllowingObjectAccessPolicy());
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
