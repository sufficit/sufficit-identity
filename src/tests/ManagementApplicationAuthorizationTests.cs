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

public sealed partial class ManagementApplicationAuthorizationTests
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
    // Um serviço não passa por nenhuma das fontes de capacidade do resolvedor
    // comum: o claim `permission` só é emitido a partir de um operador
    // autenticado, e o cliente não está em papel de usuário nenhum. Antes, a
    // única forma de dar acesso de gestão a um serviço era pô-lo num papel de
    // administrador — trocar "não consegue nada" por "consegue tudo".
    //
    // A concessão mora no banco (propriedade do cliente), o significado do
    // papel continua em configuração. Mesma divisão que já valia para gente.

    private const string ServiceClient = "sufficit_cloud_mobile_api";
    private const string VaultRole = "mobilecloudadministrator";

    private static CapabilityManagementAuthorizationEvaluator CreateEvaluator(
        bool requireMfa = false,
        string[]? adminRoles = null,
        IManagementObjectAccessPolicy? objectAccess = null,
        Dictionary<string, string[]>? roleCapabilities = null,
        string[]? clientRoles = null)
    {
        var options = Options.Create(new ManagementOptions
        {
            RequireMfa = requireMfa,
            Authorization = new ManagementAuthorizationOptions
            {
                FullAdministratorRoles = adminRoles ?? ["identity-administrator"],
                CapabilityClaimTypes = ["permission"],
                RoleCapabilities = roleCapabilities is null
                    ? new(StringComparer.OrdinalIgnoreCase)
                    : new(roleCapabilities, StringComparer.OrdinalIgnoreCase)
            }
        });
        IManagementEntitlementResolver resolver =
            new ScopeAndRoleManagementEntitlementResolver(options);
        if (clientRoles is not null)
        {
            resolver = new ServicePrincipalEntitlementResolver(
                resolver, new FakeRoleSource(ServiceClient, clientRoles), options);
        }

        return new CapabilityManagementAuthorizationEvaluator(
            resolver,
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
