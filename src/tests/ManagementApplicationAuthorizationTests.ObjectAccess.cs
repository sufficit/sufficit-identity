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
}
