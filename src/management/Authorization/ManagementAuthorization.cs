using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Sufficit.Identity.Core.Entities;
using System.Security.Claims;

namespace Sufficit.Identity.Management.Authorization;

public sealed class ScopeAndRoleManagementEntitlementResolver(
    IOptions<ManagementOptions> options) : IManagementEntitlementResolver
{
    public ValueTask<ManagementEntitlements> ResolveAsync(
        ClaimsPrincipal principal,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        if (principal.Identity?.IsAuthenticated is not true)
        {
            return ValueTask.FromResult(Empty());
        }

        var authorization = options.Value.Authorization;
        var capabilities = new HashSet<string>(StringComparer.Ordinal);

        // --- Capabilities from dedicated claim types (NOT "scope") ---
        // The OAuth scope claim carries scope values (e.g.
        // identity.management), a different namespace. Mixing them
        // would let an OAuth scope accidentally grant a management capability.
        var claimTypes = NormalizeValues(
            authorization.CapabilityClaimTypes,
            ["permission"]);

        // Defensive: never accept "scope" as a capability claim type, even if
        // an operator configures it — the two namespaces MUST stay separate.
        if (claimTypes.Contains("scope"))
        {
            claimTypes = claimTypes
                .Where(t => !string.Equals(t, "scope", StringComparison.OrdinalIgnoreCase))
                .ToArray();
        }

        foreach (var rawCapability in principal.Claims
            .Where(claim => claimTypes.Contains(
                claim.Type,
                StringComparer.OrdinalIgnoreCase))
            .SelectMany(claim => claim.Value.Split(
                ' ',
                StringSplitOptions.RemoveEmptyEntries)))
        {
            var capability = ManagementCapabilities.Normalize(rawCapability);
            if (ManagementCapabilities.All.Contains(capability))
            {
                capabilities.Add(capability);
            }
        }

        // --- Capabilities from role-to-capability mapping ---
        // Granular: a role maps to a specific subset of capabilities.
        if (authorization.RoleCapabilities.Count > 0)
        {
            foreach (var (role, mapped) in authorization.RoleCapabilities)
            {
                if (principal.IsInRole(role))
                {
                    foreach (var rawCapability in mapped)
                    {
                        var capability = ManagementCapabilities.Normalize(
                            rawCapability);
                        if (ManagementCapabilities.All.Contains(capability))
                        {
                            capabilities.Add(capability);
                        }
                    }
                }
            }
        }

        // --- Full administrator roles (god-mode) ---
        // Opt-in only: default is empty. Every principal in any of these roles
        // receives every capability. Use sparingly for break-glass access.
        var adminRoles = authorization.FullAdministratorRoles;
        if (adminRoles.Length > 0 && adminRoles.Any(principal.IsInRole))
        {
            capabilities.UnionWith(ManagementCapabilities.All);
        }

        return ValueTask.FromResult(
            new ManagementEntitlements(capabilities));
    }

    private static ManagementEntitlements Empty() =>
        new(new HashSet<string>(StringComparer.Ordinal));

    internal static string[] NormalizeValues(
        string[]? values,
        string[] fallback)
    {
        var normalized = (values ?? [])
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .Select(value => value.Trim())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

        return normalized.Length is 0 ? fallback : normalized;
    }
}

public sealed class ConfigurationManagementAccessPolicyProvider(
    IOptions<ManagementOptions> options) : IManagementAccessPolicyProvider
{
    public ValueTask<ManagementAccessPolicy> GetAsync(
        ManagementResource resource,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        return ValueTask.FromResult(
            new ManagementAccessPolicy(options.Value.RequireMfa));
    }
}

/// <summary>
/// Fail-closed default used only when a host did not compose a concrete
/// object-access policy. A missing security dependency must deny rather than
/// grant access.
/// </summary>
public sealed class DefaultManagementObjectAccessPolicy
    : IManagementObjectAccessPolicy
{
    public ValueTask<ManagementAuthorizationDecision> EvaluateAsync(
        ClaimsPrincipal principal,
        string capability,
        ManagementResource resource,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return ValueTask.FromResult(
            ManagementAuthorizationDecision.Denied(
                "object_policy_unavailable"));
    }
}

/// <summary>
/// Concrete object-level boundary: item resources require an id and user
/// mutations consult the protected-principal policy. The tenant-membership
/// check that used to live here was removed with the internal multi-tenant
/// system (2026-08 decision): isolation is per deployment (see the
/// ManagementResource remarks), so capability + MFA + protected principals
/// are the complete object-level contract.
/// </summary>
public sealed class ConfigurationManagementObjectAccessPolicy(
    IProtectedPrincipalAccessPolicy protectedPrincipals)
    : IManagementObjectAccessPolicy
{
    private static readonly HashSet<string> ItemResourceTypes =
        new(StringComparer.Ordinal)
        {
            ManagementResourceTypes.Client,
            ManagementResourceTypes.User,
            ManagementResourceTypes.Claim,
            ManagementResourceTypes.Scope,
            ManagementResourceTypes.Session,
            ManagementResourceTypes.Authorization,
            ManagementResourceTypes.VaultSecrets,
        };

    private static readonly HashSet<string> MfaMethods =
        new(StringComparer.Ordinal)
        {
            "mfa", "otp", "hwk", "sms", "vcm", "fpt", "eye", "voice", "retina"
        };

    private static readonly HashSet<string> ProtectedPrincipalCapabilities =
        new(StringComparer.Ordinal)
        {
            ManagementCapabilities.UsersUpdate,
            ManagementCapabilities.UsersDisable,
            ManagementCapabilities.UsersDelete,
            ManagementCapabilities.UsersReset,
        };

    public async ValueTask<ManagementAuthorizationDecision> EvaluateAsync(
        ClaimsPrincipal principal,
        string capability,
        ManagementResource resource,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (ItemResourceTypes.Contains(resource.Type)
            && string.IsNullOrWhiteSpace(resource.Id))
        {
            return ManagementAuthorizationDecision.Denied(
                "resource_id_required");
        }

        if (resource.Type == ManagementResourceTypes.User
            && resource.Id is not null
            && ProtectedPrincipalCapabilities.Contains(capability))
        {
            return await protectedPrincipals.EvaluateAsync(
                principal,
                capability,
                resource.Id,
                cancellationToken);
        }

        return ManagementAuthorizationDecision.Allowed();
    }

    internal static bool HasVaultBreakGlassEvidence(
        ClaimsPrincipal principal,
        VaultSecretAccessOptions policy)
    {
        var hasClaim = principal.FindAll(policy.BreakGlassClaimType)
            .Any(claim => string.Equals(
                claim.Value,
                policy.BreakGlassClaimValue,
                StringComparison.Ordinal));
        var hasMfa = principal.FindAll("amr")
            .SelectMany(claim => claim.Value.Split(
                ' ',
                StringSplitOptions.RemoveEmptyEntries))
            .Any(MfaMethods.Contains);
        return hasClaim && hasMfa;
    }
}

/// <summary>
/// Prevents equal/lower-tier operators from mutating explicitly protected
/// principals. Break-glass requires both a dedicated claim and MFA evidence.
/// </summary>
public sealed class ConfigurationProtectedPrincipalAccessPolicy(
    UserManager<ApplicationUser> userManager,
    IOptions<ManagementOptions> options,
    ILogger<ConfigurationProtectedPrincipalAccessPolicy> logger)
    : IProtectedPrincipalAccessPolicy
{
    private static readonly HashSet<string> MfaMethods =
        new(StringComparer.Ordinal)
        {
            "mfa", "otp", "hwk", "sms", "vcm", "fpt", "eye", "voice", "retina"
        };

    public async ValueTask<ManagementAuthorizationDecision> EvaluateAsync(
        ClaimsPrincipal principal,
        string capability,
        string targetUserId,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var policy = options.Value.Authorization.ProtectedPrincipals;
        var target = await userManager.FindByIdAsync(targetUserId);
        if (target is null)
        {
            return ManagementAuthorizationDecision.Allowed();
        }

        var targetClaims = await userManager.GetClaimsAsync(target);
        var targetTier = HighestTier(targetClaims, policy.TierClaimType);
        if (policy.ProtectedUserIds.Contains(targetUserId, StringComparer.Ordinal))
        {
            targetTier = Math.Max(targetTier, 1);
        }
        if (policy.ProtectedRoles.Length > 0)
        {
            var roles = await userManager.GetRolesAsync(target);
            if (roles.Any(role => policy.ProtectedRoles.Contains(
                role,
                StringComparer.OrdinalIgnoreCase)))
            {
                targetTier = Math.Max(targetTier, 1);
            }
        }

        if (targetTier <= 0)
        {
            return ManagementAuthorizationDecision.Allowed();
        }

        if (HasBreakGlassEvidence(principal, policy))
        {
            logger.LogWarning(
                "Break-glass management access used for capability {Capability} against protected user {TargetUserId}",
                capability,
                targetUserId);
            return ManagementAuthorizationDecision.Allowed(
                "protected_principal_break_glass");
        }

        var operatorTier = HighestTier(principal.Claims, policy.TierClaimType);
        if (operatorTier > targetTier)
        {
            return ManagementAuthorizationDecision.Allowed();
        }

        logger.LogWarning(
            "Protected-principal policy {PolicyMode} rejected operator tier {OperatorTier} for capability {Capability} against target tier {TargetTier}",
            policy.Mode,
            operatorTier,
            capability,
            targetTier);
        return policy.Mode is ManagementPolicyEnforcementMode.Enforce
            ? ManagementAuthorizationDecision.Denied(
                "protected_principal_higher_or_equal")
            : ManagementAuthorizationDecision.Allowed(
                "protected_principal_observed");
    }

    private static int HighestTier(
        IEnumerable<Claim> claims,
        string claimType) =>
        claims.Where(claim => string.Equals(
                claim.Type,
                claimType,
                StringComparison.Ordinal))
            .Select(claim => int.TryParse(claim.Value, out var tier) ? tier : 0)
            .DefaultIfEmpty(0)
            .Max();

    private static bool HasBreakGlassEvidence(
        ClaimsPrincipal principal,
        ProtectedPrincipalAccessOptions policy)
    {
        var hasClaim = principal.FindAll(policy.BreakGlassClaimType)
            .Any(claim => string.Equals(
                claim.Value,
                policy.BreakGlassClaimValue,
                StringComparison.Ordinal));
        var hasMfa = principal.FindAll("amr")
            .SelectMany(claim => claim.Value.Split(
                ' ',
                StringSplitOptions.RemoveEmptyEntries))
            .Any(MfaMethods.Contains);
        return hasClaim && hasMfa;
    }
}

public sealed class CapabilityManagementAuthorizationEvaluator
    : IManagementAuthorizationEvaluator
{
    private readonly IManagementEntitlementResolver entitlements;
    private readonly IManagementAccessPolicyProvider accessPolicies;
    private readonly IManagementObjectAccessPolicy objectAccess;

    private static readonly HashSet<string> MfaMethods =
        new(StringComparer.Ordinal)
        {
            "mfa", "otp", "hwk", "sms", "vcm", "fpt", "eye", "voice", "retina"
        };

    public CapabilityManagementAuthorizationEvaluator(
        IManagementEntitlementResolver entitlements,
        IManagementAccessPolicyProvider accessPolicies,
        IManagementObjectAccessPolicy objectAccess)
    {
        this.entitlements = entitlements;
        this.accessPolicies = accessPolicies;
        this.objectAccess = objectAccess;
    }

    // Source-compatible fallback for an embedded UI compiled against the preceding
    // contract commit. New hosts register all replaceable dependencies; an
    // older composition surface still receives the same fail-closed defaults.
    public CapabilityManagementAuthorizationEvaluator(
        IOptions<ManagementOptions> options,
        IManagementEntitlementResolver? entitlements = null,
        IManagementAccessPolicyProvider? accessPolicies = null,
        IManagementObjectAccessPolicy? objectAccess = null)
    {
        this.entitlements = entitlements
            ?? new ScopeAndRoleManagementEntitlementResolver(options);
        this.accessPolicies = accessPolicies
            ?? new ConfigurationManagementAccessPolicyProvider(options);
        this.objectAccess = objectAccess
            ?? new DefaultManagementObjectAccessPolicy();
    }

    public ValueTask<ManagementAuthorizationDecision> EvaluateAsync(
        ClaimsPrincipal principal,
        string capability,
        ManagementResource resource,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        if (principal.Identity?.IsAuthenticated is not true)
        {
            return ValueTask.FromResult(
                ManagementAuthorizationDecision.Denied(
                    "operator_not_authenticated",
                    capability));
        }

        if (!ManagementCapabilities.All.Contains(capability))
        {
            return ValueTask.FromResult(
                ManagementAuthorizationDecision.Denied(
                    "capability_not_granted",
                    capability));
        }

        return EvaluateKnownCapabilityAsync(
            principal,
            capability,
            resource,
            cancellationToken);
    }

    private async ValueTask<ManagementAuthorizationDecision>
        EvaluateKnownCapabilityAsync(
            ClaimsPrincipal principal,
            string capability,
            ManagementResource resource,
            CancellationToken cancellationToken)
    {
        var grants = await entitlements.ResolveAsync(
            principal,
            cancellationToken);
        if (!grants.Contains(capability))
        {
            return ManagementAuthorizationDecision.Denied(
                "capability_not_granted",
                capability);
        }

        var policy = await accessPolicies.GetAsync(
            resource,
            cancellationToken);

        // A isenção vale SÓ para a capacidade que a implantação concedeu
        // explicitamente a este client_id em ServicePrincipals. Não é "serviço
        // não faz MFA": é "esta concessão, para este cliente, foi declarada
        // sem segundo fator". Qualquer outra capacidade do mesmo principal
        // continua exigindo MFA e continua sendo negada, que é o certo.
        //
        // Existe porque exigir segundo fator de quem se autenticou com segredo
        // de cliente é exigir o impossível: um principal de máquina nunca tem
        // `amr`, e o efeito prático da exigência não é segurança, é negar para
        // sempre. O controle dele é o segredo mais esta lista fechada.
        var exempt = grants.IsMultiFactorExempt(capability);
        if (policy.RequireMfa && !exempt && !HasMfaEvidence(principal))
        {
            return ManagementAuthorizationDecision.StepUpRequired(
                "mfa_required",
                capability);
        }

        // H3 (eval): object-level authorization boundary. Consulted LAST
        // (after capability + MFA) because it may need a DB lookup to resolve
        // resource ownership, while the preceding checks are principal-scoped
        // and cheap. The default policy is permissive; a deployment replaces
        // it to enforce tenant/object scoping. A non-allowed decision carries
        // its own ReasonCode and is surfaced unchanged (audited + 403 by the
        // shared DemandAsync machinery in each service).
        var objectDecision = await objectAccess.EvaluateAsync(
            principal, capability, resource, cancellationToken);
        if (!objectDecision.IsAllowed)
        {
            return objectDecision.RequiredCapability is null
                ? objectDecision with { RequiredCapability = capability }
                : objectDecision;
        }

        return ManagementAuthorizationDecision.Allowed();
    }

    private static bool HasMfaEvidence(ClaimsPrincipal principal) =>
        principal.FindAll("amr")
            .SelectMany(claim => claim.Value.Split(
                ' ',
                StringSplitOptions.RemoveEmptyEntries))
            .Any(MfaMethods.Contains);

}
