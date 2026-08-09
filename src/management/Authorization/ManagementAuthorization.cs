using System.Security.Claims;
#if !APPLICATION_CONTRACTS
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Sufficit.Identity.Core.Entities;
#endif

namespace Sufficit.Identity.Management.Authorization;

#if APPLICATION_CONTRACTS

public static class ManagementCapabilities
{
    public const string ClientsRead = "identity.clients.read";
    public const string ClientsCreate = "identity.clients.create";
    public const string ClientsUpdate = "identity.clients.update";
    public const string ClientsDelete = "identity.clients.delete";
    public const string BrandingRead = "identity.branding.read";
    public const string BrandingManage = "identity.branding.manage";
    public const string UsersRead = "identity.users.read";
    public const string UsersCreate = "identity.users.create";
    public const string UsersUpdate = "identity.users.update";
    public const string UsersDisable = "identity.users.disable";
    public const string UsersDelete = "identity.users.delete";
    public const string UsersResetPassword = "identity.users.reset-password";
    public const string ClaimsRead = "identity.claims.read";
    public const string ClaimsCreate = "identity.claims.create";
    public const string ClaimsUpdate = "identity.claims.update";
    public const string ClaimsDelete = "identity.claims.delete";
    public const string ScopesRead = "identity.scopes.read";
    public const string ScopesCreate = "identity.scopes.create";
    public const string ScopesUpdate = "identity.scopes.update";
    public const string ScopesDelete = "identity.scopes.delete";
    public const string SessionsRead = "identity.sessions.read";
    public const string SessionsRevoke = "identity.sessions.revoke";
    public const string AuthorizationsRead = "identity.authorizations.read";
    public const string AuthorizationsRevoke =
        "identity.authorizations.revoke";
    public const string AuditRead = "identity.audit.read";
    public const string DatabaseRead = "identity.database.read";
    public const string MetricsRead = "identity.metrics.read";
    public const string MetricsManage = "identity.metrics.manage";
    public const string VaultSecretsRead = "identity.vault.secrets.read";
    public const string VaultSecretsManage = "identity.vault.secrets.manage";
    public const string ProvisioningPreview =
        "identity.provisioning.preview";
    public const string ProvisioningApply =
        "identity.provisioning.apply";

    public static IReadOnlySet<string> All { get; } =
        new HashSet<string>(
            [
                ClientsRead,
                ClientsCreate,
                ClientsUpdate,
                ClientsDelete,
                BrandingRead,
                BrandingManage,
                UsersRead,
                UsersCreate,
                UsersUpdate,
                UsersDisable,
                UsersDelete,
                UsersResetPassword,
                ClaimsRead,
                ClaimsCreate,
                ClaimsUpdate,
                ClaimsDelete,
                ScopesRead,
                ScopesCreate,
                ScopesUpdate,
                ScopesDelete,
                SessionsRead,
                SessionsRevoke,
                AuthorizationsRead,
                AuthorizationsRevoke,
                AuditRead,
                DatabaseRead,
                MetricsRead,
                MetricsManage,
                VaultSecretsRead,
                VaultSecretsManage,
                ProvisioningPreview,
                ProvisioningApply
            ],
            StringComparer.Ordinal);
}

public static class ManagementResourceTypes
{
    public const string Client = "client";
    public const string ClientCollection = "client-collection";
    public const string BrandingTheme = "branding-theme";
    public const string BrandingCollection = "branding-collection";
    public const string User = "user";
    public const string UserCollection = "user-collection";
    public const string Claim = "claim";
    public const string ClaimCollection = "claim-collection";
    public const string Scope = "scope";
    public const string ScopeCollection = "scope-collection";
    public const string Session = "session";
    public const string SessionCollection = "session-collection";
    public const string Authorization = "authorization";
    public const string AuthorizationCollection = "authorization-collection";
    public const string Audit = "audit";
    public const string DatabaseRuntime = "database-runtime";
    public const string Overview = "overview";
    public const string Metrics = "metrics";
    public const string VaultSecrets = "vault-secrets";
    public const string Provisioning = "provisioning";
}

public sealed record ManagementRequestContext(
    ClaimsPrincipal Operator,
    string CorrelationId)
{
    public string OperatorSubject =>
        Operator.FindFirst("sub")?.Value
        ?? Operator.FindFirst(ClaimTypes.NameIdentifier)?.Value
        ?? "unknown";

    public string? OperatorDisplayName =>
        Operator.Identity?.Name
        ?? Operator.FindFirst(ClaimTypes.Email)?.Value;

    public string? AuthenticationMethods
    {
        get
        {
            var values = Operator.FindAll("amr")
                .SelectMany(claim => claim.Value.Split(
                    ' ',
                    StringSplitOptions.RemoveEmptyEntries))
                .Distinct(StringComparer.Ordinal)
                .Order(StringComparer.Ordinal)
                .ToArray();

            return values.Length is 0 ? null : string.Join(' ', values);
        }
    }
}

public sealed record ManagementResource(
    string Type,
    string? Id = null,
    string? ContextId = null);

public enum ManagementAuthorizationOutcome
{
    Allowed,
    Denied,
    StepUpRequired
}

public sealed record ManagementAuthorizationDecision(
    ManagementAuthorizationOutcome Outcome,
    string ReasonCode)
{
    public bool IsAllowed => Outcome is ManagementAuthorizationOutcome.Allowed;

    public static ManagementAuthorizationDecision Allowed(
        string reasonCode = "allowed") =>
        new(ManagementAuthorizationOutcome.Allowed, reasonCode);

    public static ManagementAuthorizationDecision Denied(string reasonCode) =>
        new(ManagementAuthorizationOutcome.Denied, reasonCode);

    public static ManagementAuthorizationDecision StepUpRequired(string reasonCode) =>
        new(ManagementAuthorizationOutcome.StepUpRequired, reasonCode);
}

public interface IManagementAuthorizationEvaluator
{
    ValueTask<ManagementAuthorizationDecision> EvaluateAsync(
        ClaimsPrincipal principal,
        string capability,
        ManagementResource resource,
        CancellationToken cancellationToken = default);
}

public sealed record ManagementEntitlements(
    IReadOnlySet<string> Capabilities)
{
    public bool Contains(string capability) =>
        Capabilities.Contains(capability);
}

public interface IManagementEntitlementResolver
{
    ValueTask<ManagementEntitlements> ResolveAsync(
        ClaimsPrincipal principal,
        CancellationToken cancellationToken = default);
}

public sealed record ManagementAccessPolicy(bool RequireMfa);

public interface IManagementAccessPolicyProvider
{
    ValueTask<ManagementAccessPolicy> GetAsync(
        ManagementResource resource,
        CancellationToken cancellationToken = default);
}

/// <summary>
/// Object-level authorization boundary (BOLA / tenant scoping). Consulted by
/// the authorization evaluator AFTER the capability check and the MFA step-up
/// check pass, to decide whether the operator may exercise <paramref name="capability"/>
/// against this specific <paramref name="resource"/>. This is the seam that
/// turns <see cref="ManagementResource"/> (Type/Id/ContextId) from dead audit
/// metadata into a real access decision — enabling per-object or per-tenant
/// authorization ("can this operator delete *this* user / manage *this*
/// client") once a deployment ships a non-permissive implementation.
/// </summary>
/// <remarks>
/// The default implementation (<c>DefaultManagementObjectAccessPolicy</c>)
/// returns <see cref="ManagementAuthorizationDecision.Allowed"/> for every
/// resource, preserving the single-operator/trust-everything posture the STS
/// ships with. A deployment that needs object/tenant boundaries replaces it
/// via <c>services.Replace&lt;IManagementObjectAccessPolicy, ...&gt;()</c>,
/// exactly as it can replace <see cref="IManagementEntitlementResolver"/>.
/// The decision type is reused so the evaluator needs no translation.
/// </remarks>
public interface IManagementObjectAccessPolicy
{
    ValueTask<ManagementAuthorizationDecision> EvaluateAsync(
        ClaimsPrincipal principal,
        string capability,
        ManagementResource resource,
        CancellationToken cancellationToken = default);
}

public interface IProtectedPrincipalAccessPolicy
{
    ValueTask<ManagementAuthorizationDecision> EvaluateAsync(
        ClaimsPrincipal principal,
        string capability,
        string targetUserId,
        CancellationToken cancellationToken = default);
}

public enum ManagementPolicyEnforcementMode
{
    Observe,
    Enforce,
}

public sealed class ManagementObjectAccessOptions
{
    public ManagementPolicyEnforcementMode Mode { get; set; } =
        ManagementPolicyEnforcementMode.Observe;

    public string ContextClaimType { get; set; } = "identity_context";

    public string LegacyContextId { get; set; } = "global";

    /// <summary>
    /// Acknowledges that running this policy in <see cref="Mode"/> =
    /// <see cref="ManagementPolicyEnforcementMode.Observe"/> in production is a
    /// deliberate choice (e.g. a single-context deployment that needs no
    /// tenant boundary). When false (default), the production posture check
    /// flags Observe mode as an unresolved permissive default — the boundary
    /// only logs, it does not block.
    /// </summary>
    public bool AcknowledgeObserveInProduction { get; set; }
}

public sealed class ProtectedPrincipalAccessOptions
{
    public ManagementPolicyEnforcementMode Mode { get; set; } =
        ManagementPolicyEnforcementMode.Observe;

    public string TierClaimType { get; set; } = "identity_principal_tier";

    public string[] ProtectedUserIds { get; set; } = [];

    public string[] ProtectedRoles { get; set; } = [];

    public string BreakGlassClaimType { get; set; } =
        "identity_break_glass";

    public string BreakGlassClaimValue { get; set; } =
        "identity.management";

    /// <summary>
    /// Acknowledges that running this policy in <see cref="Mode"/> =
    /// <see cref="ManagementPolicyEnforcementMode.Observe"/> in production is a
    /// deliberate choice. When false (default), the production posture check
    /// flags Observe mode as an unresolved permissive default — privilege-
    /// escalation attempts against protected principals are logged but
    /// permitted.
    /// </summary>
    public bool AcknowledgeObserveInProduction { get; set; }
}

public sealed class ManagementAuthorizationOptions
{
    public ManagementObjectAccessOptions ObjectAccess { get; set; } = new();

    public ProtectedPrincipalAccessOptions ProtectedPrincipals { get; set; } =
        new();

    /// <summary>
    /// Deployment-specific roles that receive every management capability
    /// (full administrator). <b>Use sparingly.</b> Every principal in any of
    /// these roles bypasses per-capability checks and gets every capability.
    /// Default is empty (no god-mode) — set explicitly to grant blanket access.
    /// </summary>
    public string[] FullAdministratorRoles { get; set; } = [];

    /// <summary>
    /// Maps a role name to the set of capabilities it grants. This is the
    /// granular alternative to <see cref="FullAdministratorRoles"/>: a role
    /// like <c>identity-user-manager</c> can map to
    /// <c>[identity.users.read, identity.users.create, identity.users.update]</c>
    /// without granting client/scope/provisioning capabilities. Default is
    /// empty — configure per environment.
    /// </summary>
    public Dictionary<string, string[]> RoleCapabilities { get; set; } = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Claim types that carry exact management capability names (e.g.
    /// <c>identity.users.read</c>). <b>Must NOT include <c>"scope"</c></b>:
    /// the OAuth <c>scope</c> claim carries OAuth scope values (like
    /// <c>identity.management</c>), which are a different namespace from
    /// management capabilities. Mixing the two would let an OAuth scope
    /// accidentally grant a management capability.
    /// </summary>
    public string[] CapabilityClaimTypes { get; set; } =
        ["permission"];
}

public sealed class ManagementAccessException(
    ManagementAuthorizationDecision decision) : Exception(decision.ReasonCode)
{
    public ManagementAuthorizationDecision Decision { get; } = decision;
}

public sealed class ManagementValidationException(
    string reasonCode,
    string message,
    string? field = null) : Exception(message)
{
    public string ReasonCode { get; } = reasonCode;

    public string? Field { get; } = field;
}

public sealed class ManagementConflictException(
    string reasonCode,
    string message) : Exception(message)
{
    public string ReasonCode { get; } = reasonCode;
}

public sealed class ManagementNotFoundException(
    string reasonCode,
    string message) : Exception(message)
{
    public string ReasonCode { get; } = reasonCode;
}

#else

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

        foreach (var capability in principal.Claims
            .Where(claim => claimTypes.Contains(
                claim.Type,
                StringComparer.OrdinalIgnoreCase))
            .SelectMany(claim => claim.Value.Split(
                ' ',
                StringSplitOptions.RemoveEmptyEntries)))
        {
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
                    foreach (var cap in mapped)
                    {
                        if (ManagementCapabilities.All.Contains(cap))
                        {
                            capabilities.Add(cap);
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
/// Permissive default <see cref="IManagementObjectAccessPolicy"/>: allows every
/// resource. This preserves the single-operator/trust-everything posture the
/// STS ships with (every operator with the capability may act on any object of
/// that type). A deployment that needs object-level or tenant boundaries
/// replaces this via
/// <c>services.Replace&lt;IManagementObjectAccessPolicy, ...&gt;()</c>.
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
        return ValueTask.FromResult(ManagementAuthorizationDecision.Allowed());
    }
}

/// <summary>
/// Concrete context boundary. Existing objects without a context are assigned
/// to the explicit legacy/global context. Observe mode records mismatches while
/// preserving a rolling deployment; Enforce changes the decision to deny.
/// </summary>
public sealed class ConfigurationManagementObjectAccessPolicy(
    IOptions<ManagementOptions> options,
    IProtectedPrincipalAccessPolicy protectedPrincipals,
    ILogger<ConfigurationManagementObjectAccessPolicy> logger)
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
        };

    private static readonly HashSet<string> ProtectedPrincipalCapabilities =
        new(StringComparer.Ordinal)
        {
            ManagementCapabilities.UsersUpdate,
            ManagementCapabilities.UsersDisable,
            ManagementCapabilities.UsersDelete,
            ManagementCapabilities.UsersResetPassword,
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

        var policy = options.Value.Authorization.ObjectAccess;
        var requiredContext = string.IsNullOrWhiteSpace(resource.ContextId)
            ? policy.LegacyContextId
            : resource.ContextId;
        var contexts = principal.FindAll(policy.ContextClaimType)
            .SelectMany(claim => claim.Value.Split(
                ' ',
                StringSplitOptions.RemoveEmptyEntries
                | StringSplitOptions.TrimEntries));
        if (!contexts.Contains(requiredContext, StringComparer.Ordinal))
        {
            logger.LogWarning(
                "Management object context policy {PolicyMode} rejected capability {Capability} on resource type {ResourceType} in context {ContextId}",
                policy.Mode,
                capability,
                resource.Type,
                requiredContext);
            if (policy.Mode is ManagementPolicyEnforcementMode.Enforce)
            {
                return ManagementAuthorizationDecision.Denied(
                    "context_not_accessible");
            }
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
                ManagementAuthorizationDecision.Denied("operator_not_authenticated"));
        }

        if (!ManagementCapabilities.All.Contains(capability))
        {
            return ValueTask.FromResult(
                ManagementAuthorizationDecision.Denied("capability_not_granted"));
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
                "capability_not_granted");
        }

        var policy = await accessPolicies.GetAsync(
            resource,
            cancellationToken);
        if (policy.RequireMfa && !HasMfaEvidence(principal))
        {
            return ManagementAuthorizationDecision.StepUpRequired(
                "mfa_required");
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
            return objectDecision;
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

#endif
