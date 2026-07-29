using System.Security.Claims;
using Microsoft.Extensions.Options;

namespace Sufficit.Identity.Management.Authorization;

public static class ManagementCapabilities
{
    public const string ClientsRead = "identity.clients.read";
    public const string ClientsCreate = "identity.clients.create";
    public const string ClientsDelete = "identity.clients.delete";
    public const string BrandingRead = "identity.branding.read";
    public const string BrandingManage = "identity.branding.manage";
    public const string UsersRead = "identity.users.read";
    public const string UsersCreate = "identity.users.create";
    public const string UsersUpdate = "identity.users.update";
    public const string UsersDisable = "identity.users.disable";
    public const string UsersDelete = "identity.users.delete";
    public const string UsersResetPassword = "identity.users.reset-password";
    public const string UsersPermissionsManage =
        "identity.users.permissions.manage";
    public const string AuditRead = "identity.audit.read";
}

public static class ManagementResourceTypes
{
    public const string Client = "client";
    public const string ClientCollection = "client-collection";
    public const string BrandingTheme = "branding-theme";
    public const string BrandingCollection = "branding-collection";
    public const string User = "user";
    public const string UserCollection = "user-collection";
    public const string Audit = "audit";
}

public sealed record ManagementRequestContext(
    ClaimsPrincipal Operator,
    string CorrelationId)
{
    public string OperatorSubject =>
        Operator.FindFirstValue("sub")
        ?? Operator.FindFirstValue(ClaimTypes.NameIdentifier)
        ?? "unknown";

    public string? OperatorDisplayName =>
        Operator.Identity?.Name
        ?? Operator.FindFirstValue(ClaimTypes.Email);

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

    public static ManagementAuthorizationDecision Allowed() =>
        new(ManagementAuthorizationOutcome.Allowed, "allowed");

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
    bool HasGlobalAdministratorAccess,
    IReadOnlySet<string> ManagedContextIds);

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

public sealed class ManagementAuthorizationOptions
{
    public string[] AdministratorRoles { get; set; } = ["administrator"];

    public string[] ManagerRoles { get; set; } = ["manager"];

    public string[] ContextClaimTypes { get; set; } = ["management_context"];

    public Dictionary<string, ManagementContextAccessPolicyOptions> Contexts
    {
        get;
        set;
    } = new(StringComparer.OrdinalIgnoreCase);
}

public sealed class ManagementContextAccessPolicyOptions
{
    public bool RequireMfa { get; set; }
}

public sealed class RoleAndClaimManagementEntitlementResolver(
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
        if (NormalizeRoles(
                authorization.AdministratorRoles,
                "administrator")
            .Any(principal.IsInRole))
        {
            return ValueTask.FromResult(
                new ManagementEntitlements(
                    HasGlobalAdministratorAccess: true,
                    ManagedContextIds: new HashSet<string>(
                        StringComparer.OrdinalIgnoreCase)));
        }

        if (!NormalizeRoles(authorization.ManagerRoles, "manager")
            .Any(principal.IsInRole))
        {
            return ValueTask.FromResult(Empty());
        }

        var claimTypes = NormalizeRoles(
            authorization.ContextClaimTypes,
            "management_context");
        var contexts = principal.Claims
            .Where(claim => claimTypes.Contains(
                claim.Type,
                StringComparer.OrdinalIgnoreCase))
            .Select(claim => NormalizeContextId(claim.Value))
            .Where(contextId => contextId is not null)
            .Select(contextId => contextId!)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        return ValueTask.FromResult(
            new ManagementEntitlements(
                HasGlobalAdministratorAccess: false,
                ManagedContextIds: contexts));
    }

    private static ManagementEntitlements Empty() =>
        new(
            HasGlobalAdministratorAccess: false,
            ManagedContextIds: new HashSet<string>(
                StringComparer.OrdinalIgnoreCase));

    internal static string? NormalizeContextId(string? value)
    {
        var normalized = value?.Trim();
        if (string.IsNullOrWhiteSpace(normalized)
            || normalized == Guid.Empty.ToString("D"))
        {
            return null;
        }

        return Guid.TryParse(normalized, out var contextId)
            ? contextId.ToString("D")
            : normalized;
    }

    internal static string[] NormalizeRoles(
        string[]? roles,
        string fallback)
    {
        var normalized = (roles ?? [])
            .Where(role => !string.IsNullOrWhiteSpace(role))
            .Select(role => role.Trim())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

        return normalized.Length is 0 ? [fallback] : normalized;
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

        var configuration = options.Value;
        var requireMfa = configuration.RequireMfa;
        var contextId =
            RoleAndClaimManagementEntitlementResolver.NormalizeContextId(
                resource.ContextId);

        if (contextId is not null
            && configuration.Authorization.Contexts.TryGetValue(
                contextId,
                out var contextPolicy))
        {
            requireMfa = contextPolicy.RequireMfa;
        }

        return ValueTask.FromResult(new ManagementAccessPolicy(requireMfa));
    }
}

public sealed class RoleBasedManagementAuthorizationEvaluator
    : IManagementAuthorizationEvaluator
{
    private readonly IManagementEntitlementResolver entitlements;
    private readonly IManagementAccessPolicyProvider accessPolicies;

    private static readonly HashSet<string> MfaMethods =
        new(StringComparer.Ordinal)
        {
            "mfa", "otp", "hwk", "sms", "vcm", "fpt", "eye", "voice", "retina"
        };

    public RoleBasedManagementAuthorizationEvaluator(
        IManagementEntitlementResolver entitlements,
        IManagementAccessPolicyProvider accessPolicies)
    {
        this.entitlements = entitlements;
        this.accessPolicies = accessPolicies;
    }

    // Source-compatible fallback for a sibling UI pinned to the preceding
    // contract commit. New hosts register both replaceable dependencies; an
    // older composition surface still receives the same fail-closed defaults.
    public RoleBasedManagementAuthorizationEvaluator(
        IOptions<ManagementOptions> options,
        IManagementEntitlementResolver? entitlements = null,
        IManagementAccessPolicyProvider? accessPolicies = null)
    {
        this.entitlements = entitlements
            ?? new RoleAndClaimManagementEntitlementResolver(options);
        this.accessPolicies = accessPolicies
            ?? new ConfigurationManagementAccessPolicyProvider(options);
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

        var isKnownCapability = capability is
            ManagementCapabilities.ClientsRead or
            ManagementCapabilities.ClientsCreate or
            ManagementCapabilities.ClientsDelete or
            ManagementCapabilities.BrandingRead or
            ManagementCapabilities.BrandingManage or
            ManagementCapabilities.UsersRead or
            ManagementCapabilities.UsersCreate or
            ManagementCapabilities.UsersUpdate or
            ManagementCapabilities.UsersDisable or
            ManagementCapabilities.UsersDelete or
            ManagementCapabilities.UsersResetPassword or
            ManagementCapabilities.UsersPermissionsManage or
            ManagementCapabilities.AuditRead;

        if (!isKnownCapability)
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
        var isUserCapability = capability.StartsWith(
            "identity.users.",
            StringComparison.Ordinal);
        var normalizedContextId =
            RoleAndClaimManagementEntitlementResolver.NormalizeContextId(
                resource.ContextId);

        var isGranted = grants.HasGlobalAdministratorAccess
            || isUserCapability
                && normalizedContextId is not null
                && grants.ManagedContextIds.Contains(normalizedContextId);

        if (!isGranted)
        {
            return ManagementAuthorizationDecision.Denied(
                isUserCapability && normalizedContextId is null
                    ? "context_required"
                    : "capability_not_granted");
        }

        var policy = await accessPolicies.GetAsync(
            resource,
            cancellationToken);
        if (policy.RequireMfa && !HasMfaEvidence(principal))
        {
            return ManagementAuthorizationDecision.StepUpRequired(
                "mfa_required");
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
