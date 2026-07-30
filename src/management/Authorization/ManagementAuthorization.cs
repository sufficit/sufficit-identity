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

    public static IReadOnlySet<string> All { get; } =
        new HashSet<string>(
            [
                ClientsRead,
                ClientsCreate,
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
                AuditRead
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

public sealed class ManagementAuthorizationOptions
{
    /// <summary>
    /// Deployment-specific roles that receive every provider-management
    /// capability. The generic default is deliberately not a Sufficit
    /// business role.
    /// </summary>
    public string[] OperatorRoles { get; set; } =
        ["identity-administrator"];

    /// <summary>
    /// Claim types that can carry exact management capability names. Values
    /// may contain one capability or a space-delimited OAuth scope list.
    /// </summary>
    public string[] CapabilityClaimTypes { get; set; } =
        ["permission", "scope"];
}

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
        var claimTypes = NormalizeValues(
            authorization.CapabilityClaimTypes,
            ["permission", "scope"]);
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

        var operatorRoles = NormalizeValues(
            authorization.OperatorRoles,
            ["identity-administrator"]);
        if (operatorRoles.Any(principal.IsInRole))
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

public sealed class CapabilityManagementAuthorizationEvaluator
    : IManagementAuthorizationEvaluator
{
    private readonly IManagementEntitlementResolver entitlements;
    private readonly IManagementAccessPolicyProvider accessPolicies;

    private static readonly HashSet<string> MfaMethods =
        new(StringComparer.Ordinal)
        {
            "mfa", "otp", "hwk", "sms", "vcm", "fpt", "eye", "voice", "retina"
        };

    public CapabilityManagementAuthorizationEvaluator(
        IManagementEntitlementResolver entitlements,
        IManagementAccessPolicyProvider accessPolicies)
    {
        this.entitlements = entitlements;
        this.accessPolicies = accessPolicies;
    }

    // Source-compatible fallback for a sibling UI pinned to the preceding
    // contract commit. New hosts register both replaceable dependencies; an
    // older composition surface still receives the same fail-closed defaults.
    public CapabilityManagementAuthorizationEvaluator(
        IOptions<ManagementOptions> options,
        IManagementEntitlementResolver? entitlements = null,
        IManagementAccessPolicyProvider? accessPolicies = null)
    {
        this.entitlements = entitlements
            ?? new ScopeAndRoleManagementEntitlementResolver(options);
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
