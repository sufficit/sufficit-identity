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
    public const string AuditRead = "identity.audit.read";
}

public static class ManagementResourceTypes
{
    public const string Client = "client";
    public const string ClientCollection = "client-collection";
    public const string BrandingTheme = "branding-theme";
    public const string BrandingCollection = "branding-collection";
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

public sealed class ManagementAuthorizationOptions
{
    public string[] AdministratorRoles { get; set; } = ["administrator"];
}

public sealed class RoleBasedManagementAuthorizationEvaluator(
    IOptions<ManagementOptions> options) : IManagementAuthorizationEvaluator
{
    private static readonly HashSet<string> MfaMethods =
        new(StringComparer.Ordinal)
        {
            "mfa", "otp", "hwk", "sms", "vcm", "fpt", "eye", "voice", "retina"
        };

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

        var configuration = options.Value;
        var administratorRoles = NormalizeRoles(
            configuration.Authorization.AdministratorRoles,
            "administrator");

        var isAdministrator = administratorRoles.Any(principal.IsInRole);
        var isKnownCapability = capability is
            ManagementCapabilities.ClientsRead or
            ManagementCapabilities.ClientsCreate or
            ManagementCapabilities.ClientsDelete or
            ManagementCapabilities.BrandingRead or
            ManagementCapabilities.BrandingManage or
            ManagementCapabilities.AuditRead;

        if (!isAdministrator || !isKnownCapability)
        {
            return ValueTask.FromResult(
                ManagementAuthorizationDecision.Denied("capability_not_granted"));
        }

        if (configuration.RequireMfa && !HasMfaEvidence(principal))
        {
            return ValueTask.FromResult(
                ManagementAuthorizationDecision.StepUpRequired("mfa_required"));
        }

        return ValueTask.FromResult(ManagementAuthorizationDecision.Allowed());
    }

    private static bool HasMfaEvidence(ClaimsPrincipal principal) =>
        principal.FindAll("amr")
            .SelectMany(claim => claim.Value.Split(
                ' ',
                StringSplitOptions.RemoveEmptyEntries))
            .Any(MfaMethods.Contains);

    private static string[] NormalizeRoles(string[]? roles, string fallback)
    {
        var normalized = (roles ?? [])
            .Where(role => !string.IsNullOrWhiteSpace(role))
            .Select(role => role.Trim())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

        return normalized.Length is 0 ? [fallback] : normalized;
    }
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
