#if !APPLICATION_CONTRACTS
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
#endif
using Sufficit.Identity.Management.Authorization;

namespace Sufficit.Identity.Management.Overview;

#if APPLICATION_CONTRACTS

/// <summary>
/// Canonical discovery boundary for the provider-management runtime.
/// Embedded UI and HTTP controllers project the same effective configuration,
/// module catalog and operator access decisions.
/// </summary>
public interface IManagementOverviewService
{
    Task<ManagementOverview> GetAsync(
        ManagementRequestContext context,
        CancellationToken cancellationToken = default);
}

public sealed record ManagementOverview(
    string EnvironmentName,
    ManagementApiDescriptor Api,
    ManagementOperatorDescriptor Operator,
    IReadOnlyList<ManagementModuleDescriptor> Modules);

public sealed record ManagementApiDescriptor(
    string RoutePrefix,
    bool RequiresAuthorization,
    string RequiredScope);

public sealed record ManagementOperatorDescriptor(
    bool RequiresMfa,
    bool MeetsMfaRequirement,
    IReadOnlyList<string> Capabilities);

public sealed record ManagementModuleDescriptor(
    string Key,
    bool IsAvailable,
    string? RequiredCapability,
    ManagementAuthorizationOutcome AccessOutcome,
    string ReasonCode)
{
    public bool CanAccess =>
        IsAvailable
        && AccessOutcome is ManagementAuthorizationOutcome.Allowed;
}

#else

public sealed class ManagementOverviewService(
    IManagementEntitlementResolver entitlements,
    IManagementAccessPolicyProvider accessPolicies,
    IManagementAuthorizationEvaluator authorization,
    IOptions<ManagementOptions> options,
    IHostEnvironment hostEnvironment,
    ILogger<ManagementOverviewService>? logger = null) : IManagementOverviewService
{
    private static readonly ManagementResource OverviewResource =
        new(ManagementResourceTypes.Overview);

    private static readonly ModuleDefinition[] ModuleCatalog =
    [
        new("users", ManagementCapabilities.UsersRead),
        new("claims", ManagementCapabilities.ClaimsRead),
        new("clients", ManagementCapabilities.ClientsRead),
        new("service-accounts", ManagementCapabilities.ClientsRead),
        new("scopes", ManagementCapabilities.ScopesRead),
        new("authorizations", ManagementCapabilities.AuthorizationsRead),
        new("branding", ManagementCapabilities.BrandingRead),
        new("sessions", ManagementCapabilities.SessionsRead),
        new("audit", ManagementCapabilities.AuditRead),
        new("database", ManagementCapabilities.DatabaseRead),
        new("metrics", ManagementCapabilities.MetricsRead),
        new("operator-tokens", ManagementCapabilities.ManagementTokensRead),
        new("provisioning", ManagementCapabilities.ProvisioningPreview)
    ];

    public async Task<ManagementOverview> GetAsync(
        ManagementRequestContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);

        var authenticationMethods = context.Operator.FindAll("amr")
            .SelectMany(claim => claim.Value.Split(
                ' ',
                StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            .Distinct(StringComparer.Ordinal)
            .Order(StringComparer.Ordinal)
            .ToArray();
        logger?.LogDebug(
            "Management overview evaluation started for subject {Subject}; "
            + "authenticated={Authenticated}; amr={AuthenticationMethods}; "
            + "aal={AssuranceLevel}; correlation={CorrelationId}.",
            context.OperatorSubject,
            context.Operator.Identity?.IsAuthenticated == true,
            string.Join(' ', authenticationMethods),
            context.Operator.FindFirst("aal")?.Value ?? "missing",
            context.CorrelationId);

        if (context.Operator.Identity?.IsAuthenticated is not true)
        {
            throw new ManagementAccessException(
                ManagementAuthorizationDecision.Denied(
                    "operator_not_authenticated"));
        }

        var grants = await entitlements.ResolveAsync(
            context.Operator,
            cancellationToken);
        var capabilities = grants.Capabilities
            .Order(StringComparer.Ordinal)
            .ToArray();

        if (capabilities.Length is 0)
        {
            throw new ManagementAccessException(
                ManagementAuthorizationDecision.Denied(
                    "capability_not_granted"));
        }

        var accessPolicy = await accessPolicies.GetAsync(
            OverviewResource,
            cancellationToken);
        var sessionDecision = await authorization.EvaluateAsync(
            context.Operator,
            capabilities[0],
            OverviewResource,
            cancellationToken);
        logger?.LogInformation(
            "Management overview authorization for subject {Subject}: "
            + "capabilities={Capabilities}; requireMfa={RequireMfa}; "
            + "mfaSatisfied={MfaSatisfied}; outcome={Outcome}; "
            + "reason={ReasonCode}; correlation={CorrelationId}.",
            context.OperatorSubject,
            string.Join(',', capabilities),
            accessPolicy.RequireMfa,
            !accessPolicy.RequireMfa || sessionDecision.IsAllowed,
            sessionDecision.Outcome,
            sessionDecision.ReasonCode,
            context.CorrelationId);
        var modules = new List<ManagementModuleDescriptor>(
            ModuleCatalog.Length);

        foreach (var module in ModuleCatalog)
        {
            if (!module.IsAvailable || module.RequiredCapability is null)
            {
                modules.Add(new ManagementModuleDescriptor(
                    module.Key,
                    module.IsAvailable,
                    module.RequiredCapability,
                    ManagementAuthorizationOutcome.Denied,
                    module.UnavailableReasonCode
                        ?? "module_unavailable"));
                continue;
            }

            var decision = await authorization.EvaluateAsync(
                context.Operator,
                module.RequiredCapability,
                OverviewResource,
                cancellationToken);
            modules.Add(new ManagementModuleDescriptor(
                module.Key,
                IsAvailable: true,
                module.RequiredCapability,
                decision.Outcome,
                decision.ReasonCode));
        }

        var configured = options.Value;
        return new ManagementOverview(
            hostEnvironment.EnvironmentName,
            new ManagementApiDescriptor(
                NormalizeRoutePrefix(configured.RoutePrefix),
                configured.RequireAuthorization,
                configured.RequiredScope),
            new ManagementOperatorDescriptor(
                accessPolicy.RequireMfa,
                !accessPolicy.RequireMfa || sessionDecision.IsAllowed,
                capabilities),
            modules);
    }

    private static string NormalizeRoutePrefix(string? value)
    {
        var normalized = value?.Trim().Trim('/');
        return string.IsNullOrWhiteSpace(normalized) ? "api" : normalized;
    }

    private sealed record ModuleDefinition(
        string Key,
        string? RequiredCapability,
        bool IsAvailable = true,
        string? UnavailableReasonCode = null);
}
#endif
