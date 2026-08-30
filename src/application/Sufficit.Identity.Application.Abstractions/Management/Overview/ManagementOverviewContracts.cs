using Sufficit.Identity.Management.Authorization;

namespace Sufficit.Identity.Management.Overview;

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
