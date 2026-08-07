using Sufficit.Identity.Application.Diagnostics;
using Sufficit.Identity.Management.Authorization;

namespace Sufficit.Identity.Management.Database;

#if APPLICATION_CONTRACTS

/// <summary>
/// Canonical, read-only application boundary for database runtime telemetry.
/// Both the embedded UI and HTTP adapter consume this service.
/// </summary>
public interface IDatabaseMonitoringService
{
    Task<DatabaseRuntimeSnapshot> GetAsync(
        ManagementRequestContext context,
        CancellationToken cancellationToken = default);
}

#else

internal sealed class DatabaseMonitoringService(
    IDatabaseRuntimeTelemetry telemetry,
    IManagementAuthorizationEvaluator authorization)
    : IDatabaseMonitoringService
{
    private static readonly ManagementResource Resource =
        new(ManagementResourceTypes.DatabaseRuntime);

    public async Task<DatabaseRuntimeSnapshot> GetAsync(
        ManagementRequestContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);

        var decision = await authorization.EvaluateAsync(
            context.Operator,
            ManagementCapabilities.DatabaseRead,
            Resource,
            cancellationToken);
        if (!decision.IsAllowed)
        {
            throw new ManagementAccessException(decision);
        }

        return telemetry.GetSnapshot();
    }
}

#endif
