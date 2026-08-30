using System.Runtime.CompilerServices;
using Sufficit.Identity.Application.Diagnostics;
using Sufficit.Identity.Management.Authorization;

namespace Sufficit.Identity.Management.Database;

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
        await AuthorizeAsync(context, cancellationToken);

        return telemetry.GetSnapshot();
    }

    public async IAsyncEnumerable<DatabaseRuntimeSnapshot> WatchAsync(
        ManagementRequestContext context,
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        await AuthorizeAsync(context, cancellationToken);

        await foreach (var snapshot in telemetry
            .WatchAsync(cancellationToken)
            .WithCancellation(cancellationToken))
        {
            yield return snapshot;
        }
    }

    private async ValueTask AuthorizeAsync(
        ManagementRequestContext context,
        CancellationToken cancellationToken)
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
    }
}
