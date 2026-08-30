using System.Runtime.CompilerServices;
using Sufficit.Identity.Application.Diagnostics;
using Sufficit.Identity.Management.Authorization;

namespace Sufficit.Identity.Management.Database;

/// <summary>
/// Canonical, read-only application boundary for database runtime telemetry.
/// Both the embedded UI and HTTP adapter consume this service.
/// </summary>
public interface IDatabaseMonitoringService
{
    Task<DatabaseRuntimeSnapshot> GetAsync(
        ManagementRequestContext context,
        CancellationToken cancellationToken = default);

    IAsyncEnumerable<DatabaseRuntimeSnapshot> WatchAsync(
        ManagementRequestContext context,
        CancellationToken cancellationToken = default);
}
