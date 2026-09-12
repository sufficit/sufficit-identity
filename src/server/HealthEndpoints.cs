using Microsoft.AspNetCore.Http;

namespace Sufficit.Identity.Server;

/// <summary>
/// Health endpoint paths, shared by the endpoint mapping and by middleware that
/// must never block liveness.
/// </summary>
internal static class HealthEndpoints
{
    /// <summary>Process liveness: no dependency checks.</summary>
    public const string Liveness = "/health";

    /// <summary>Readiness: runs every registered check.</summary>
    public const string Readiness = "/health/ready";

    public static bool IsLiveness(PathString path) =>
        path.Equals(Liveness, StringComparison.OrdinalIgnoreCase);
}
