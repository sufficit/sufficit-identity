using Sufficit.Identity.Application.Security;

namespace Sufficit.Identity.STS;

/// <summary>
/// Management API configuration (opt-in).
/// </summary>
public sealed class ManagementOptions
{
    public bool Enabled { get; init; } = false;

    /// <summary>
    /// Route prefix for the management REST endpoints.
    /// </summary>
    public string RoutePrefix { get; init; } = "api";

    /// <summary>
    /// If true, the management endpoints require an access token carrying the
    /// <c>identity.management</c> scope (or another configured scope).
    /// </summary>
    public bool RequireAuthorization { get; init; } = true;

    /// <summary>
    /// Required authorization policy/scope. Defaults to
    /// <c>identity.management</c>.
    /// </summary>
    public string RequiredScope { get; init; } = "identity.management";
}
