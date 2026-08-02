using Sufficit.Identity.Management.Authorization;

namespace Sufficit.Identity.Management;

/// <summary>Bindable options for the provider-management application.</summary>
public sealed class ManagementOptions
{
    public bool Enabled { get; init; }

    public string RoutePrefix { get; init; } = "api";

    public bool RequireAuthorization { get; init; } = true;

    public string RequiredScope { get; init; } =
        "skoruba_identity_admin_api";

    public ManagementAuthorizationOptions Authorization { get; init; } = new();

    /// <summary>
    /// Requires multi-factor evidence for sensitive provider-management
    /// operations. Deployment configuration controls this policy.
    /// </summary>
    public bool RequireMfa { get; init; }
}
