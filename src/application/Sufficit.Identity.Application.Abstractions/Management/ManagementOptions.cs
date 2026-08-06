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
    public bool RequireMfa { get; init; } = true;

    /// <summary>
    /// API-protection scopes that must NEVER be created via the runtime
    /// scope-management CRUD API or assigned to a client via the management-API
    /// client-create path. These scopes gate administrative surfaces (the
    /// management API itself, SCIM, and any custom privileged API); letting an
    /// operator mint one through the regular CRUD path is a privilege-
    /// escalation vector (H2/M3, eval): an operator with only
    /// <c>identity.scopes.create</c> could otherwise define
    /// <c>skoruba_identity_admin_api</c> as a custom scope and bind it to a
    /// client they control. Defaults cover the management + SCIM required
    /// scopes; add any custom privileged API scope here. These can still be
    /// declared via bootstrap/provisioning.
    /// </summary>
    public string[] ReservedApiScopes { get; init; } =
        ["skoruba_identity_admin_api", "scim"];
}
