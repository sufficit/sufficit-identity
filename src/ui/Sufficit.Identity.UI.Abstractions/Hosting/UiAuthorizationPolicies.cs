namespace Sufficit.Identity.UI.Abstractions.Hosting;

/// <summary>
/// Stable authorization policy names shared by optional UI modules and the
/// public account surface that links to them.
/// </summary>
public static class UiAuthorizationPolicies
{
    /// <summary>
    /// Grants access to the Management UI when the authenticated principal has
    /// at least one effective management capability.
    /// </summary>
    public const string ManagementAccess =
        "sufficit-identity-management-ui-access";
}
