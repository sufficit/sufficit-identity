namespace Sufficit.Identity.Application.Security;

/// <summary>
/// OAuth scopes that belonged to retired products and must never be
/// reintroduced by management, dynamic registration or provisioning.
/// </summary>
public static class RetiredIdentityScopes
{
    public const string SkorubaIdentityAdminApi =
        "skoruba_identity_admin_api";

    public static IReadOnlySet<string> Names { get; } =
        new HashSet<string>(StringComparer.Ordinal)
        {
            SkorubaIdentityAdminApi
        };

    public static bool Contains(string? scope) =>
        !string.IsNullOrWhiteSpace(scope) && Names.Contains(scope);
}
