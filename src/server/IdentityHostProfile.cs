using Sufficit.Identity.Management;
using Sufficit.Identity.Scim;
using Sufficit.Identity.UI.Management;
using Sufficit.Identity.UI.Vault;

namespace Sufficit.Identity.Server;

/// <summary>
/// Which plane this process serves. One binary, one database, one set of
/// modules per profile.
/// </summary>
public enum IdentityHostProfile
{
    /// <summary>
    /// Everything the configuration enables — what a single-process
    /// deployment has always done, and the default.
    /// </summary>
    All,

    /// <summary>
    /// The authentication plane: sign-in and token issuance. The management
    /// API, the consoles and SCIM are not composed, so the process that mints
    /// tokens does not carry them.
    /// </summary>
    Sts,

    /// <summary>
    /// The administration plane: management API and consoles, SCIM, Vault UI.
    /// The public sign-in UI is not composed.
    /// </summary>
    Admin,
}

/// <summary>
/// Resolves the profile and the modules it admits.
/// </summary>
/// <remarks>
/// The profile narrows what the configuration already allows: it never turns a
/// module on. That is what lets the three nodes share one configuration and
/// still run different planes — the unit says which profile, the settings say
/// what exists. What a profile leaves out is logged at startup, so a missing
/// endpoint is explained by the log rather than by a 404.
/// </remarks>
public static class IdentityHostProfilePolicy
{
    public const string SettingName = "Sufficit:Identity:HostProfile";

    private static readonly IReadOnlySet<string> AuthenticationPlane =
        new HashSet<string>(StringComparer.Ordinal)
        {
            PublicUiIdentityModule.ModuleId,
        };

    private static readonly IReadOnlySet<string> AdministrationPlane =
        new HashSet<string>(StringComparer.Ordinal)
        {
            ManagementIdentityModule.ModuleId,
            ManagementUiIdentityModule.ModuleId,
            VaultUiIdentityModule.ModuleId,
            ScimIdentityModule.ModuleId,
        };

    public static IdentityHostProfile Resolve(IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);

        var value = configuration[SettingName];
        if (string.IsNullOrWhiteSpace(value))
        {
            return IdentityHostProfile.All;
        }

        return Enum.TryParse<IdentityHostProfile>(value, ignoreCase: true, out var profile)
            ? profile
            : throw new InvalidOperationException(
                $"'{value}' is not a known {SettingName}. Use All, Sts or Admin.");
    }

    /// <summary>
    /// The module identifiers the profile admits, or <see langword="null"/>
    /// when it admits every module the configuration enables.
    /// </summary>
    public static IReadOnlySet<string>? AdmittedModules(IdentityHostProfile profile) =>
        profile switch
        {
            IdentityHostProfile.Sts => AuthenticationPlane,
            IdentityHostProfile.Admin => AdministrationPlane,
            _ => null,
        };

    /// <summary>
    /// The modules the configuration enables that this profile does not serve,
    /// so the host can say what it left out.
    /// </summary>
    public static IReadOnlyList<string> Excluded(
        IdentityHostProfile profile,
        IReadOnlyCollection<string> enabledModules)
    {
        ArgumentNullException.ThrowIfNull(enabledModules);

        if (AdmittedModules(profile) is not { } admitted)
        {
            return [];
        }

        return enabledModules
            .Where(id => !admitted.Contains(id))
            .OrderBy(id => id, StringComparer.Ordinal)
            .ToArray();
    }
}
