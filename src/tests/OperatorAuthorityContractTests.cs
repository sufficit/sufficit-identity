using System.Text.RegularExpressions;
using Xunit;

namespace Sufficit.Identity.Tests;

/// <summary>
/// Plan A1: console authority comes from roles the Identity never assigns,
/// mapped by reviewed configuration (FullAdministratorRoles, RoleCapabilities),
/// and from capability claims nobody can write through the claim API. If any
/// production path started assigning roles, every operator holding that path
/// could mint console authority — this is the stop.
/// </summary>
public sealed class OperatorAuthorityContractTests
{
    private static readonly Regex RoleAssignment = new(
        @"\b(AddToRoleAsync|AddToRolesAsync|RemoveFromRoleAsync|RemoveFromRolesAsync)\b"
        + @"|\bUserRoles\s*\.\s*(Add|AddRange|Remove|RemoveRange)\b"
        + @"|new\s+IdentityUserRole<"
        + @"|(?i:insert\s+into\s+`?userroles`?)",
        RegexOptions.Compiled);

    // Seeds roles for the test host only; not compiled into a production path.
    private static readonly string[] Allowed =
    [
        Path.Combine("src", "server", "DevelopmentTestEndpoints.cs"),
    ];

    [Fact]
    public void No_production_path_assigns_roles()
    {
        var root = ResolveIdentityRepository();
        var source = Path.Combine(root, "src");
        var offenders = Directory.EnumerateFiles(source, "*.cs", SearchOption.AllDirectories)
            .Where(path => !IsExcluded(Path.GetRelativePath(root, path)))
            .Where(path => RoleAssignment.IsMatch(File.ReadAllText(path)))
            .Select(path => Path.GetRelativePath(root, path))
            .ToArray();

        Assert.True(
            offenders.Length == 0,
            "Role assignment found outside the allowed seeding code. Roles grant console "
            + "authority through Management:Authorization; the Identity must not write them: "
            + string.Join(", ", offenders));
    }

    private static bool IsExcluded(string relative)
    {
        var parts = relative.Split(Path.DirectorySeparatorChar);
        return parts.Contains("obj") || parts.Contains("bin") || parts.Contains("tests")
            || parts.Contains("Migrations")
            || Allowed.Contains(relative, StringComparer.Ordinal);
    }

    private static string ResolveIdentityRepository()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null
            && !File.Exists(Path.Combine(directory.FullName, "Sufficit.Identity.sln")))
        {
            directory = directory.Parent;
        }

        Assert.NotNull(directory);
        return directory!.FullName;
    }
}
