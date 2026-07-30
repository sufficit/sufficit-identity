using Xunit;

namespace Sufficit.Identity.Tests;

public sealed class ManagementUiArchitectureTests
{
    private static readonly string[] ForbiddenUiDependencies =
    [
        "AppDbContext",
        "DbContext",
        "UserManager<",
        "SignInManager<",
        "IOpenIddictApplicationManager",
        "IOpenIddictAuthorizationManager",
        "IOpenIddictScopeManager",
        "IOpenIddictTokenManager",
    ];

    [Fact]
    public void Management_ui_source_uses_only_application_contracts()
    {
        var sourceRoot = ResolveManagementUiSource();
        var sourceFiles = Directory
            .EnumerateFiles(sourceRoot, "*", SearchOption.AllDirectories)
            .Where(path =>
                path.EndsWith(".cs", StringComparison.OrdinalIgnoreCase)
                || path.EndsWith(".razor", StringComparison.OrdinalIgnoreCase))
            .Where(path =>
                !path.Contains(
                    $"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}",
                    StringComparison.Ordinal)
                && !path.Contains(
                    $"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}",
                    StringComparison.Ordinal))
            .ToArray();

        Assert.NotEmpty(sourceFiles);

        foreach (var sourceFile in sourceFiles)
        {
            var source = File.ReadAllText(sourceFile);
            foreach (var forbidden in ForbiddenUiDependencies)
            {
                Assert.DoesNotContain(
                    forbidden,
                    source,
                    StringComparison.Ordinal);
            }
        }
    }

    [Fact]
    public void Public_and_management_ui_reuse_the_canonical_avatar_resolver()
    {
        var repositoryRoot = ResolveIdentityRepository();
        var uiRoot = Path.GetFullPath(Path.Combine(
            repositoryRoot,
            "..",
            "sufficit-identity-ui",
            "src"));
        var publicProfile = File.ReadAllText(Path.Combine(
            uiRoot,
            "Sufficit.Identity.UI",
            "Pages",
            "Manage",
            "Index.razor"));
        var managementLayout = File.ReadAllText(Path.Combine(
            uiRoot,
            "Sufficit.Identity.UI.Management",
            "Components",
            "Layout",
            "MainLayout.razor"));

        Assert.Contains(
            "IUserAvatarUrlResolver",
            publicProfile,
            StringComparison.Ordinal);
        Assert.Contains(
            "IUserAvatarUrlResolver",
            managementLayout,
            StringComparison.Ordinal);
        Assert.DoesNotContain(
            "AvatarUrlTemplate.Replace",
            publicProfile,
            StringComparison.Ordinal);
        Assert.DoesNotContain(
            "AvatarUrlTemplate.Replace",
            managementLayout,
            StringComparison.Ordinal);
    }

    [Fact]
    public void Management_navigation_does_not_invent_api_status_labels()
    {
        var navigation = File.ReadAllText(Path.Combine(
            ResolveManagementUiSource(),
            "Components",
            "Layout",
            "NavMenu.razor"));

        Assert.DoesNotContain(
            "nav-item__meta",
            navigation,
            StringComparison.Ordinal);
        Assert.DoesNotContain(
            ">API<",
            navigation,
            StringComparison.Ordinal);
    }

    [Fact]
    public void Client_controller_is_only_an_http_adapter()
    {
        var repositoryRoot = ResolveIdentityRepository();
        var controller = File.ReadAllText(Path.Combine(
            repositoryRoot,
            "src",
            "management",
            "Controllers",
            "ClientsController.cs"));

        Assert.Contains("IClientManagementService", controller, StringComparison.Ordinal);
        Assert.DoesNotContain("IOpenIddictApplicationManager", controller, StringComparison.Ordinal);
        Assert.DoesNotContain("OpenIddictApplicationDescriptor", controller, StringComparison.Ordinal);
        Assert.DoesNotContain("DbContext", controller, StringComparison.Ordinal);
    }

    [Fact]
    public void Branding_controller_is_only_an_http_adapter()
    {
        var repositoryRoot = ResolveIdentityRepository();
        var controller = File.ReadAllText(Path.Combine(
            repositoryRoot,
            "src",
            "management",
            "Controllers",
            "BrandingController.cs"));

        Assert.Contains(
            "IBrandingManagementService",
            controller,
            StringComparison.Ordinal);
        Assert.DoesNotContain("AppDbContext", controller, StringComparison.Ordinal);
        Assert.DoesNotContain("DbContext", controller, StringComparison.Ordinal);
        Assert.DoesNotContain("BrandingThemeProvider", controller, StringComparison.Ordinal);
    }

    [Fact]
    public void Users_controller_is_only_an_http_adapter()
    {
        var repositoryRoot = ResolveIdentityRepository();
        var controller = File.ReadAllText(Path.Combine(
            repositoryRoot,
            "src",
            "management",
            "Controllers",
            "UsersController.cs"));

        Assert.Contains(
            "IUserManagementService",
            controller,
            StringComparison.Ordinal);
        Assert.DoesNotContain("AppDbContext", controller, StringComparison.Ordinal);
        Assert.DoesNotContain("DbContext", controller, StringComparison.Ordinal);
        Assert.DoesNotContain("UserManager<", controller, StringComparison.Ordinal);
    }

    [Fact]
    public void Claims_and_scopes_controllers_are_only_http_adapters()
    {
        var controllers = Path.Combine(
            ResolveIdentityRepository(),
            "src",
            "management",
            "Controllers");
        var claims = File.ReadAllText(Path.Combine(
            controllers,
            "ClaimsController.cs"));
        var scopes = File.ReadAllText(Path.Combine(
            controllers,
            "ScopesController.cs"));

        Assert.Contains(
            "IClaimManagementService",
            claims,
            StringComparison.Ordinal);
        Assert.Contains(
            "IScopeManagementService",
            scopes,
            StringComparison.Ordinal);
        Assert.DoesNotContain("UserManager<", claims, StringComparison.Ordinal);
        Assert.DoesNotContain("DbContext", claims, StringComparison.Ordinal);
        Assert.DoesNotContain(
            "IOpenIddictScopeManager",
            scopes,
            StringComparison.Ordinal);
        Assert.DoesNotContain("DbContext", scopes, StringComparison.Ordinal);
    }

    [Fact]
    public void Generic_provider_has_no_business_permission_controller()
    {
        var repositoryRoot = ResolveIdentityRepository();
        var controllerPath = Path.Combine(
            repositoryRoot,
            "src",
            "management",
            "Controllers",
            "UserPermissionsController.cs");

        Assert.False(File.Exists(controllerPath));
    }

    [Fact]
    public void Claims_and_scopes_are_separate_functional_surfaces()
    {
        var pages = Path.Combine(
            ResolveManagementUiSource(),
            "Components",
            "Pages");
        var claims = File.ReadAllText(Path.Combine(pages, "Claims.razor"));
        var scopes = File.ReadAllText(Path.Combine(pages, "Scopes.razor"));
        var navigation = File.ReadAllText(Path.Combine(
            ResolveManagementUiSource(),
            "Components",
            "Layout",
            "NavMenu.razor"));

        Assert.False(File.Exists(Path.Combine(pages, "Access.razor")));
        Assert.Contains("ManagementClaimDataSource", claims, StringComparison.Ordinal);
        Assert.Contains("ManagementScopeDataSource", scopes, StringComparison.Ordinal);
        Assert.Contains("href=\"claims\"", navigation, StringComparison.Ordinal);
        Assert.Contains("href=\"scopes\"", navigation, StringComparison.Ordinal);
        Assert.DoesNotContain("href=\"access\"", navigation, StringComparison.Ordinal);
        Assert.DoesNotContain("manager", claims, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("administrator", claims, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("manager", scopes, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("administrator", scopes, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Managed_user_contract_has_no_business_roles_or_contexts()
    {
        var source = File.ReadAllText(Path.Combine(
            ResolveIdentityRepository(),
            "src",
            "management",
            "Users",
            "UserManagementService.cs"));

        Assert.DoesNotContain(
            "IManagementUserContextStore",
            source,
            StringComparison.Ordinal);
        Assert.DoesNotContain(
            "IUserPermissionManagementService",
            source,
            StringComparison.Ordinal);
        Assert.DoesNotContain(
            "IReadOnlyList<string> Roles",
            source,
            StringComparison.Ordinal);
        Assert.DoesNotContain(
            "IReadOnlySet<string> ContextIds",
            source,
            StringComparison.Ordinal);
    }

    private static string ResolveManagementUiSource()
    {
        var repositoryRoot = ResolveIdentityRepository();
        var sourceRoot = Path.GetFullPath(Path.Combine(
            repositoryRoot,
            "..",
            "sufficit-identity-ui",
            "src",
            "Sufficit.Identity.UI.Management"));

        if (!Directory.Exists(sourceRoot))
        {
            throw new DirectoryNotFoundException(
                $"Management UI source was not found at '{sourceRoot}'.");
        }

        return sourceRoot;
    }

    private static string ResolveIdentityRepository()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);

        while (directory is not null
               && !File.Exists(Path.Combine(
                   directory.FullName,
                   "Sufficit.Identity.sln")))
        {
            directory = directory.Parent;
        }

        return directory?.FullName
            ?? throw new DirectoryNotFoundException(
                "Could not locate the Sufficit Identity repository root.");
    }
}
