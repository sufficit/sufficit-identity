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
    public void Runtime_surfaces_project_the_canonical_overview_contract()
    {
        var uiRoot = ResolveManagementUiSource();
        var pages = Path.Combine(uiRoot, "Components", "Pages");
        var layout = File.ReadAllText(Path.Combine(
            uiRoot,
            "Components",
            "Layout",
            "MainLayout.razor"));
        var navigation = File.ReadAllText(Path.Combine(
            uiRoot,
            "Components",
            "Layout",
            "NavMenu.razor"));
        var home = File.ReadAllText(Path.Combine(pages, "Home.razor"));
        var settings = File.ReadAllText(Path.Combine(pages, "Settings.razor"));
        var combined = layout + navigation + home + settings;

        Assert.Contains(
            "ManagementOverviewDataSource",
            layout,
            StringComparison.Ordinal);
        Assert.Contains(
            "ManagementModulePresentations",
            navigation,
            StringComparison.Ordinal);
        Assert.Contains(
            "CascadingParameter(Name = \"ManagementOverview\")",
            home,
            StringComparison.Ordinal);
        Assert.Contains(
            "CascadingParameter(Name = \"ManagementOverview\")",
            settings,
            StringComparison.Ordinal);
        Assert.DoesNotContain("IOptions<", home + settings, StringComparison.Ordinal);
        Assert.DoesNotContain(
            "IWebHostEnvironment",
            layout,
            StringComparison.Ordinal);
        Assert.DoesNotContain(
            "Prontidão dos módulos",
            combined,
            StringComparison.Ordinal);
        Assert.DoesNotContain("5 de 5", combined, StringComparison.Ordinal);
        Assert.DoesNotContain(
            "Listagem incorporada",
            combined,
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
    public void Overview_controller_is_only_an_http_adapter()
    {
        var controller = File.ReadAllText(Path.Combine(
            ResolveIdentityRepository(),
            "src",
            "management",
            "Controllers",
            "OverviewController.cs"));

        Assert.Contains(
            "IManagementOverviewService",
            controller,
            StringComparison.Ordinal);
        Assert.DoesNotContain("IOptions<", controller, StringComparison.Ordinal);
        Assert.DoesNotContain("IHostEnvironment", controller, StringComparison.Ordinal);
        Assert.DoesNotContain(
            "IManagementEntitlementResolver",
            controller,
            StringComparison.Ordinal);
    }

    [Fact]
    public void Provisioning_adapters_use_only_the_canonical_contract()
    {
        var repositoryRoot = ResolveIdentityRepository();
        var controller = File.ReadAllText(Path.Combine(
            repositoryRoot,
            "src",
            "management",
            "Controllers",
            "ProvisioningController.cs"));
        var dataSource = File.ReadAllText(Path.Combine(
            ResolveManagementUiSource(),
            "Provisioning",
            "ManagementProvisioningDataSource.cs"));

        Assert.Contains(
            "IProvisioningManagementService",
            controller,
            StringComparison.Ordinal);
        Assert.Contains(
            "IProvisioningManagementService",
            dataSource,
            StringComparison.Ordinal);
        Assert.DoesNotContain(
            "OpenIddictManifestProvisioner",
            controller,
            StringComparison.Ordinal);
        Assert.DoesNotContain("DbContext", controller, StringComparison.Ordinal);
        Assert.DoesNotContain("DbContext", dataSource, StringComparison.Ordinal);
        Assert.DoesNotContain(
            "IOpenIddictApplicationManager",
            dataSource,
            StringComparison.Ordinal);
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
    public void Session_and_authorization_controllers_are_only_http_adapters()
    {
        var controllers = Path.Combine(
            ResolveIdentityRepository(),
            "src",
            "management",
            "Controllers");
        var sessions = File.ReadAllText(Path.Combine(
            controllers,
            "SessionsController.cs"));
        var authorizations = File.ReadAllText(Path.Combine(
            controllers,
            "AuthorizationsController.cs"));

        Assert.Contains(
            "ISessionManagementService",
            sessions,
            StringComparison.Ordinal);
        Assert.Contains(
            "IAuthorizationManagementService",
            authorizations,
            StringComparison.Ordinal);
        Assert.DoesNotContain("DbContext", sessions, StringComparison.Ordinal);
        Assert.DoesNotContain("DbContext", authorizations, StringComparison.Ordinal);
        Assert.DoesNotContain(
            "IOpenIddictTokenManager",
            sessions,
            StringComparison.Ordinal);
        Assert.DoesNotContain(
            "IOpenIddictAuthorizationManager",
            authorizations,
            StringComparison.Ordinal);
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
    public void Claims_are_user_contextual_and_protocol_surfaces_stay_separate()
    {
        var pages = Path.Combine(
            ResolveManagementUiSource(),
            "Components",
            "Pages");
        var claims = File.ReadAllText(Path.Combine(pages, "Claims.razor"));
        var claimCreate = File.ReadAllText(Path.Combine(
            pages,
            "ClaimCreate.razor"));
        var claimDetail = File.ReadAllText(Path.Combine(
            pages,
            "ClaimDetail.razor"));
        var scopes = File.ReadAllText(Path.Combine(pages, "Scopes.razor"));
        var sessions = File.ReadAllText(Path.Combine(pages, "Sessions.razor"));
        var authorizations = File.ReadAllText(Path.Combine(
            pages,
            "Authorizations.razor"));
        var userDetail = File.ReadAllText(Path.Combine(
            pages,
            "UserDetail.razor"));
        var navigation = File.ReadAllText(Path.Combine(
            ResolveManagementUiSource(),
            "Components",
            "Layout",
            "NavMenu.razor"));
        var presentations = File.ReadAllText(Path.Combine(
            ResolveManagementUiSource(),
            "Overview",
            "ManagementModulePresentation.cs"));

        Assert.False(File.Exists(Path.Combine(pages, "Access.razor")));
        Assert.Contains("ManagementClaimDataSource", claims, StringComparison.Ordinal);
        Assert.Contains("ManagementScopeDataSource", scopes, StringComparison.Ordinal);
        Assert.Contains(
            "@page \"/claims\"",
            claims,
            StringComparison.Ordinal);
        Assert.Contains(
            "claims?user={Uri.EscapeDataString(Id)}",
            userDetail,
            StringComparison.Ordinal);
        Assert.Contains(
            "[SupplyParameterFromQuery(Name = \"user\")]",
            claims,
            StringComparison.Ordinal);
        Assert.Contains(
            "@page \"/claims/new\"",
            claimCreate,
            StringComparison.Ordinal);
        Assert.Contains(
            "@page \"/claims/edit\"",
            claimDetail,
            StringComparison.Ordinal);
        Assert.Contains(
            "[SupplyParameterFromQuery(Name = \"claim\")]",
            claimDetail,
            StringComparison.Ordinal);
        Assert.DoesNotContain(
            "@page \"/users/{UserId}/claims",
            claims + claimCreate + claimDetail,
            StringComparison.Ordinal);
        Assert.DoesNotContain("href=\"claims\"", navigation, StringComparison.Ordinal);
        Assert.Contains("\"scopes\"", presentations, StringComparison.Ordinal);
        Assert.Contains(
            "ManagementSessionDataSource",
            sessions,
            StringComparison.Ordinal);
        Assert.Contains(
            "ManagementAuthorizationDataSource",
            authorizations,
            StringComparison.Ordinal);
        Assert.Contains("\"sessions\"", presentations, StringComparison.Ordinal);
        Assert.Contains(
            "\"authorizations\"",
            presentations,
            StringComparison.Ordinal);
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
