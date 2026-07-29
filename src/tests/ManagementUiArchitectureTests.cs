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
