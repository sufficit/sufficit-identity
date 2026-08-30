using Xunit;

namespace Sufficit.Identity.Tests;

public sealed partial class ManagementUiArchitectureTests
{
    private static readonly string[] ForbiddenUiDependencies =
    [
        "AppDbContext",
        "DbContext",
        "ApplicationUser",
        "UserManager<",
        "SignInManager<",
        "Microsoft.EntityFrameworkCore",
        "OpenIddict",
        "IOpenIddictApplicationManager",
        "IOpenIddictAuthorizationManager",
        "IOpenIddictScopeManager",
        "IOpenIddictTokenManager",
    ];

    [Fact]
    public void User_interfaces_reference_only_neutral_application_contracts()
    {
        var repository = ResolveIdentityRepository();
        var projects = new[]
        {
            Path.Combine(
                repository,
                "src",
                "ui",
                "Sufficit.Identity.UI",
                "Sufficit.Identity.UI.csproj"),
            Path.Combine(
                repository,
                "src",
                "ui",
                "Sufficit.Identity.UI.Management",
                "Sufficit.Identity.UI.Management.csproj"),
        };

        foreach (var path in projects)
        {
            var project = File.ReadAllText(path);
            Assert.Contains(
                "Sufficit.Identity.Application.Abstractions.csproj",
                project,
                StringComparison.Ordinal);
            Assert.DoesNotContain(
                "Sufficit.Identity.Core.csproj",
                project,
                StringComparison.Ordinal);
            Assert.DoesNotContain(
                "Sufficit.Identity.Management.csproj",
                project,
                StringComparison.Ordinal);
            Assert.DoesNotContain(
                "Sufficit.Identity.STS.csproj",
                project,
                StringComparison.Ordinal);
        }
    }

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

    private static string ResolveManagementUiSource()
    {
        var repositoryRoot = ResolveIdentityRepository();
        var sourceRoot = Path.GetFullPath(Path.Combine(
            repositoryRoot,
            "src",
            "ui",
            "Sufficit.Identity.UI.Management"));

        if (!Directory.Exists(sourceRoot))
        {
            throw new DirectoryNotFoundException(
                $"Management UI source was not found at '{sourceRoot}'.");
        }

        return sourceRoot;
    }

    private static string ResolvePublicUiSource()
    {
        var repositoryRoot = ResolveIdentityRepository();
        var sourceRoot = Path.GetFullPath(Path.Combine(
            repositoryRoot,
            "src",
            "ui",
            "Sufficit.Identity.UI"));

        if (!Directory.Exists(sourceRoot))
        {
            throw new DirectoryNotFoundException(
                $"Public UI source was not found at '{sourceRoot}'.");
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
