using Xunit;

namespace Sufficit.Identity.Tests;

public sealed class RuntimeHostnameUiTests
{
    [Fact]
    public void Public_and_management_layouts_show_the_processing_server()
    {
        var repository = ResolveRepository();
        var publicLayout = File.ReadAllText(Path.Combine(repository, "src", "ui",
            "Sufficit.Identity.UI", "Components", "Layout", "MainLayout.razor"));
        var managementLayout = File.ReadAllText(Path.Combine(repository, "src", "ui",
            "Sufficit.Identity.UI.Management", "Components", "Layout", "MainLayout.razor"));
        var managementNavigation = File.ReadAllText(Path.Combine(repository, "src", "ui",
            "Sufficit.Identity.UI.Management", "Components", "Layout", "NavMenu.razor"));

        foreach (var layout in new[] { publicLayout, managementLayout })
        {
            Assert.Contains("Sufficit:Runtime:ServerHostName", layout, StringComparison.Ordinal);
            Assert.Contains("Environment.MachineName", layout, StringComparison.Ordinal);
        }

        Assert.Contains("footer-server", publicLayout, StringComparison.Ordinal);
        Assert.Contains("ServerHostName", managementNavigation, StringComparison.Ordinal);
        Assert.Contains("sidebar-instance", managementNavigation, StringComparison.Ordinal);
    }

    private static string ResolveRepository()
    {
        var current = new DirectoryInfo(AppContext.BaseDirectory);
        while (current is not null)
        {
            if (File.Exists(Path.Combine(current.FullName, "Sufficit.Identity.sln")))
                return current.FullName;
            current = current.Parent;
        }

        throw new DirectoryNotFoundException("Identity repository root not found.");
    }
}
