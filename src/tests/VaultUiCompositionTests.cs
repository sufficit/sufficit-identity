using Xunit;

namespace Sufficit.Identity.Tests;

public sealed class VaultUiCompositionTests
{
    [Fact]
    public void Vault_ui_is_a_contract_driven_module_with_mobile_routes()
    {
        var root = ResolveIdentityRepository();
        var project = File.ReadAllText(Path.Combine(
            root, "src", "ui", "Sufficit.Identity.UI.Vault",
            "Sufficit.Identity.UI.Vault.csproj"));
        var userPage = File.ReadAllText(Path.Combine(
            root, "src", "ui", "Sufficit.Identity.UI.Vault", "Components",
            "Pages", "UserVault.razor"));
        var adminPage = File.ReadAllText(Path.Combine(
            root, "src", "ui", "Sufficit.Identity.UI.Vault", "Components",
            "Pages", "AdminVault.razor"));
        var css = File.ReadAllText(Path.Combine(
            root, "src", "ui", "Sufficit.Identity.UI.Vault", "wwwroot",
            "vault.css"));

        Assert.Contains("Sufficit.Identity.Application.Abstractions", project,
            StringComparison.Ordinal);
        Assert.DoesNotContain("Sufficit.Identity.Core", project,
            StringComparison.Ordinal);
        Assert.DoesNotContain("DbContext", userPage, StringComparison.Ordinal);
        Assert.DoesNotContain("Ciphertext", userPage, StringComparison.Ordinal);
        Assert.Contains("@page \"/vault\"", userPage, StringComparison.Ordinal);
        Assert.Contains("@page \"/management/vault\"", adminPage,
            StringComparison.Ordinal);
        Assert.Contains("@media (max-width: 640px)", css,
            StringComparison.Ordinal);
        Assert.Contains("prefers-reduced-motion", css,
            StringComparison.Ordinal);
    }

    private static string ResolveIdentityRepository()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null
               && !File.Exists(Path.Combine(directory.FullName, "Sufficit.Identity.sln")))
        {
            directory = directory.Parent;
        }

        return directory?.FullName
            ?? throw new DirectoryNotFoundException("Identity repository root was not found.");
    }
}
