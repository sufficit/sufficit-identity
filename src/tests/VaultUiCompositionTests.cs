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
        Assert.Contains("Credenciais conectadas", userPage,
            StringComparison.Ordinal);
        Assert.Contains("Gerenciada pelo aplicativo", userPage,
            StringComparison.Ordinal);
        Assert.Contains("LoadPersonalOverviewAsync", userPage,
            StringComparison.Ordinal);
        Assert.Contains("@page \"/management/vault\"", adminPage,
            StringComparison.Ordinal);
        Assert.Contains("@media (max-width: 640px)", css,
            StringComparison.Ordinal);
        Assert.Contains("prefers-reduced-motion", css,
            StringComparison.Ordinal);
        Assert.Contains(".vault-list__status", css,
            StringComparison.Ordinal);
        Assert.Contains(".vault-layout { min-height: 100vh; background: var(--vault-bg); }",
            css, StringComparison.Ordinal);
        Assert.DoesNotContain("body { margin: 0; background: var(--vault-bg); }",
            css, StringComparison.Ordinal);
    }

    [Fact]
    public void Embedded_vault_shares_the_public_blazor_endpoint()
    {
        var root = ResolveIdentityRepository();
        var vaultExtensions = File.ReadAllText(Path.Combine(
            root, "src", "ui", "Sufficit.Identity.UI.Vault",
            "ServiceCollectionExtensions.cs"));
        var publicExtensions = File.ReadAllText(Path.Combine(
            root, "src", "ui", "Sufficit.Identity.UI",
            "ServiceCollectionExtensions.cs"));
        var program = File.ReadAllText(Path.Combine(
            root, "src", "server", "Program.cs"));

        Assert.Contains("bool mapEndpoints = true", vaultExtensions,
            StringComparison.Ordinal);
        Assert.Contains("if (mapEndpoints)", vaultExtensions,
            StringComparison.Ordinal);
        Assert.Contains("razorComponents.AddAdditionalAssemblies",
            publicExtensions, StringComparison.Ordinal);
        Assert.Contains(
            "mapEndpoints: !uiHostingOptions.Public.IsEmbedded",
            program,
            StringComparison.Ordinal);
        Assert.Contains(
            "typeof(Sufficit.Identity.UI.Vault.ServiceCollectionExtensions).Assembly",
            program,
            StringComparison.Ordinal);
    }

    [Fact]
    public void Authenticated_header_exposes_vault_only_when_backend_and_surface_are_enabled()
    {
        var root = ResolveIdentityRepository();
        var layout = File.ReadAllText(Path.Combine(
            root, "src", "ui", "Sufficit.Identity.UI", "Components",
            "Layout", "MainLayout.razor"));
        var css = File.ReadAllText(Path.Combine(
            root, "src", "ui", "Sufficit.Identity.UI", "wwwroot",
            "css", "site.css"));

        Assert.Contains("UiModules.HasSurface(UiSurface.Vault)", layout,
            StringComparison.Ordinal);
        Assert.Contains("Sufficit:Vault:Enabled", layout,
            StringComparison.Ordinal);
        Assert.Contains("<AuthorizeView>", layout, StringComparison.Ordinal);
        Assert.Contains("@if (VaultAvailable)", layout, StringComparison.Ordinal);
        Assert.Contains("href=\"/vault\"", layout, StringComparison.Ordinal);
        Assert.Contains("Layout.MyVault", layout, StringComparison.Ordinal);

        var culture = layout.IndexOf("<CultureSelector />", StringComparison.Ordinal);
        var vault = layout.IndexOf("href=\"/vault\"", StringComparison.Ordinal);
        var logout = layout.IndexOf("href=\"/account/logout\"", StringComparison.Ordinal);
        Assert.True(culture >= 0 && culture < vault && vault < logout);

        Assert.Contains(".nav-link--vault", css, StringComparison.Ordinal);
        Assert.Contains("@media (max-width: 400px)", css,
            StringComparison.Ordinal);
        Assert.Contains(".nav-link--vault .nav-link__label { display: none; }",
            css, StringComparison.Ordinal);
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
