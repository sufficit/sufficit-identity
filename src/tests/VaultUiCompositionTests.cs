using System.Xml.Linq;
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
        var adminUserPage = File.ReadAllText(Path.Combine(
            root, "src", "ui", "Sufficit.Identity.UI.Vault", "Components",
            "Pages", "AdminUserVault.razor"));
        var dataSource = File.ReadAllText(Path.Combine(
            root, "src", "ui", "Sufficit.Identity.UI.Vault", "Data",
            "VaultDataSource.cs"));
        var policies = File.ReadAllText(Path.Combine(
            root, "src", "ui", "Sufficit.Identity.UI.Vault",
            "ServiceCollectionExtensions.cs"));
        var css = File.ReadAllText(Path.Combine(
            root, "src", "ui", "Sufficit.Identity.UI.Vault", "wwwroot",
            "vault.css"));
        var portuguese = XDocument.Load(Path.Combine(
                root, "src", "ui", "Sufficit.Identity.UI.Vault", "Resources",
                "VaultResource.pt-BR.resx"))
            .Root!.Elements("data")
            .ToDictionary(
                data => (string)data.Attribute("name")!,
                data => (string?)data.Element("value") ?? string.Empty,
                StringComparer.Ordinal);

        Assert.Contains("Sufficit.Identity.Application.Abstractions", project,
            StringComparison.Ordinal);
        Assert.DoesNotContain("Sufficit.Identity.Core", project,
            StringComparison.Ordinal);
        Assert.DoesNotContain("DbContext", userPage, StringComparison.Ordinal);
        Assert.DoesNotContain("Ciphertext", userPage, StringComparison.Ordinal);
        Assert.Contains("@page \"/vault\"", userPage, StringComparison.Ordinal);
        AssertLocalized(userPage, portuguese,
            "Vault.UserVault.ManagedCredentialHeading", "Credenciais conectadas");
        AssertLocalized(userPage, portuguese,
            "Vault.UserVault.ManagedByApp", "Gerenciada pelo aplicativo");
        Assert.Contains("LoadPersonalOverviewAsync", userPage,
            StringComparison.Ordinal);
        Assert.Contains("<AuthorizeView Policy=\"@VaultUiPolicies.Admin\">",
            userPage, StringComparison.Ordinal);
        Assert.Contains("Href=\"/vault/admin\"", userPage,
            StringComparison.Ordinal);
        AssertLocalized(userPage, portuguese,
            "Vault.UserVault.AdminEntryHeading", "Administração global");
        AssertLocalized(userPage, portuguese,
            "Vault.UserVault.AdminEntryBody",
            "Credenciais pessoais permanecem isoladas por usuário");
        Assert.Contains("@page \"/vault/admin\"", adminPage,
            StringComparison.Ordinal);
        Assert.Contains("@page \"/management/vault\"", adminPage,
            StringComparison.Ordinal);
        AssertLocalized(adminPage, portuguese,
            "Vault.AdminVault.UserVaultsTab", "Vaults de usuários");
        AssertLocalized(adminPage, portuguese,
            "Vault.AdminVault.GlobalSecretsHeading", "Segredos globais");
        Assert.Contains("ListVaultUsersAsync", adminPage,
            StringComparison.Ordinal);
        Assert.Contains("@page \"/vault/admin/users/{OwnerSubject}\"",
            adminUserPage, StringComparison.Ordinal);
        AssertLocalized(adminUserPage, portuguese,
            "Vault.AdminUserVault.ManagedCredentialsHeading", "Credenciais conectadas");
        AssertLocalized(adminUserPage, portuguese,
            "Vault.AdminUserVault.PersonalSecretsHeading", "Segredos pessoais");
        AssertLocalized(adminUserPage, portuguese,
            "Vault.AdminUserVault.CleanupHeading", "Limpar o Vault deste usuário");
        Assert.DoesNotContain("Ciphertext", adminPage, StringComparison.Ordinal);
        Assert.DoesNotContain("Ciphertext", adminUserPage, StringComparison.Ordinal);
        Assert.DoesNotContain("ResolveAsync", dataSource, StringComparison.Ordinal);
        Assert.Contains("VaultUiPolicies.AdminManage", adminUserPage,
            StringComparison.Ordinal);
        Assert.Contains("ManagementCapabilities.VaultSecretsManage", policies,
            StringComparison.Ordinal);
        Assert.Contains("@media (max-width: 640px)", css,
            StringComparison.Ordinal);
        Assert.Contains("prefers-reduced-motion", css,
            StringComparison.Ordinal);
        Assert.Contains(".vault-list__status", css,
            StringComparison.Ordinal);
        Assert.Contains(".vault-admin-entry", css,
            StringComparison.Ordinal);
        Assert.Contains(".vault-admin-entry .sui-btn", css,
            StringComparison.Ordinal);
        Assert.Contains(".vault-admin-tabs", css,
            StringComparison.Ordinal);
        Assert.Contains(".vault-user-row", css,
            StringComparison.Ordinal);
        Assert.Contains(".vault-danger-zone", css,
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
        var vaultModule = File.ReadAllText(Path.Combine(
            root, "src", "ui", "Sufficit.Identity.UI.Vault",
            "VaultUiIdentityModule.cs"));
        Assert.Contains(
            "mapEndpoints: !uiHostingOptions.Public.IsEmbedded",
            vaultModule,
            StringComparison.Ordinal);
        Assert.Contains(
            "typeof(Sufficit.Identity.UI.Vault.ServiceCollectionExtensions).Assembly",
            program,
            StringComparison.Ordinal);
    }

    [Fact]
    public void Manage_page_exposes_only_available_and_authorized_resources()
    {
        var root = ResolveIdentityRepository();
        var layout = File.ReadAllText(Path.Combine(
            root, "src", "ui", "Sufficit.Identity.UI", "Components",
            "Layout", "MainLayout.razor"));
        var manage = File.ReadAllText(Path.Combine(
            root, "src", "ui", "Sufficit.Identity.UI", "Pages",
            "Manage", "Index.razor"));
        var css = File.ReadAllText(Path.Combine(
            root, "src", "ui", "Sufficit.Identity.UI", "wwwroot",
            "css", "site.css"));
        var policies = File.ReadAllText(Path.Combine(
            root, "src", "ui", "Sufficit.Identity.UI.Abstractions",
            "Hosting", "UiAuthorizationPolicies.cs"));
        var managementComposition = File.ReadAllText(Path.Combine(
            root, "src", "ui", "Sufficit.Identity.UI.Management",
            "ServiceCollectionExtensions.cs"));

        Assert.DoesNotContain("href=\"/vault\"", layout,
            StringComparison.Ordinal);
        Assert.DoesNotContain("nav-link--vault", css,
            StringComparison.Ordinal);
        Assert.Contains("UiModules.HasSurface(UiSurface.Vault)", manage,
            StringComparison.Ordinal);
        Assert.Contains("Sufficit:Vault:Enabled", manage,
            StringComparison.Ordinal);
        Assert.Contains("UiModules.HasSurface(UiSurface.Management)", manage,
            StringComparison.Ordinal);
        Assert.Contains("AuthorizationService.AuthorizeAsync", manage,
            StringComparison.Ordinal);
        Assert.Contains("UiAuthorizationPolicies.ManagementAccess", manage,
            StringComparison.Ordinal);
        Assert.Contains("@if (AdditionalResourcesAvailable)", manage,
            StringComparison.Ordinal);
        Assert.Contains("href=\"/vault\"", manage, StringComparison.Ordinal);
        Assert.Contains("href=\"/management/\"", manage, StringComparison.Ordinal);
        Assert.Contains("data-enhance-nav=\"false\"", manage,
            StringComparison.Ordinal);
        Assert.Contains("Manage.StoredCredentials", manage,
            StringComparison.Ordinal);
        Assert.Contains("Manage.SystemManagement", manage,
            StringComparison.Ordinal);
        Assert.Contains(".manage-resources", css, StringComparison.Ordinal);
        Assert.Contains(
            ".manage-resources__heading {\n    margin: 0 0 var(--space-5);",
            css,
            StringComparison.Ordinal);
        Assert.Contains("sufficit-identity-management-ui-access", policies,
            StringComparison.Ordinal);
        Assert.Contains(
            "public const string Access = UiAuthorizationPolicies.ManagementAccess;",
            managementComposition,
            StringComparison.Ordinal);

        var personalData = manage.IndexOf(
            "Manage.PersonalData", StringComparison.Ordinal);
        var resources = manage.IndexOf(
            "Manage.AdditionalResources", StringComparison.Ordinal);
        Assert.True(personalData >= 0 && personalData < resources);
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

    /// <summary>
    /// The page renders the text through its resource key, and the pt-BR
    /// satellite keeps the wording the page used before localization.
    /// </summary>
    private static void AssertLocalized(
        string source,
        IReadOnlyDictionary<string, string> portuguese,
        string key,
        string expectedPortuguese)
    {
        Assert.Contains($"\"{key}\"", source, StringComparison.Ordinal);
        Assert.True(portuguese.TryGetValue(key, out var value), $"Missing pt-BR resource {key}.");
        Assert.Contains(expectedPortuguese, value, StringComparison.Ordinal);
    }
}
