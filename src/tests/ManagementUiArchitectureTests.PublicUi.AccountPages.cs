using Xunit;

namespace Sufficit.Identity.Tests;

public sealed partial class ManagementUiArchitectureTests
{
    [Fact]
    public void Migrated_account_pages_use_only_the_self_service_contract()
    {
        var pages = Path.Combine(
            ResolvePublicUiSource(),
            "Pages",
            "Manage");
        var migratedPages = new[]
        {
            "Index.razor",
            "ChangePassword.razor",
            "PersonalData.razor",
            "DeleteAccount.razor",
        };

        foreach (var page in migratedPages)
        {
            var source = File.ReadAllText(Path.Combine(pages, page));
            Assert.Contains(
                "IAccountSelfService",
                source,
                StringComparison.Ordinal);
            foreach (var forbidden in ForbiddenUiDependencies)
            {
                Assert.DoesNotContain(
                    forbidden,
                    source,
                    StringComparison.Ordinal);
            }
        }

        var selfService = File.ReadAllText(Path.Combine(
            ResolveIdentityRepository(),
            "src",
            "sts",
            "AccountSelfService.cs"));
        Assert.Contains(
            "accountLifecycle.DeleteAsync",
            selfService,
            StringComparison.Ordinal);
        Assert.DoesNotContain(
            "userManager.DeleteAsync",
            selfService,
            StringComparison.Ordinal);
    }

    [Fact]
    public void Account_access_pages_use_only_the_canonical_access_contract()
    {
        var pages = Path.Combine(
            ResolvePublicUiSource(),
            "Pages",
            "Manage");
        var grants = File.ReadAllText(Path.Combine(pages, "Grants.razor"));
        var sessions = File.ReadAllText(Path.Combine(pages, "Sessions.razor"));

        Assert.Contains("IAccountAccessService", grants, StringComparison.Ordinal);
        Assert.Contains("IAccountAccessService", sessions, StringComparison.Ordinal);
        Assert.Contains(
            "GetConnectedApplicationsAsync",
            grants,
            StringComparison.Ordinal);
        Assert.Contains("GetSessionsAsync", sessions, StringComparison.Ordinal);
        foreach (var forbidden in ForbiddenUiDependencies)
        {
            Assert.DoesNotContain(forbidden, grants, StringComparison.Ordinal);
            Assert.DoesNotContain(forbidden, sessions, StringComparison.Ordinal);
        }

        var service = File.ReadAllText(Path.Combine(
            ResolveIdentityRepository(),
            "src",
            "sts",
            "AccountAccessService.cs"));
        Assert.Contains(
            "RevokeByAuthorizationIdAsync",
            service,
            StringComparison.Ordinal);
        Assert.Contains("TryRevokeAsync", service, StringComparison.Ordinal);
        Assert.DoesNotContain("DeleteAsync", service, StringComparison.Ordinal);
    }

    [Fact]
    public void External_identity_page_uses_only_the_canonical_account_contract()
    {
        var page = File.ReadAllText(Path.Combine(
            ResolvePublicUiSource(),
            "Pages",
            "Manage",
            "ExternalLogins.razor"));
        Assert.Contains(
            "IAccountExternalIdentityService",
            page,
            StringComparison.Ordinal);
        Assert.Contains("GetOverviewAsync", page, StringComparison.Ordinal);
        Assert.Contains("RemoveAsync", page, StringComparison.Ordinal);
        foreach (var forbidden in ForbiddenUiDependencies)
        {
            Assert.DoesNotContain(forbidden, page, StringComparison.Ordinal);
        }

        var adapter = File.ReadAllText(Path.Combine(
            ResolveIdentityRepository(),
            "src",
            "sts",
            "AspNetCoreIdentityAccountExternalIdentityService.cs"));
        Assert.Contains(
            ": IAccountExternalIdentityService",
            adapter,
            StringComparison.Ordinal);
        Assert.Contains("last-sign-in-method", adapter, StringComparison.Ordinal);

        var controller = File.ReadAllText(Path.Combine(
            ResolveIdentityRepository(),
            "src",
            "sts",
            "Controllers",
            "ExternalLoginController.cs"));
        Assert.Contains(
            "IExternalSignInService",
            controller,
            StringComparison.Ordinal);
        Assert.Contains(
            "externalSignInService.CompleteAsync",
            controller,
            StringComparison.Ordinal);

        var externalAdapter = File.ReadAllText(Path.Combine(
            ResolveIdentityRepository(),
            "src",
            "sts",
            "AspNetCoreIdentityExternalSignInService.cs"));
        Assert.Contains(
            ": IExternalSignInService",
            externalAdapter,
            StringComparison.Ordinal);
        Assert.Contains(
            "IAccountExternalIdentityService",
            externalAdapter,
            StringComparison.Ordinal);
    }

    [Fact]
    public void Two_factor_page_uses_only_the_canonical_account_contract()
    {
        var page = File.ReadAllText(Path.Combine(
            ResolvePublicUiSource(),
            "Pages",
            "Manage",
            "TwoFactor.razor"));

        Assert.Contains(
            "IAccountTwoFactorService",
            page,
            StringComparison.Ordinal);
        Assert.Contains("BeginSetupAsync", page, StringComparison.Ordinal);
        Assert.Contains("EnableAsync", page, StringComparison.Ordinal);
        Assert.Contains(
            "GenerateRecoveryCodesAsync",
            page,
            StringComparison.Ordinal);
        foreach (var forbidden in ForbiddenUiDependencies)
        {
            Assert.DoesNotContain(forbidden, page, StringComparison.Ordinal);
        }

        var adapter = File.ReadAllText(Path.Combine(
            ResolveIdentityRepository(),
            "src",
            "sts",
            "AspNetCoreIdentityAccountTwoFactorService.cs"));
        Assert.Contains(
            ": IAccountTwoFactorService",
            adapter,
            StringComparison.Ordinal);
        Assert.Contains(
            "BuildAuthenticatorUri",
            adapter,
            StringComparison.Ordinal);
        Assert.Contains(
            "Uri.EscapeDataString",
            adapter,
            StringComparison.Ordinal);
        Assert.DoesNotContain("QRCoder", adapter, StringComparison.Ordinal);
    }

    [Fact]
    public void Two_factor_page_localizes_all_actions_and_feedback()
    {
        var page = File.ReadAllText(Path.Combine(
            ResolvePublicUiSource(),
            "Pages",
            "Manage",
            "TwoFactor.razor"));

        var hardcodedCopy = new[]
        {
            "Carregando configuração",
            "Tentar novamente",
            "Copiar códigos",
            "Já guardei os códigos",
            "Reconfigurar autenticador",
            "Gerar novos códigos",
            "Desativar duas etapas",
            "Código de verificação",
            "Ativar duas etapas",
            "Configurar aplicativo autenticador",
            "Não foi possível concluir",
        };

        Assert.All(
            hardcodedCopy,
            text => Assert.DoesNotContain(text, page, StringComparison.Ordinal));
        Assert.Contains(
            "ManageTwoFactor.ConfigureAuthenticator",
            page,
            StringComparison.Ordinal);
        Assert.Contains(
            "ManageTwoFactor.GenerateRecoveryCodesConfirm",
            page,
            StringComparison.Ordinal);
        Assert.Contains(
            "ManageTwoFactor.Error.InvalidCode",
            page,
            StringComparison.Ordinal);
    }

    [Fact]
    public void Interactive_sign_in_pages_use_only_the_canonical_contract()
    {
        var publicUi = ResolvePublicUiSource();
        var accountPages = Path.Combine(publicUi, "Pages", "Account");
        var login = File.ReadAllText(Path.Combine(accountPages, "Login.razor"));
        var twoFactor = File.ReadAllText(Path.Combine(
            accountPages,
            "LoginWith2fa.razor"));
        var recovery = File.ReadAllText(Path.Combine(
            accountPages,
            "LoginWithRecoveryCode.razor"));
        var logout = File.ReadAllText(Path.Combine(accountPages, "Logout.razor"));
        var pages = login + twoFactor + recovery + logout;

        Assert.Contains("IInteractiveSignInService", login, StringComparison.Ordinal);
        Assert.Contains(
            "action=\"/account/login/password\"",
            login,
            StringComparison.Ordinal);
        Assert.DoesNotContain("HandleLoginAsync", login, StringComparison.Ordinal);
        Assert.Contains(
            "[SupplyParameterFromQuery(Name = \"ReturnUrl\")]",
            login,
            StringComparison.Ordinal);
        Assert.Contains(
            "[SupplyParameterFromQuery(Name = \"returnUrl\")]",
            login,
            StringComparison.Ordinal);
        Assert.Contains("QueryHelpers.ParseQuery", login, StringComparison.Ordinal);
        Assert.Contains("HttpContextAccessor.HttpContext", login, StringComparison.Ordinal);
        Assert.Contains("IInteractiveSignInService", twoFactor, StringComparison.Ordinal);
        Assert.Contains(
            "action=\"/account/login/2fa\"",
            twoFactor,
            StringComparison.Ordinal);
        Assert.DoesNotContain(
            "AuthenticatorSignInCommand",
            twoFactor,
            StringComparison.Ordinal);
        Assert.Contains("IInteractiveSignInService", recovery, StringComparison.Ordinal);
        Assert.Contains(
            "action=\"/account/login/recoverycode\"",
            recovery,
            StringComparison.Ordinal);
        Assert.DoesNotContain(
            "RecoveryCodeSignInAsync",
            recovery,
            StringComparison.Ordinal);
        Assert.DoesNotContain("AuthenticationScheme", login, StringComparison.Ordinal);
        foreach (var forbidden in ForbiddenUiDependencies)
        {
            Assert.DoesNotContain(forbidden, pages, StringComparison.Ordinal);
        }

        var repository = ResolveIdentityRepository();
        var passwordLoginController = File.ReadAllText(Path.Combine(
            repository,
            "src",
            "sts",
            "Controllers",
            "PasswordLoginController.cs"));
        Assert.Contains(
            "IInteractiveSignInService",
            passwordLoginController,
            StringComparison.Ordinal);
        Assert.Contains(
            "PasswordSignInCommand",
            passwordLoginController,
            StringComparison.Ordinal);
        Assert.Contains(
            "ValidateRequestAsync",
            passwordLoginController,
            StringComparison.Ordinal);

        var twoFactorLoginController = File.ReadAllText(Path.Combine(
            repository,
            "src",
            "sts",
            "Controllers",
            "TwoFactorLoginController.cs"));
        Assert.Contains(
            "AuthenticatorSignInCommand",
            twoFactorLoginController,
            StringComparison.Ordinal);
        Assert.Contains(
            "RecoveryCodeSignInAsync",
            twoFactorLoginController,
            StringComparison.Ordinal);
        Assert.Contains(
            "ValidateRequestAsync",
            twoFactorLoginController,
            StringComparison.Ordinal);
        Assert.Contains(
            "ParseBoolean",
            twoFactorLoginController,
            StringComparison.Ordinal);

        var contract = File.ReadAllText(Path.Combine(
            repository,
            "src",
            "application",
            "Sufficit.Identity.Application.Abstractions",
            "Accounts",
            "InteractiveSignInService.cs"));
        var adapter = File.ReadAllText(Path.Combine(
            repository,
            "src",
            "sts",
            "AspNetCoreIdentityInteractiveSignInService.cs"));
        Assert.Contains("interface IInteractiveSignInService", contract, StringComparison.Ordinal);
        Assert.DoesNotContain("Microsoft.AspNetCore.Identity", contract, StringComparison.Ordinal);
        Assert.Contains(": IInteractiveSignInService", adapter, StringComparison.Ordinal);
        Assert.Contains("SignInManager<ApplicationUser>", adapter, StringComparison.Ordinal);
    }

    [Fact]
    public void Pending_mfa_recovery_clears_remembered_device_and_returns_to_login()
    {
        var home = File.ReadAllText(Path.Combine(
            ResolveManagementUiSource(),
            "Components",
            "Pages",
            "Home.razor"));
        // The controller is a partial class split across files by concern, so
        // the assertions below must look at every part rather than pin one
        // path — the logout branch lives in AuthorizationController.Logout.cs.
        var controller = string.Join(
            Environment.NewLine,
            Directory.EnumerateFiles(
                    Path.Combine(
                        ResolveIdentityRepository(),
                        "src",
                        "sts",
                        "Controllers"),
                    "AuthorizationController*.cs")
                .OrderBy(path => path, StringComparer.Ordinal)
                .Select(File.ReadAllText));

        Assert.Contains("name=\"force_mfa\"", home, StringComparison.Ordinal);
        Assert.DoesNotContain(
            "class=\"button button--",
            home,
            StringComparison.Ordinal);
        Assert.Contains(
            "<SUIButton ButtonTypeValue=\"SUIButtonType.Submit\"",
            home,
            StringComparison.Ordinal);
        Assert.Contains(
            "ForgetTwoFactorClientAsync",
            controller,
            StringComparison.Ordinal);
        Assert.Contains(
            "\"/account/login\"",
            controller,
            StringComparison.Ordinal);
        Assert.Contains(
            "\"/management/\"",
            controller,
            StringComparison.Ordinal);
    }

    [Fact]
    public void Passkey_ui_uses_canonical_contracts_and_real_http_ceremonies()
    {
        var publicUi = ResolvePublicUiSource();
        var page = File.ReadAllText(Path.Combine(
            publicUi,
            "Pages",
            "Manage",
            "Passkeys.razor"));
        var login = File.ReadAllText(Path.Combine(
            publicUi,
            "Pages",
            "Account",
            "Login.razor"));
        var script = File.ReadAllText(Path.Combine(
            publicUi,
            "wwwroot",
            "js",
            "passkeys.js"));
        var controller = File.ReadAllText(Path.Combine(
            ResolveIdentityRepository(),
            "src",
            "sts",
            "Controllers",
            "AccountPasskeysController.cs"));
        var adapter = File.ReadAllText(Path.Combine(
            ResolveIdentityRepository(),
            "src",
            "sts",
            "AspNetCoreIdentityPasskeyService.cs"));

        Assert.Contains("IAccountPasskeyService", page, StringComparison.Ordinal);
        Assert.Contains("passkeys.register", page, StringComparison.Ordinal);
        Assert.Contains("PasskeyService.RenameAsync", page, StringComparison.Ordinal);
        Assert.Contains("new AccountPasskeyRename", page, StringComparison.Ordinal);
        Assert.Contains(
            "L[\"ManagePasskeys.RenameAria\"",
            page,
            StringComparison.Ordinal);
        Assert.Contains(
            "L[\"ManagePasskeys.RemoveAria\"",
            page,
            StringComparison.Ordinal);
        Assert.DoesNotContain("Renomear", page, StringComparison.Ordinal);
        Assert.DoesNotContain("Remover esta passkey", page, StringComparison.Ordinal);
        Assert.DoesNotContain("UserManager<", page, StringComparison.Ordinal);
        Assert.DoesNotContain("SignInManager<", page, StringComparison.Ordinal);
        Assert.Contains("passkeys.signIn", login, StringComparison.Ordinal);
        Assert.DoesNotContain(
            "MakePasskeyRequestOptionsAsync",
            login,
            StringComparison.Ordinal);
        Assert.DoesNotContain("PasskeySignInAsync(credentialJson", login, StringComparison.Ordinal);
        Assert.Contains(
            "/account/passkeys/creation-options",
            script,
            StringComparison.Ordinal);
        Assert.Contains(
            "/account/passkeys/authenticate",
            script,
            StringComparison.Ordinal);
        Assert.Contains(
            "JSON.parse(responseText.trim())",
            script,
            StringComparison.Ordinal);
        Assert.DoesNotContain(
            "headers.get(\"content-type\")",
            script,
            StringComparison.Ordinal);
        Assert.DoesNotContain(
            "@onsubmit=\"RegisterPasskeyAsync\"",
            page,
            StringComparison.Ordinal);
        Assert.DoesNotContain(
            "@onsubmit=\"PasskeySignInAsync\"",
            login,
            StringComparison.Ordinal);
        Assert.Contains(
            "type=\"button\" class=\"btn btn-primary\" disabled=\"@_busy\" @onclick=\"RegisterPasskeyAsync\"",
            page,
            StringComparison.Ordinal);
        Assert.Contains("IAccountPasskeyService", controller, StringComparison.Ordinal);
        Assert.Contains("IPasskeyAuthenticationService", controller, StringComparison.Ordinal);
        Assert.DoesNotContain("UserManager<", controller, StringComparison.Ordinal);
        Assert.DoesNotContain("SignInManager<", controller, StringComparison.Ordinal);
        Assert.Contains(": IAccountPasskeyService", adapter, StringComparison.Ordinal);
        Assert.Contains("IPasskeyAuthenticationService", adapter, StringComparison.Ordinal);
    }
}
