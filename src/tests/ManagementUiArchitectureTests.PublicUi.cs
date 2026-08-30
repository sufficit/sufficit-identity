using Xunit;

namespace Sufficit.Identity.Tests;

public sealed partial class ManagementUiArchitectureTests
{
    /// <summary>
    /// The footer link must follow the host's publication gate rather than
    /// being hardcoded (eval 2026-08-23, S-1): advertising /swagger where the
    /// host does not serve it points operators at a dead route and implies the
    /// contract is browsable when it is not.
    /// </summary>
    [Fact]
    public void Public_layout_links_to_swagger_only_when_it_is_published()
    {
        var layout = File.ReadAllText(Path.Combine(
            ResolvePublicUiSource(),
            "Components",
            "Layout",
            "MainLayout.razor"));

        Assert.Contains(
            "<a href=\"/swagger\">API Swagger</a>",
            layout,
            StringComparison.Ordinal);
        Assert.Contains(
            "@if (SwaggerPublished)",
            layout,
            StringComparison.Ordinal);
        Assert.Contains(
            "Sufficit:Identity:Swagger:Enabled",
            layout,
            StringComparison.Ordinal);
    }

    /// <summary>
    /// Swagger publication is a deployment decision, not a constant (eval
    /// 2026-08-23, S-1). Both endpoints are anonymous, so publishing by
    /// default exposed the full management/SCIM/provisioning/vault contract to
    /// unauthenticated callers. The host must read the flag instead of calling
    /// UseSwagger unconditionally.
    /// </summary>
    [Fact]
    public void Swagger_pipeline_is_gated_behind_the_publication_flag()
    {
        var program = File.ReadAllText(Path.Combine(
            ResolveIdentityRepository(),
            "src",
            "server",
            "Program.cs"));

        Assert.Contains("app.UseSwagger();", program, StringComparison.Ordinal);
        Assert.Contains("app.UseSwaggerUI();", program, StringComparison.Ordinal);
        Assert.Contains(
            "identityOptions.Swagger.Enabled",
            program,
            StringComparison.Ordinal);
        Assert.Contains(
            "?? app.Environment.IsDevelopment()",
            program,
            StringComparison.Ordinal);
        Assert.DoesNotContain(
            "including Production",
            program,
            StringComparison.Ordinal);
    }

    [Fact]
    public void Public_and_management_ui_reuse_the_canonical_avatar_resolver()
    {
        var repositoryRoot = ResolveIdentityRepository();
        var uiRoot = Path.GetFullPath(Path.Combine(
            repositoryRoot,
            "src",
            "ui"));
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
    public void Public_identity_language_selector_uses_the_shared_sui_component()
    {
        var publicUi = ResolvePublicUiSource();
        var selector = File.ReadAllText(Path.Combine(
            publicUi,
            "Components",
            "CultureSelector.razor"));
        var app = File.ReadAllText(Path.Combine(
            publicUi,
            "Components",
            "App.razor"));
        var project = File.ReadAllText(Path.Combine(
            publicUi,
            "Sufficit.Identity.UI.csproj"));

        Assert.Contains("<SUISelect", selector, StringComparison.Ordinal);
        Assert.Contains("<SUISelectItem", selector, StringComparison.Ordinal);
        Assert.Contains(
            "@rendermode @(RenderMode.InteractiveServer)",
            selector,
            StringComparison.Ordinal);
        Assert.Contains(
            "culture-selector__fallback",
            selector,
            StringComparison.Ordinal);
        Assert.Contains(
            "_content/Sufficit.Blazor.UI/sufficit-ui.css",
            app,
            StringComparison.Ordinal);
        Assert.Contains(
            "Sufficit.Identity.Server.styles.css",
            app,
            StringComparison.Ordinal);
        // Since the shared components ship as the Sufficit.Blazor.UI NuGet
        // package, the reference is the package id (no sibling checkout).
        Assert.Contains(
            "Sufficit.Blazor.UI",
            project,
            StringComparison.Ordinal);
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
    public void Public_account_lifecycle_and_consent_use_canonical_contracts()
    {
        var publicUi = ResolvePublicUiSource();
        var accountPages = Path.Combine(publicUi, "Pages", "Account");
        var lifecyclePages = new[]
        {
            "Register.razor",
            "ForgotPassword.razor",
            "ResetPassword.razor",
            "ConfirmEmail.razor",
            "ResendEmailConfirmation.razor",
        };
        foreach (var pageName in lifecyclePages)
        {
            var page = File.ReadAllText(Path.Combine(accountPages, pageName));
            Assert.Contains(
                "IAccountOnboardingService",
                page,
                StringComparison.Ordinal);
            foreach (var forbidden in ForbiddenUiDependencies)
            {
                Assert.DoesNotContain(
                    forbidden,
                    page,
                    StringComparison.Ordinal);
            }
        }

        var reset = File.ReadAllText(Path.Combine(
            accountPages,
            "ResetPassword.razor"));
        Assert.Contains(
            "name=\"_model.UserId\"",
            reset,
            StringComparison.Ordinal);
        Assert.Contains(
            "name=\"_model.EncodedToken\"",
            reset,
            StringComparison.Ordinal);

        var consent = File.ReadAllText(Path.Combine(
            publicUi,
            "Pages",
            "Consent.razor"));
        Assert.Contains(
            "IAuthorizationConsentService",
            consent,
            StringComparison.Ordinal);
        foreach (var forbidden in ForbiddenUiDependencies)
        {
            Assert.DoesNotContain(
                forbidden,
                consent,
                StringComparison.Ordinal);
        }

        var project = File.ReadAllText(Path.Combine(
            publicUi,
            "Sufficit.Identity.UI.csproj"));
        Assert.DoesNotContain(
            "OpenIddict.AspNetCore",
            project,
            StringComparison.Ordinal);
        Assert.DoesNotContain(
            "Identity.EntityFrameworkCore",
            project,
            StringComparison.Ordinal);
    }

    [Fact]
    public void Consent_layout_uses_available_desktop_width_and_stacks_on_mobile()
    {
        var publicUi = ResolvePublicUiSource();
        var consent = File.ReadAllText(Path.Combine(
            publicUi,
            "Pages",
            "Consent.razor"));
        var styles = File.ReadAllText(Path.Combine(
            publicUi,
            "wwwroot",
            "css",
            "site.css"));

        Assert.Contains(
            "class=\"auth-card consent-card\"",
            consent,
            StringComparison.Ordinal);
        Assert.Contains(
            "data-enhance=\"false\" data-consent-form",
            consent,
            StringComparison.Ordinal);
        Assert.Contains(
            "data-consent-submitted hidden",
            consent,
            StringComparison.Ordinal);
        var identityScript = File.ReadAllText(Path.Combine(
            publicUi,
            "wwwroot",
            "js",
            "identity.js"));
        Assert.Contains(
            "initializeConsentSubmit",
            identityScript,
            StringComparison.Ordinal);
        Assert.Contains(
            "form.dataset.consentSubmitted",
            identityScript,
            StringComparison.Ordinal);
        var submitListener = identityScript.IndexOf(
            "form.addEventListener('submit'",
            StringComparison.Ordinal);
        var deferredLock = identityScript.IndexOf(
            "window.setTimeout(function ()",
            submitListener,
            StringComparison.Ordinal);
        var controlLock = identityScript.IndexOf(
            "controls[i].disabled = true;",
            submitListener,
            StringComparison.Ordinal);
        Assert.True(submitListener >= 0);
        Assert.True(
            deferredLock >= 0 && controlLock > deferredLock,
            "Consent controls must be locked only after the browser captures the submit payload.");
        Assert.Contains(
            ".consent-card {\n    max-width: 800px;",
            styles,
            StringComparison.Ordinal);
        Assert.Contains(
            "grid-template-columns: 18px minmax(13.5rem, 0.65fr) minmax(0, 1.35fr);",
            styles,
            StringComparison.Ordinal);
        Assert.Contains(
            "grid-template-columns: 18px minmax(0, 1fr);",
            styles,
            StringComparison.Ordinal);
    }

    [Fact]
    public void Human_verification_pages_enable_interactive_server_rendering()
    {
        var accountPages = Path.Combine(
            ResolvePublicUiSource(),
            "Pages",
            "Account");
        var protectedPages = new[]
        {
            "Register.razor",
            "ForgotPassword.razor",
            "ResendEmailConfirmation.razor",
        };

        foreach (var pageName in protectedPages)
        {
            var page = File.ReadAllText(Path.Combine(accountPages, pageName));
            Assert.Contains(
                "@rendermode @(RenderMode.InteractiveServer)",
                page,
                StringComparison.Ordinal);
            Assert.Contains(
                "<HumanVerification",
                page,
                StringComparison.Ordinal);
        }
    }

    [Fact]
    public void Registration_validates_username_only_when_the_field_is_required()
    {
        var page = File.ReadAllText(Path.Combine(
            ResolvePublicUiSource(),
            "Pages",
            "Account",
            "Register.razor"));

        Assert.Contains(
            "public string? UserName { get; set; }",
            page,
            StringComparison.Ordinal);
        Assert.Contains(
            "_model.RequiresUserName = _registrationPolicy.RequiresUserName;",
            page,
            StringComparison.Ordinal);
        Assert.Contains(
            "if (RequiresUserName && string.IsNullOrWhiteSpace(UserName))",
            page,
            StringComparison.Ordinal);
        Assert.Contains(
            "<ValidationSummary class=\"validation-summary\" role=\"alert\" aria-live=\"polite\" />",
            page,
            StringComparison.Ordinal);
        Assert.DoesNotContain(
            "public string UserName { get; set; } = string.Empty;",
            page,
            StringComparison.Ordinal);
    }

    [Fact]
    public void Human_verification_only_uses_js_after_interactive_initialization()
    {
        var component = File.ReadAllText(Path.Combine(
            ResolvePublicUiSource(),
            "Components",
            "HumanVerification.razor"));

        Assert.Contains(
            "private bool _browserWidgetInitialized;",
            component,
            StringComparison.Ordinal);
        Assert.Contains(
            "_browserWidgetInitialized = true;",
            component,
            StringComparison.Ordinal);
        Assert.Equal(
            2,
            component.Split(
                "if (_browserWidgetInitialized)",
                StringSplitOptions.None).Length - 1);
    }

    [Fact]
    public void Human_verification_waits_for_the_provider_render_api()
    {
        var script = File.ReadAllText(Path.Combine(
            ResolvePublicUiSource(),
            "wwwroot",
            "js",
            "human-verification.js"));

        Assert.Contains(
            "typeof api.render === 'function'",
            script,
            StringComparison.Ordinal);
        Assert.Contains(
            "setTimeout(checkReady, 50)",
            script,
            StringComparison.Ordinal);
        Assert.DoesNotContain(
            "if (window[definition.global]) return Promise.resolve();",
            script,
            StringComparison.Ordinal);
    }

    [Fact]
    public void Human_verification_passes_the_flow_action_to_every_provider()
    {
        var script = File.ReadAllText(Path.Combine(
            ResolvePublicUiSource(),
            "wwwroot",
            "js",
            "human-verification.js"));

        Assert.Contains(
            "action: action,",
            script,
            StringComparison.Ordinal);
        Assert.DoesNotContain(
            "callbacks.action = action;",
            script,
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

    [Fact]
    public void Public_ui_has_no_direct_identity_dependencies()
    {
        var sourceRoot = ResolvePublicUiSource();
        var unexpectedViolations = Directory
            .EnumerateFiles(sourceRoot, "*", SearchOption.AllDirectories)
            .Where(path =>
                path.EndsWith(".cs", StringComparison.OrdinalIgnoreCase)
                || path.EndsWith(
                    ".razor",
                    StringComparison.OrdinalIgnoreCase))
            .Where(path =>
                !path.Contains(
                    $"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}",
                    StringComparison.Ordinal)
                && !path.Contains(
                    $"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}",
                    StringComparison.Ordinal))
            .Where(path =>
            {
                var source = File.ReadAllText(path);
                return ForbiddenUiDependencies.Any(forbidden =>
                    source.Contains(forbidden, StringComparison.Ordinal));
            })
            .Select(path => Path
                .GetRelativePath(sourceRoot, path)
                .Replace(Path.DirectorySeparatorChar, '/'))
            .Order(StringComparer.Ordinal)
            .ToArray();

        Assert.Empty(unexpectedViolations);
    }

    [Fact]
    public void Pending_mfa_recovery_clears_remembered_device_and_returns_to_login()
    {
        var home = File.ReadAllText(Path.Combine(
            ResolveManagementUiSource(),
            "Components",
            "Pages",
            "Home.razor"));
        var controller = File.ReadAllText(Path.Combine(
            ResolveIdentityRepository(),
            "src",
            "sts",
            "Controllers",
            "AuthorizationController.cs"));

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
    public void Device_completion_is_terminal_and_falls_back_when_the_tab_cannot_close()
    {
        var publicUi = ResolvePublicUiSource();
        var page = File.ReadAllText(Path.Combine(
            publicUi,
            "Pages",
            "Device",
            "UserCode.razor"));
        var script = File.ReadAllText(Path.Combine(
            publicUi,
            "wwwroot",
            "js",
            "identity.js"));
        var stylesheet = File.ReadAllText(Path.Combine(
            publicUi,
            "wwwroot",
            "css",
            "site.css"));

        Assert.DoesNotContain("<a href=\"/\"", page, StringComparison.Ordinal);
        Assert.Contains("data-device-flow-result", page, StringComparison.Ordinal);
        Assert.Contains("data-device-flow-close", page, StringComparison.Ordinal);
        Assert.Contains("data-device-flow-return", page, StringComparison.Ordinal);
        Assert.Contains("data-device-close-fallback", page, StringComparison.Ordinal);
        Assert.Contains("data-device-close-fallback hidden", page, StringComparison.Ordinal);
        Assert.Contains("[hidden] { display: none !important; }", stylesheet, StringComparison.Ordinal);
        Assert.Contains("data-enhance=\"false\"", page, StringComparison.Ordinal);
        Assert.Contains("window.close();", script, StringComparison.Ordinal);
        Assert.Contains("var strategies = [", script, StringComparison.Ordinal);
        Assert.Contains("name: 'direct'", script, StringComparison.Ordinal);
        Assert.Contains("name: 'top'", script, StringComparison.Ordinal);
        Assert.Contains("name: 'retargeted'", script, StringComparison.Ordinal);
        Assert.True(
            script.IndexOf("name: 'direct'", StringComparison.Ordinal)
            < script.IndexOf("name: 'top'", StringComparison.Ordinal));
        Assert.True(
            script.IndexOf("name: 'top'", StringComparison.Ordinal)
            < script.IndexOf("name: 'retargeted'", StringComparison.Ordinal));
        Assert.Contains("window.open('', '_self');", script, StringComparison.Ordinal);
        Assert.Contains("function logDeviceFlow(event, details)", script, StringComparison.Ordinal);
        Assert.Contains("console.info('[Sufficit Identity][DeviceFlow]'", script, StringComparison.Ordinal);
        Assert.Contains("manual-close-required", script, StringComparison.Ordinal);
        Assert.Contains("script-close-attempted", script, StringComparison.Ordinal);
        Assert.Contains("script-close-succeeded", script, StringComparison.Ordinal);
        Assert.Contains("script-close-blocked", script, StringComparison.Ordinal);
        Assert.Contains("script-close-error", script, StringComparison.Ordinal);
        Assert.Contains("close-pagehide-observed", script, StringComparison.Ordinal);
        Assert.Contains("manual-close-instructions-shown", script, StringComparison.Ordinal);
        Assert.Contains("deviceCloseManualLogged", script, StringComparison.Ordinal);
        Assert.Contains("device codes", script, StringComparison.Ordinal);
        Assert.Contains("function canAttemptScriptClose()", script, StringComparison.Ordinal);
        Assert.Contains(
            "showManualCompletion(result, 'tab-not-script-opened', false)",
            script,
            StringComparison.Ordinal);
        Assert.Contains("var scriptCloseAvailable = canAttemptScriptClose();", script, StringComparison.Ordinal);
        Assert.Contains("closeButton.hidden = !scriptCloseAvailable", script, StringComparison.Ordinal);
        Assert.Contains("fallback.hidden = false", script, StringComparison.Ordinal);
        Assert.Contains("button.hidden = keepCloseButton !== true", script, StringComparison.Ordinal);
        Assert.Contains("deviceCloseAttempted", script, StringComparison.Ordinal);
        Assert.Contains("deviceCloseInProgress", script, StringComparison.Ordinal);
        Assert.Contains("deviceCloseBlocked", script, StringComparison.Ordinal);
        Assert.Contains("window.opener", script, StringComparison.Ordinal);
        Assert.Contains("data-device-launch-mode", page, StringComparison.Ordinal);
        Assert.Contains("launch_mode", page, StringComparison.Ordinal);
        Assert.Contains("function notifyPopupOpener(result)", script, StringComparison.Ordinal);
        Assert.Contains("function initializeNativeAppReturn(result)", script, StringComparison.Ordinal);
        Assert.Contains("native-app-return-attempted", script, StringComparison.Ordinal);
        Assert.Contains("sufficit-auth-complete", script, StringComparison.Ordinal);
        Assert.Contains("popup-completion-notified", script, StringComparison.Ordinal);
        Assert.Contains("window.opener.postMessage", script, StringComparison.Ordinal);
        Assert.Contains("result.dataset.deviceLaunchMode === 'popup'", script, StringComparison.Ordinal);
        Assert.Contains("window.navigator.sendBeacon", script, StringComparison.Ordinal);
        Assert.Contains("keepalive: true", script, StringComparison.Ordinal);
        Assert.Contains("/security/device-flow-close-report", script, StringComparison.Ordinal);
        Assert.Contains("COOP can remove opener", script, StringComparison.Ordinal);
        Assert.Contains("initializeDeviceFlowClose", script, StringComparison.Ordinal);
        Assert.Contains("enhancedload", script, StringComparison.Ordinal);
        Assert.Contains("deviceCloseInitialized", script, StringComparison.Ordinal);
        Assert.Contains("DOMContentLoaded", script, StringComparison.Ordinal);
        Assert.DoesNotContain(
            "window.history.length <= 1",
            script,
            StringComparison.Ordinal);
        Assert.DoesNotContain("console.warn", script, StringComparison.Ordinal);
        Assert.DoesNotContain("closeDeviceFlowTab(result, false)", script, StringComparison.Ordinal);
        Assert.DoesNotContain("Tentar fechar novamente", script, StringComparison.Ordinal);
        Assert.Contains("from the button", script, StringComparison.Ordinal);
        Assert.Contains("same guarded close strategies", script, StringComparison.Ordinal);
    }

    [Fact]
    public void Identity_ui_consumes_the_shared_sui_assets()
    {
        var repository = ResolveIdentityRepository();
        var components = Path.Combine(
            repository,
            "src",
            "ui",
            "Sufficit.Identity.UI.Components");
        var vault = Path.Combine(
            repository,
            "src",
            "ui",
            "Sufficit.Identity.UI.Vault");

        var projectFiles = new[]
        {
            Path.Combine(components, "Sufficit.Identity.UI.Components.csproj"),
            Path.Combine(vault, "Sufficit.Identity.UI.Vault.csproj"),
            Path.Combine(repository, "src", "server", "Sufficit.Identity.Server.csproj"),
        };

        foreach (var projectFile in projectFiles)
        {
            // The shared components ship as the Sufficit.Blazor.UI NuGet
            // package (no sibling checkout).
            Assert.Contains(
                "Sufficit.Blazor.UI",
                File.ReadAllText(projectFile),
                StringComparison.Ordinal);
        }

        Assert.False(File.Exists(Path.Combine(components, "wwwroot", "sufficit-ui.css")));

        foreach (var app in new[]
                 {
                     Path.Combine(ResolveManagementUiSource(), "Components", "App.razor"),
                     Path.Combine(vault, "Components", "App.razor"),
                 })
        {
            var source = File.ReadAllText(app);
            Assert.Contains(
                "/_content/Sufficit.Blazor.UI/sufficit-ui.css",
                source,
                StringComparison.Ordinal);
            Assert.Contains(
                "/Sufficit.Identity.Server.styles.css",
                source,
                StringComparison.Ordinal);
        }
    }
}
