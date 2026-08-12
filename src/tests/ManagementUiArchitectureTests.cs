using Xunit;

namespace Sufficit.Identity.Tests;

public sealed class ManagementUiArchitectureTests
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
        Assert.Contains("AuthenticatorSignInCommand", twoFactor, StringComparison.Ordinal);
        Assert.Contains("IInteractiveSignInService", recovery, StringComparison.Ordinal);
        Assert.Contains("RecoveryCodeSignInAsync", recovery, StringComparison.Ordinal);
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
        Assert.Contains("aria-label=\"Renomear", page, StringComparison.Ordinal);
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
    public void Branding_preview_uses_the_configured_background_and_safe_live_draft_values()
    {
        var repositoryRoot = ResolveIdentityRepository();
        var page = File.ReadAllText(Path.Combine(
            repositoryRoot,
            "src",
            "ui",
            "Sufficit.Identity.UI.Management",
            "Components",
            "Pages",
            "Branding.razor"));
        var styles = File.ReadAllText(Path.Combine(
            repositoryRoot,
            "src",
            "ui",
            "Sufficit.Identity.UI.Management",
            "wwwroot",
            "app.css"));

        Assert.Contains("@bind-Value:event=\"oninput\"", page, StringComparison.Ordinal);
        Assert.Contains("SafePreviewImageUrl", page, StringComparison.Ordinal);
        Assert.Contains("--preview-background-image", page, StringComparison.Ordinal);
        Assert.Contains("var(--preview-background-image, none)", styles, StringComparison.Ordinal);
        Assert.Contains("Fundo personalizado", page, StringComparison.Ordinal);
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
            "private static bool IsLockedOut(ManagementUserDetail? user)",
            userDetail,
            StringComparison.Ordinal);
        Assert.Contains(
            "user?.LockoutEnd",
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

        Assert.DoesNotContain("<a href=\"/\"", page, StringComparison.Ordinal);
        Assert.Contains("data-device-flow-result", page, StringComparison.Ordinal);
        Assert.Contains("data-device-flow-close", page, StringComparison.Ordinal);
        Assert.Contains("data-device-close-fallback", page, StringComparison.Ordinal);
        Assert.Contains("data-device-close-fallback hidden", page, StringComparison.Ordinal);
        Assert.Contains("data-enhance=\"false\"", page, StringComparison.Ordinal);
        Assert.Contains("window.close();", script, StringComparison.Ordinal);
        Assert.Contains("window.open('', '_self');", script, StringComparison.Ordinal);
        Assert.Contains("fallback.hidden = false", script, StringComparison.Ordinal);
        Assert.Contains("button.hidden = true", script, StringComparison.Ordinal);
        Assert.Contains("deviceCloseAttempted", script, StringComparison.Ordinal);
        Assert.Contains("deviceCloseBlocked", script, StringComparison.Ordinal);
        Assert.Contains("window.opener", script, StringComparison.Ordinal);
        Assert.Contains("console.warn", script, StringComparison.Ordinal);
        Assert.Contains("initializeDeviceFlowClose", script, StringComparison.Ordinal);
        Assert.Contains("enhancedload", script, StringComparison.Ordinal);
        Assert.Contains("deviceCloseInitialized", script, StringComparison.Ordinal);
        Assert.Contains("DOMContentLoaded", script, StringComparison.Ordinal);
        Assert.DoesNotContain(
            "window.history.length <= 1",
            script,
            StringComparison.Ordinal);
        Assert.DoesNotContain("closeDeviceFlowTab(result, false)", script, StringComparison.Ordinal);
        Assert.DoesNotContain("Tentar fechar novamente", script, StringComparison.Ordinal);
        Assert.Contains(
            "only from the button",
            script,
            StringComparison.Ordinal);
    }

    [Fact]
    public void Database_dashboard_uses_the_runtime_event_stream_instead_of_polling()
    {
        var page = File.ReadAllText(Path.Combine(
            ResolveManagementUiSource(),
            "Components",
            "Pages",
            "Database.razor"));

        Assert.Contains(".WatchAsync(cancellationToken)", page, StringComparison.Ordinal);
        Assert.Contains("Eventos em tempo real", page, StringComparison.Ordinal);
        Assert.DoesNotContain("PeriodicTimer", page, StringComparison.Ordinal);
        Assert.DoesNotContain("FromSeconds(2)", page, StringComparison.Ordinal);
        Assert.DoesNotContain("a cada 2 segundos", page, StringComparison.Ordinal);
    }

    [Fact]
    public void Client_configurator_is_resumable_protected_and_uses_shared_cases_of_use()
    {
        var repository = ResolveIdentityRepository();
        var managementUi = ResolveManagementUiSource();
        var wizard = File.ReadAllText(Path.Combine(
            managementUi,
            "Components",
            "Pages",
            "ClientDraft.razor"));
        var list = File.ReadAllText(Path.Combine(
            managementUi,
            "Components",
            "Pages",
            "Clients.razor"));
        var dataSource = File.ReadAllText(Path.Combine(
            managementUi,
            "Clients",
            "ManagementClientDataSource.cs"));
        var controller = File.ReadAllText(Path.Combine(
            repository,
            "src",
            "management",
            "Controllers",
            "ClientDraftsController.cs"));

        Assert.Contains("/clients/drafts/{Id:guid}/{Step}", wizard, StringComparison.Ordinal);
        Assert.Contains("Task.Delay(650", wizard, StringComparison.Ordinal);
        Assert.Contains("SaveClientDraftAsync", wizard, StringComparison.Ordinal);
        Assert.Contains("CompleteClientDraftAsync", wizard, StringComparison.Ordinal);
        Assert.Contains("OneTimeSecret", wizard, StringComparison.Ordinal);
        Assert.DoesNotContain("OneTimeSecret)}", wizard, StringComparison.Ordinal);
        Assert.Contains("SupplyParameterFromQuery(Name = \"q\")", list, StringComparison.Ordinal);
        Assert.Contains("SupplyParameterFromQuery(Name = \"type\")", list, StringComparison.Ordinal);
        Assert.Contains("GetClientDraftsAsync", list, StringComparison.Ordinal);
        Assert.Contains("IClientConfigurationDraftService", dataSource, StringComparison.Ordinal);
        Assert.Contains("IClientConfigurationDraftService", controller, StringComparison.Ordinal);
    }

    [Fact]
    public void Client_configurator_styles_are_mobile_first_and_touch_friendly()
    {
        var stylesheet = File.ReadAllText(Path.Combine(
            ResolveManagementUiSource(),
            "wwwroot",
            "app.css"));

        Assert.Contains(".wizard-shell", stylesheet, StringComparison.Ordinal);
        Assert.Contains("grid-template-columns: minmax(0, 1fr);", stylesheet, StringComparison.Ordinal);
        Assert.Contains("@media (min-width: 768px)", stylesheet, StringComparison.Ordinal);
        Assert.Contains("@media (min-width: 1100px)", stylesheet, StringComparison.Ordinal);
        Assert.Contains("min-height: 44px", stylesheet, StringComparison.Ordinal);
        Assert.Contains("env(safe-area-inset-bottom)", stylesheet, StringComparison.Ordinal);
        Assert.Contains("prefers-reduced-motion", stylesheet, StringComparison.Ordinal);
    }

    [Fact]
    public void Identity_ui_is_self_contained_and_serves_its_local_sui_assets()
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
        };

        foreach (var projectFile in projectFiles)
        {
            Assert.DoesNotContain(
                "sufficit-blazor-ui",
                File.ReadAllText(projectFile),
                StringComparison.OrdinalIgnoreCase);
        }

        Assert.True(File.Exists(Path.Combine(components, "wwwroot", "sufficit-ui.css")));

        foreach (var app in new[]
                 {
                     Path.Combine(ResolveManagementUiSource(), "Components", "App.razor"),
                     Path.Combine(vault, "Components", "App.razor"),
                 })
        {
            var source = File.ReadAllText(app);
            Assert.Contains(
                "/_content/Sufficit.Identity.UI.Components/sufficit-ui.css",
                source,
                StringComparison.Ordinal);
            Assert.DoesNotContain(
                "/_content/Sufficit.Blazor.UI/",
                source,
                StringComparison.Ordinal);
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
