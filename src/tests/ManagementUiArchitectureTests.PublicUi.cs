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
