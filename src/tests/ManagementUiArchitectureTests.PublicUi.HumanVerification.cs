using Xunit;

namespace Sufficit.Identity.Tests;

public sealed partial class ManagementUiArchitectureTests
{
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
}
