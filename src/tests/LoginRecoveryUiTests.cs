using System.Runtime.CompilerServices;
using Xunit;

namespace Sufficit.Identity.Tests;

public sealed class LoginRecoveryUiTests
{
    [Fact]
    public void Authenticated_login_recovery_keeps_credentials_in_the_anonymous_branch()
    {
        var repository = ResolveIdentityRepository();
        var login = File.ReadAllText(Path.Combine(
            repository,
            "src",
            "ui",
            "Sufficit.Identity.UI",
            "Pages",
            "Account",
            "Login.razor"));

        var authorizedStart = login.IndexOf(
            "<Authorized>",
            StringComparison.Ordinal);
        var notAuthorizedStart = login.IndexOf(
            "<NotAuthorized>",
            StringComparison.Ordinal);

        Assert.True(authorizedStart >= 0);
        Assert.True(notAuthorizedStart > authorizedStart);

        var authenticatedMarkup = login[authorizedStart..notAuthorizedStart];
        var anonymousMarkup = login[notAuthorizedStart..];

        Assert.Contains(
            "Login.SessionActive.ExternalCorrelationFailed",
            authenticatedMarkup,
            StringComparison.Ordinal);
        Assert.Contains(
            "href=\"@(_returnUrl ?? \"/\")\"",
            authenticatedMarkup,
            StringComparison.Ordinal);
        Assert.Contains(
            "data-enhance-nav=\"false\"",
            authenticatedMarkup,
            StringComparison.Ordinal);
        Assert.DoesNotContain(
            "name=\"Password\"",
            authenticatedMarkup,
            StringComparison.Ordinal);
        Assert.Contains(
            "name=\"Password\"",
            anonymousMarkup,
            StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("SharedResource.resx")]
    [InlineData("SharedResource.en.resx")]
    public void Login_recovery_copy_is_localized(string resourceFile)
    {
        var repository = ResolveIdentityRepository();
        var resource = File.ReadAllText(Path.Combine(
            repository,
            "src",
            "ui",
            "Sufficit.Identity.UI",
            "Resources",
            resourceFile));

        Assert.Contains(
            "Login.SessionActive.Title",
            resource,
            StringComparison.Ordinal);
        Assert.Contains(
            "Login.SessionActive.Description",
            resource,
            StringComparison.Ordinal);
        Assert.Contains(
            "Login.SessionActive.ExternalCorrelationFailed",
            resource,
            StringComparison.Ordinal);
        Assert.Contains(
            "Login.SessionActive.Continue",
            resource,
            StringComparison.Ordinal);
        Assert.Contains(
            "Login.SessionActive.UseAnotherAccount",
            resource,
            StringComparison.Ordinal);
    }

    private static string ResolveIdentityRepository([CallerFilePath] string sourceFile = "") =>
        Path.GetFullPath(Path.Combine(
            Path.GetDirectoryName(sourceFile)
                ?? throw new InvalidOperationException(
                    "Unable to resolve the test source directory."),
            "..",
            ".."));
}
