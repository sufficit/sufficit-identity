using System.Net;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.Tests.Infrastructure;
using Xunit;

namespace Sufficit.Identity.Tests;

[Collection(StsCollection.Name)]
public sealed class RegistrationSignInTests(SufficitIdentityTestFactory factory)
{
    [Theory]
    [InlineData("success", null)]
    [InlineData("wrong-password", "invalid_password")]
    [InlineData("no-password", null)]
    [InlineData("locked", "locked_out")]
    [InlineData("unconfirmed", "not_allowed")]
    [InlineData("mfa", null)]
    public async Task Registration_continuation_uses_normal_sign_in_policy(string scenario, string? error)
    {
        string email;
        string userId;
        string? originalHash;
        await using (var scope = factory.Services.CreateAsyncScope())
        {
            var users = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
            var user = await TestDataSeeder.CreateUserAsync(users,
                $"signup-signin-{Guid.NewGuid():N}", TestDataSeeder.DefaultPassword);
            // Deliberately distinct from the username: lookup must use email.
            email = $"signup-email-{Guid.NewGuid():N}@example.test";
            user.Email = email;
            user.EmailConfirmed = scenario != "unconfirmed";
            Assert.True((await users.UpdateAsync(user)).Succeeded);
            if (scenario == "locked")
                Assert.True((await users.SetLockoutEndDateAsync(user, DateTimeOffset.UtcNow.AddMinutes(10))).Succeeded);
            if (scenario == "mfa")
                Assert.True((await users.SetTwoFactorEnabledAsync(user, true)).Succeeded);
            if (scenario == "no-password")
                Assert.True((await users.RemovePasswordAsync(user)).Succeeded);
            userId = user.Id;
            originalHash = user.PasswordHash;
        }

        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
        var csrf = await TestOnlyEndpoints.GetAntiforgeryTokenAsync(client);
        var password = scenario == "wrong-password" ? "Wrong!Passw0rd#84" : TestDataSeeder.DefaultPassword;
        using var response = await client.PostAsync("/account/login/password", new FormUrlEncodedContent(
            new Dictionary<string, string>
            {
                ["__RequestVerificationToken"] = csrf,
                ["UserName"] = email.ToUpperInvariant(),
                ["Password"] = password,
                ["FromRegistration"] = "true",
                ["ReturnUrl"] = "/protected",
            }));

        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        var location = Assert.IsType<Uri>(response.Headers.Location).OriginalString;
        Assert.DoesNotContain(password, location, StringComparison.Ordinal);
        var query = QueryHelpers.ParseQuery(new Uri(new Uri("https://sts.tests.local"), location).Query);
        Assert.Equal("/protected", query["returnUrl"]);
        var hasApplicationCookie = response.Headers.TryGetValues("Set-Cookie", out var cookies)
            && cookies.Any(cookie => cookie.StartsWith(".AspNetCore.Identity.Application=", StringComparison.Ordinal));
        Assert.Equal(scenario == "success", hasApplicationCookie);
        if (scenario == "success")
            Assert.StartsWith("/account/authenticationcontinue?", location);
        else if (scenario == "mfa")
            Assert.StartsWith("/account/loginwith2fa?", location);
        else if (scenario == "no-password")
        {
            Assert.Equal("external_signin", query["notice"]);
            Assert.False(query.ContainsKey("error"));
            Assert.Equal(email.ToUpperInvariant(), query["login_hint"]);
        }
        else
        {
            Assert.Equal(error, query["error"]);
            Assert.Equal(email.ToUpperInvariant(), query["login_hint"]);
            Assert.False(query.ContainsKey("Password"));
        }

        await using var verificationScope = factory.Services.CreateAsyncScope();
        var unchanged = await verificationScope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>()
            .FindByIdAsync(userId);
        Assert.NotNull(unchanged);
        Assert.Equal(originalHash, unchanged.PasswordHash);
        if (scenario == "wrong-password") Assert.Equal(1, unchanged.AccessFailedCount);
        if (scenario == "no-password") Assert.Equal(0, unchanged.AccessFailedCount);
    }

    [Fact]
    public async Task Email_continuation_never_falls_back_to_a_conflicting_username()
    {
        var email = $"not-an-email-owner-{Guid.NewGuid():N}@example.test";
        await using (var scope = factory.Services.CreateAsyncScope())
        {
            var users = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
            var user = await TestDataSeeder.CreateUserAsync(users, email, TestDataSeeder.DefaultPassword);
            user.Email = $"different-{Guid.NewGuid():N}@example.test";
            Assert.True((await users.UpdateAsync(user)).Succeeded);
        }
        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
        var csrf = await TestOnlyEndpoints.GetAntiforgeryTokenAsync(client);
        using var response = await client.PostAsync("/account/login/password", new FormUrlEncodedContent(
            new Dictionary<string, string>
            {
                ["__RequestVerificationToken"] = csrf,
                ["UserName"] = email,
                ["Password"] = TestDataSeeder.DefaultPassword,
                ["FromRegistration"] = "true",
                ["ReturnUrl"] = "https://attacker.invalid/",
            }));
        var location = response.Headers.Location!.OriginalString;
        Assert.Contains("error=invalid_password", location);
        Assert.Contains("returnUrl=%2F", location);
        Assert.DoesNotContain("attacker.invalid", location);
        Assert.False(response.Headers.TryGetValues("Set-Cookie", out var cookies)
            && cookies.Any(cookie => cookie.StartsWith(".AspNetCore.Identity.Application=", StringComparison.Ordinal)));
    }
}
