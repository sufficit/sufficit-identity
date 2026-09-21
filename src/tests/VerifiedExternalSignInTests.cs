using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Sufficit.Identity.Application.Accounts;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.STS;
using Sufficit.Identity.Tests.Infrastructure;
using Xunit;

namespace Sufficit.Identity.Tests;

[Collection(StsCollection.Name)]
public sealed class VerifiedExternalSignInTests(SufficitIdentityTestFactory factory)
{
    [Theory]
    [InlineData("confirmed", true, ExternalSignInStatus.Succeeded, true)]
    [InlineData("no-password", true, ExternalSignInStatus.Succeeded, true)]
    [InlineData("confirmed", false, ExternalSignInStatus.AccountLinkRequiresSignIn, false)]
    [InlineData("unconfirmed", true, ExternalSignInStatus.NotAllowed, false)]
    [InlineData("locked", true, ExternalSignInStatus.LockedOut, false)]
    [InlineData("mfa", true, ExternalSignInStatus.RequiresTwoFactor, true)]
    [InlineData("registration-disabled", true, ExternalSignInStatus.Succeeded, true)]
    [InlineData("denied", true, ExternalSignInStatus.AccountLinkRequiresSignIn, false)]
    [InlineData("trusted", false, ExternalSignInStatus.Succeeded, true)]
    public async Task Existing_account_links_only_after_email_proof_and_keeps_sign_in_policy(
        string scenario, bool verified, ExternalSignInStatus expected, bool shouldLink)
    {
        using var isolated = scenario switch
        {
            "registration-disabled" => SufficitIdentityTestFactory.CreateIsolated(
                new Dictionary<string, string?> { ["Sufficit:Identity:Register:Enabled"] = "false" }),
            "denied" => SufficitIdentityTestFactory.CreateIsolated(new Dictionary<string, string?>
                { ["Sufficit:Identity:ExternalIdentities:RegistrationDeniedProviders:0"] = "VerifiedTestProvider" }),
            "trusted" => SufficitIdentityTestFactory.CreateIsolated(new Dictionary<string, string?>
                { ["Sufficit:Identity:ExternalIdentities:TrustedEmailProviders:0"] = "VerifiedTestProvider" }),
            _ => null,
        };
        await using var scope = (isolated ?? factory).Services.CreateAsyncScope();
        var services = scope.ServiceProvider;
        var users = services.GetRequiredService<UserManager<ApplicationUser>>();
        var user = await TestDataSeeder.CreateUserAsync(users,
            $"external-match-{Guid.NewGuid():N}", TestDataSeeder.DefaultPassword);
        user.EmailConfirmed = scenario != "unconfirmed";
        Assert.True((await users.UpdateAsync(user)).Succeeded);
        if (scenario == "locked")
            Assert.True((await users.SetLockoutEndDateAsync(user, DateTimeOffset.UtcNow.AddMinutes(10))).Succeeded);
        if (scenario == "mfa")
            Assert.True((await users.SetTwoFactorEnabledAsync(user, true)).Succeeded);
        if (scenario == "no-password")
            Assert.True((await users.RemovePasswordAsync(user)).Succeeded);
        var originalHash = user.PasswordHash;
        var providerKey = Guid.NewGuid().ToString("N");
        var context = ExternalContext(services, providerKey, user.Email!.ToUpperInvariant(), verified);

        var result = await services.GetRequiredService<IExternalSignInService>()
            .CompleteAsync(new ClaimsPrincipal(new ClaimsIdentity()), forceMfa: true);

        Assert.Equal(expected, result.Status);
        var linked = await users.FindByLoginAsync("VerifiedTestProvider", providerKey);
        Assert.Equal(shouldLink ? user.Id : null, linked?.Id);
        Assert.Equal(originalHash, (await users.FindByIdAsync(user.Id))!.PasswordHash);
        Assert.Equal(expected == ExternalSignInStatus.Succeeded,
            context.Response.Headers.SetCookie.Any(cookie =>
                cookie!.StartsWith(".AspNetCore.Identity.Application=", StringComparison.Ordinal)));
    }

    [Fact]
    public async Task A_linked_subject_cannot_be_moved_to_another_account_by_changing_email()
    {
        await using var scope = factory.Services.CreateAsyncScope();
        var services = scope.ServiceProvider;
        var users = services.GetRequiredService<UserManager<ApplicationUser>>();
        var owner = await TestDataSeeder.CreateUserAsync(users,
            $"external-owner-{Guid.NewGuid():N}", TestDataSeeder.DefaultPassword);
        var other = await TestDataSeeder.CreateUserAsync(users,
            $"external-other-{Guid.NewGuid():N}", TestDataSeeder.DefaultPassword);
        var key = Guid.NewGuid().ToString("N");
        Assert.True((await users.AddLoginAsync(owner,
            new UserLoginInfo("VerifiedTestProvider", key, "Test provider"))).Succeeded);
        ExternalContext(services, key, other.Email!, verified: true);
        var result = await services.GetRequiredService<IExternalSignInService>()
            .CompleteAsync(new ClaimsPrincipal(new ClaimsIdentity()), forceMfa: false);
        Assert.Equal(ExternalSignInStatus.Succeeded, result.Status);
        Assert.Equal(owner.Id, (await users.FindByLoginAsync("VerifiedTestProvider", key))!.Id);
        Assert.Empty(await users.GetLoginsAsync(other));
    }

    [Fact]
    public async Task Registration_opt_out_never_authorizes_unproven_existing_account_linking()
    {
        var policy = new ConfigurableExternalIdentityLinkingPolicy(
            new ExternalIdentityOptions { RequireVerifiedEmail = false },
            NullLogger<ConfigurableExternalIdentityLinkingPolicy>.Instance);
        var result = await policy.EvaluateAsync(new ExternalIdentityAssertion(
            "Unverified", "key", null, "owner@example.test", false, ExistingAccount: true));
        Assert.Equal(ExternalIdentityLinkingDecision.RequiresEmailVerification, result.Decision);
    }

    [Theory]
    [InlineData("{\"email\":\"person@gmail.com\",\"email_verified\":true}", "true")]
    [InlineData("{\"email\":\"person@company.test\",\"email_verified\":true,\"hd\":\"company.test\"}", "true")]
    [InlineData("{\"email\":\"person@company.test\",\"email_verified\":true}", "false")]
    [InlineData("{\"email\":\"person@gmail.com\",\"email_verified\":false}", "false")]
    [InlineData("{\"email\":\"person@gmail.com\"}", "false")]
    [InlineData("{\"email_verified\":true,\"hd\":\"company.test\"}", "false")]
    public void Google_proof_requires_current_authority_over_the_address(string json, string expected)
    {
        using var document = JsonDocument.Parse(json);
        Assert.Equal(expected, GoogleEmailProof.FromProfile(document.RootElement));
    }

    private static DefaultHttpContext ExternalContext(IServiceProvider services, string key, string email, bool verified)
    {
        var options = services.GetRequiredService<IOptionsMonitor<CookieAuthenticationOptions>>()
            .Get(IdentityConstants.ExternalScheme);
        var properties = new AuthenticationProperties();
        properties.Items["LoginProvider"] = "VerifiedTestProvider";
        var principal = new ClaimsPrincipal(new ClaimsIdentity(
            [new Claim(ClaimTypes.NameIdentifier, key), new Claim(ClaimTypes.Email, email),
             new Claim("email_verified", verified ? "true" : "false")], "VerifiedTestProvider"));
        var ticket = new AuthenticationTicket(principal, properties, IdentityConstants.ExternalScheme);
        var context = new DefaultHttpContext { RequestServices = services };
        context.Request.Scheme = "https";
        context.Request.Host = new HostString("sts.tests.local");
        context.Request.Headers.Cookie = options.Cookie.Name + "=" + options.TicketDataFormat.Protect(ticket);
        services.GetRequiredService<IHttpContextAccessor>().HttpContext = context;
        return context;
    }
}
