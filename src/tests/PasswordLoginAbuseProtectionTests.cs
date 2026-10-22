using System.Net;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Sufficit.Identity.Application.Security;
using Sufficit.Identity.Tests.Infrastructure;
using Xunit;

namespace Sufficit.Identity.Tests;

/// <summary>Plan D6 end to end: after repeated failures an account needs human verification.</summary>
public sealed class PasswordLoginAbuseProtectionTests
{
    [Fact]
    public async Task After_repeated_failures_even_the_right_password_needs_human_verification()
    {
        using var isolated = SufficitIdentityTestFactory.CreateIsolated(new Dictionary<string, string?>
        {
            ["Sufficit:Identity:AbuseProtection:Mode"] = "Enforce",
            ["Sufficit:Identity:AbuseProtection:AccountDelayAfter"] = "100",
            ["Sufficit:Identity:AbuseProtection:AccountVerificationAfter"] = "2",
            ["Sufficit:Identity:HumanVerification:Enabled"] = "true",
            ["Sufficit:Identity:HumanVerification:SiteKey"] = "test-site-key",
        });
        await ((IAsyncLifetime)isolated).InitializeAsync();
        using var factory = isolated.WithWebHostBuilder(builder => builder.ConfigureTestServices(services =>
            services.Replace(ServiceDescriptor.Singleton<IHumanVerificationService, AcceptsOnlyOk>())));
        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
        var antiforgery = await TestOnlyEndpoints.GetAntiforgeryTokenAsync(client);

        for (var i = 0; i < 2; i++)
        {
            using var wrong = await PostAsync(client, antiforgery, "wrong-password");
            Assert.Equal("invalid_credentials", Query(wrong)["error"].ToString());
        }

        // Refused before the password is checked: a guess costs a verification.
        using var unverified = await PostAsync(client, antiforgery, TestDataSeeder.DefaultPassword);
        var query = Query(unverified);
        Assert.Equal("verification_required", query["error"].ToString());
        Assert.Equal("1", query["verify"].ToString());
        Assert.False(SignedIn(unverified));

        using var verified = await PostAsync(client, antiforgery, TestDataSeeder.DefaultPassword, verification: "ok");
        Assert.True(SignedIn(verified));

        // The success cleared the account's count (a fresh browser: the old one is signed in now).
        using var other = factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
        using var clean = await PostAsync(other, await TestOnlyEndpoints.GetAntiforgeryTokenAsync(other), "wrong-password");
        Assert.Equal("invalid_credentials", Query(clean)["error"].ToString());
        Assert.False(Query(clean).ContainsKey("verify"));
    }

    private static Task<HttpResponseMessage> PostAsync(HttpClient client, string antiforgery, string password, string? verification = null)
    {
        var values = new Dictionary<string, string>
        {
            ["UserName"] = TestDataSeeder.DefaultUsername,
            ["Password"] = password,
            ["ReturnUrl"] = "/",
            ["__RequestVerificationToken"] = antiforgery,
        };
        if (verification is not null) values["human-verification-response"] = verification;
        return client.PostAsync("/account/login/password", new FormUrlEncodedContent(values));
    }

    private static bool SignedIn(HttpResponseMessage response) =>
        response.Headers.TryGetValues("Set-Cookie", out var cookies)
        && cookies.Any(value => value.Contains(".AspNetCore.Identity.Application=", StringComparison.Ordinal));

    private static Dictionary<string, Microsoft.Extensions.Primitives.StringValues> Query(HttpResponseMessage response)
    {
        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        var absolute = new Uri(new Uri("https://identity.tests.local"), response.Headers.Location!);
        return Microsoft.AspNetCore.WebUtilities.QueryHelpers.ParseQuery(absolute.Query);
    }

    private sealed class AcceptsOnlyOk : IHumanVerificationService
    {
        public HumanVerificationWidget GetWidget(HumanVerificationFlow flow) =>
            new(true, HumanVerificationProvider.GoogleRecaptchaV2, "test-site-key", "login");

        public Task<HumanVerificationResult> VerifyAsync(HumanVerificationFlow flow, string? responseToken,
            CancellationToken cancellationToken = default) =>
            Task.FromResult(responseToken == "ok" ? HumanVerificationResult.Success : new HumanVerificationResult(false, "invalid"));
    }
}
