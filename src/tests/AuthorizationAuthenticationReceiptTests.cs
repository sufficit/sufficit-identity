using System.Security.Claims;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Sufficit.Identity.STS;
using Xunit;

namespace Sufficit.Identity.Tests;

public sealed class AuthorizationAuthenticationReceiptTests
{
    private const string Url = "/connect/authorize?client_id=fleet&state=unique&max_age=0";
    private static readonly DateTimeOffset Now = DateTimeOffset.Parse("2026-09-10T21:00:00Z");

    [Theory]
    [InlineData("valid", true)]
    [InlineData("different-request", false)]
    [InlineData("different-session", false)]
    [InlineData("different-authentication", false)]
    [InlineData("expired", false)]
    [InlineData("tampered", false)]
    [InlineData("anonymous", false)]
    public void Receipt_is_bound_to_request_and_authenticated_session(string scenario, bool expected)
    {
        var clock = new Clock();
        using var services = Services(clock);
        var issuance = Context(services);
        AuthorizationAuthenticationReceipt.Issue(issuance, Url);
        var cookie = issuance.Response.Headers.SetCookie.Single()!.Split(';')[0];
        Assert.Contains("secure", issuance.Response.Headers.SetCookie.ToString());
        Assert.Contains("httponly", issuance.Response.Headers.SetCookie.ToString());
        var resumed = Context(services);
        resumed.Request.Headers.Cookie = scenario == "tampered" ? cookie[..^4] + "xxxx" : cookie;
        var identity = (ClaimsIdentity)resumed.User.Identity!;
        if (scenario == "different-session") identity.RemoveClaim(identity.FindFirst("sid")!);
        if (scenario == "different-authentication") identity.RemoveClaim(identity.FindFirst("auth_time")!);
        if (scenario == "anonymous") resumed.User = new ClaimsPrincipal(new ClaimsIdentity());
        clock.Now = Now.AddMinutes(scenario == "expired" ? 6 : 1);
        Assert.Equal(expected, AuthorizationAuthenticationReceipt.IsValid(resumed,
            scenario == "different-request" ? Url + "&scope=other" : Url));
        if (expected)
        {
            Assert.True(AuthorizationAuthenticationReceipt.IsValid(resumed, Url + "&consent_decision=allow&__RequestVerificationToken=test"));
            AuthorizationAuthenticationReceipt.Clear(resumed);
            Assert.Contains("expires=Thu, 01 Jan 1970", resumed.Response.Headers.SetCookie.ToString());
        }
    }

    [Fact]
    public void Existing_cookie_without_a_credential_ceremony_cannot_issue_receipt()
    {
        using var services = new ServiceCollection().BuildServiceProvider();
        var context = Context(services);
        AuthorizationAuthenticationReceipt.Issue(context, Url);
        Assert.False(context.Response.Headers.ContainsKey("Set-Cookie"));
        Assert.False(AuthorizationAuthenticationReceipt.IsValid(context, Url));
    }

    private static ServiceProvider Services(Clock clock)
    {
        var evidence = new AuthenticationContextAccessor();
        evidence.Set(new AuthenticationContextEvidence(["otp", "mfa"], Now, "urn:example:acr:loa2"));
        return new ServiceCollection()
            .AddSingleton<TimeProvider>(clock)
            .AddSingleton<IDataProtectionProvider>(new EphemeralDataProtectionProvider())
            .AddSingleton<IAuthenticationContextAccessor>(evidence).BuildServiceProvider();
    }
    private static DefaultHttpContext Context(IServiceProvider services) => new()
    {
        RequestServices = services,
        User = new ClaimsPrincipal(new ClaimsIdentity([
            new Claim("sid", "test-session"),
            new Claim("auth_time", Now.ToUnixTimeSeconds().ToString())], "test")),
    };
    private sealed class Clock : TimeProvider
    {
        public DateTimeOffset Now { get; set; } = AuthorizationAuthenticationReceiptTests.Now;
        public override DateTimeOffset GetUtcNow() => Now;
    }
}
