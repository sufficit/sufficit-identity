using System.Net;
using System.Net.Http.Json;
using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.IdentityModel.Tokens;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.STS;
using Sufficit.Identity.Tests.Infrastructure;
using Xunit;

namespace Sufficit.Identity.Tests;

/// <summary>
/// Tests for the security-hardening components added to close the evaluation
/// findings: SCIM authorization audit filter, breached-password validator,
/// and the SCIM RequireAuthorization=false safety guard.
/// </summary>
public sealed class SecurityHardeningTests
{
    // ---- BreachedPasswordValidator ----

    [Fact]
    public async Task Breached_password_validator_returns_success_when_api_unreachable()
    {
        // Point the validator at a non-existent endpoint to simulate API
        // unavailability — must fail-open (return Success).
        var handler = new StubHandler(System.Net.HttpStatusCode.ServiceUnavailable);
        var validator = new BreachedPasswordValidator(
            new HttpClient(handler),
            NullLogger<BreachedPasswordValidator>.Instance);

        var result = await validator.ValidateAsync(null!, null!, "any-password");
        Assert.True(result.Succeeded);
    }

    [Fact]
    public async Task Breached_password_validator_rejects_known_breached_password()
    {
        // The HIBP API returns "SUFFIX:count" lines. We simulate a match by
        // returning a suffix that matches the SHA-1 hash of "password".
        var sha1 = Convert.ToHexString(
            System.Security.Cryptography.SHA1.HashData(
                System.Text.Encoding.UTF8.GetBytes("password")));
        var prefix = sha1[..5];
        var suffix = sha1[5..];
        var responseBody = $"{suffix}:12345\r\n";

        var handler = new StubHandler(System.Net.HttpStatusCode.OK, responseBody);
        // The validator prepends the HIBP base URL + the prefix. Override
        // the BaseAddress by constructing the client with a handler that
        // returns the body regardless of the URL.
        var client = new HttpClient(handler) { BaseAddress = new Uri("https://api.pwnedpasswords.com/range/") };

        var validator = new BreachedPasswordValidator(
            client,
            NullLogger<BreachedPasswordValidator>.Instance);

        var result = await validator.ValidateAsync(null!, null!, "password");
        Assert.False(result.Succeeded);
        Assert.Contains(result.Errors, e => e.Code == "PasswordBreached");
        await Task.CompletedTask;
    }

    // ---- SCIM RequireAuthorization=false safety ----

    [Fact]
    public async Task Scim_authorization_policy_always_requires_authentication()
    {
        // H5 fix verification: build the SCIM service collection with
        // RequireAuthorization=false and inspect the authorization policy.
        // Authentication must remain mandatory even when the scope check
        // is relaxed.
        var config = new Microsoft.Extensions.Configuration.ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["RequireAuthorization"] = "false",
            })
            .Build();

        var services = new ServiceCollection();
        services.AddLogging();
        Sufficit.Identity.Scim.ScimServiceCollectionExtensions
            .AddSufficitIdentityScim(services, config);
        services.AddAuthorization();

        var provider = services.BuildServiceProvider();
        var policyProvider = provider.GetRequiredService<
            Microsoft.AspNetCore.Authorization.IAuthorizationPolicyProvider>();
        var policy = await policyProvider.GetPolicyAsync(
            Sufficit.Identity.Scim.ScimServiceCollectionExtensions.PolicyName);

        Assert.NotNull(policy);
        // The policy MUST have authentication requirements (not just an
        // assertion that returns true for everyone).
        Assert.NotEmpty(policy!.Requirements);
        Assert.NotEmpty(policy.AuthenticationSchemes);
        // Must NOT contain a DenyAnonymousAuthorizationRequirement bypass.
        Assert.DoesNotContain(policy.Requirements,
            r => r.GetType().Name.Contains("Assertion", StringComparison.Ordinal));
    }

    private sealed class StubHandler : HttpMessageHandler
    {
        private readonly HttpStatusCode _status;
        private readonly string _body;

        public StubHandler(HttpStatusCode status, string body = "")
        {
            _status = status;
            _body = body;
        }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            var content = new StringContent(_body);
            content.Headers.ContentType =
                new System.Net.Http.Headers.MediaTypeHeaderValue("text/plain");
            return Task.FromResult(new HttpResponseMessage(_status) { Content = content });
        }
    }
}
