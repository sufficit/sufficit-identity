using System.Net;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Abstractions;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.STS;
using Sufficit.Identity.Tests.Infrastructure;
using Xunit;

namespace Sufficit.Identity.Tests;

public sealed class AuthenticationContextProjectionTests
{
    [Fact]
    public void Projector_copies_authentication_evidence_without_user_claim_storage()
    {
        var sourceIdentity = new ClaimsIdentity(
        [
            new Claim("amr", "pwd"),
            new Claim("amr", "mfa"),
            new Claim("acr", "urn:sufficit:acr:loa2"),
            new Claim("auth_time", "123456"),
        ]);
        var destination = new ClaimsIdentity();

        new AuthenticationContextProjector().Project(
            new ClaimsPrincipal(sourceIdentity),
            destination);

        Assert.Equal(
            ["pwd", "mfa"],
            destination.FindAll("amr").Select(claim => claim.Value));
        Assert.Equal("urn:sufficit:acr:loa2", destination.FindFirst("acr")?.Value);
        Assert.Equal("123456", destination.FindFirst("auth_time")?.Value);
    }

    [Fact]
    public async Task Session_factory_stamps_real_factor_evidence_and_authentication_time()
    {
        using var factory = SufficitIdentityTestFactory.CreateIsolated(
            new Dictionary<string, string?>());
        await ((IAsyncLifetime)factory).InitializeAsync();
        await using var scope = factory.Services.CreateAsyncScope();
        var users = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        var user = await users.FindByNameAsync(TestDataSeeder.DefaultUsername)
            ?? throw new InvalidOperationException("Seed user not found.");
        var evidence = scope.ServiceProvider.GetRequiredService<IAuthenticationContextAccessor>();
        evidence.Set(new AuthenticationContextEvidence(
            ["pwd", "otp", "mfa"],
            DateTimeOffset.UtcNow.AddMinutes(-1),
            "urn:sufficit:acr:loa2"));
        var claimsFactory = scope.ServiceProvider
            .GetRequiredService<IUserClaimsPrincipalFactory<ApplicationUser>>();

        var principal = await claimsFactory.CreateAsync(user);

        Assert.Contains(principal.FindAll("amr"), claim => claim.Value == "pwd");
        Assert.Contains(principal.FindAll("amr"), claim => claim.Value == "mfa");
        Assert.Equal("urn:sufficit:acr:loa2", principal.FindFirst("acr")?.Value);
        Assert.True(long.TryParse(principal.FindFirst("auth_time")?.Value, out _));
    }

    [Fact]
    public async Task Session_factory_refreshes_authentication_evidence_when_sid_already_exists()
    {
        using var factory = SufficitIdentityTestFactory.CreateIsolated(
            new Dictionary<string, string?>());
        await ((IAsyncLifetime)factory).InitializeAsync();
        await using var scope = factory.Services.CreateAsyncScope();
        var users = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        var user = await users.FindByNameAsync(TestDataSeeder.DefaultUsername)
            ?? throw new InvalidOperationException("Seed user not found.");
        var databaseFactory = scope.ServiceProvider
            .GetRequiredService<IDbContextFactory<Sufficit.Identity.Core.Data.AppDbContext>>();
        await using (var database = await databaseFactory.CreateDbContextAsync())
        {
            database.OidcUserSessions.Add(new OidcUserSession
            {
                SessionId = "persisted-session",
                Subject = user.Id,
                CreatedAtUtc = DateTime.UtcNow,
                LastActivityUtc = DateTime.UtcNow,
            });
            await database.SaveChangesAsync();
        }
        var httpContextAccessor = scope.ServiceProvider
            .GetRequiredService<IHttpContextAccessor>();
        httpContextAccessor.HttpContext = new DefaultHttpContext
        {
            User = new ClaimsPrincipal(new ClaimsIdentity(
                [
                    new Claim(ClaimTypes.NameIdentifier, user.Id),
                    new Claim("sid", "persisted-session"),
                ],
                authenticationType: "Test")),
        };

        var evidence = scope.ServiceProvider.GetRequiredService<IAuthenticationContextAccessor>();
        evidence.Set(new AuthenticationContextEvidence(
            ["passkey", "hwk", "mfa"],
            DateTimeOffset.UtcNow.AddSeconds(-30),
            "urn:sufficit:acr:loa3"));
        var claimsFactory = scope.ServiceProvider
            .GetRequiredService<IUserClaimsPrincipalFactory<ApplicationUser>>();

        var principal = await claimsFactory.CreateAsync(user);

        Assert.Equal("persisted-session", principal.FindFirst("sid")?.Value);
        Assert.Contains(principal.FindAll("amr"), claim => claim.Value == "passkey");
        Assert.Equal("urn:sufficit:acr:loa3", principal.FindFirst("acr")?.Value);
        Assert.Single(principal.FindAll("auth_time"));
    }

    [Fact]
    public async Task Session_factory_does_not_reuse_sid_without_matching_persisted_row()
    {
        using var factory = SufficitIdentityTestFactory.CreateIsolated(
            new Dictionary<string, string?>());
        await ((IAsyncLifetime)factory).InitializeAsync();
        await using var scope = factory.Services.CreateAsyncScope();
        var users = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        var user = await users.FindByNameAsync(TestDataSeeder.DefaultUsername)
            ?? throw new InvalidOperationException("Seed user not found.");
        scope.ServiceProvider.GetRequiredService<IHttpContextAccessor>().HttpContext =
            new DefaultHttpContext
            {
                User = new ClaimsPrincipal(new ClaimsIdentity(
                    [
                        new Claim(ClaimTypes.NameIdentifier, user.Id),
                        new Claim("sid", "stale-cookie-sid"),
                    ],
                    authenticationType: "Test")),
            };

        var principal = await scope.ServiceProvider
            .GetRequiredService<IUserClaimsPrincipalFactory<ApplicationUser>>()
            .CreateAsync(user);

        Assert.NotEqual("stale-cookie-sid", principal.FindFirst("sid")?.Value);
        Assert.False(string.IsNullOrWhiteSpace(principal.FindFirst("sid")?.Value));
    }

    [Fact]
    public async Task Password_grant_projects_amr_acr_and_auth_time_into_access_token()
    {
        using var factory = SufficitIdentityTestFactory.CreateIsolated(
            new Dictionary<string, string?>());
        await ((IAsyncLifetime)factory).InitializeAsync();
        var client = factory.CreateClient();
        var (tokenStatus, tokenBody) = await client.PostFormAsync(
            "/connect/token",
            new Dictionary<string, string>
            {
                ["grant_type"] = "password",
                ["username"] = TestDataSeeder.DefaultUsername,
                ["password"] = TestDataSeeder.DefaultPassword,
                ["client_id"] = TestDataSeeder.PasswordClientId,
                ["client_secret"] = TestDataSeeder.PasswordClientSecret,
                ["scope"] = TestDataSeeder.ScopeName,
            });
        Assert.Equal(HttpStatusCode.OK, tokenStatus);

        client.DefaultRequestHeaders.Authorization = IntrospectionTests.BasicAuthFor(
            TestDataSeeder.IntrospectionClientId,
            TestDataSeeder.IntrospectionClientSecret);
        var (_, introspection) = await client.PostFormAsync(
            "/connect/introspect",
            new Dictionary<string, string>
            {
                ["token"] = tokenBody.GetProperty("access_token").GetString()!,
            });

        Assert.Equal("pwd", introspection.GetProperty("amr").GetString());
        Assert.Equal(
            "urn:sufficit:acr:loa1",
            introspection.GetProperty("acr").GetString());
        Assert.True(introspection.GetProperty("auth_time").GetInt64() > 0);
    }
}
