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
            new Claim("acr", "urn:example:acr:loa2"),
            new Claim("auth_time", "123456"),
        ]);
        var destination = new ClaimsIdentity();

        new AuthenticationContextProjector(
            new ConfigurableAuthenticationContextClassMapper(
                new AuthenticationContextOptions()))
            .Project(
            new ClaimsPrincipal(sourceIdentity),
            destination);

        Assert.Equal(
            ["pwd", "mfa"],
            destination.FindAll("amr").Select(claim => claim.Value));
        Assert.Equal("urn:identity:acr:loa2", destination.FindFirst("acr")?.Value);
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
            "urn:example:acr:loa2"));
        var claimsFactory = scope.ServiceProvider
            .GetRequiredService<IUserClaimsPrincipalFactory<ApplicationUser>>();

        var principal = await claimsFactory.CreateAsync(user);

        Assert.Contains(principal.FindAll("amr"), claim => claim.Value == "pwd");
        Assert.Contains(principal.FindAll("amr"), claim => claim.Value == "mfa");
        Assert.Equal("urn:example:acr:loa2", principal.FindFirst("acr")?.Value);
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
            "urn:example:acr:loa3"));
        var claimsFactory = scope.ServiceProvider
            .GetRequiredService<IUserClaimsPrincipalFactory<ApplicationUser>>();

        var principal = await claimsFactory.CreateAsync(user);

        Assert.Equal("persisted-session", principal.FindFirst("sid")?.Value);
        Assert.Contains(principal.FindAll("amr"), claim => claim.Value == "passkey");
        Assert.Equal("urn:example:acr:loa3", principal.FindFirst("acr")?.Value);
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

    [Theory]
    [InlineData(Sufficit.Identity.Application.Security.CaepAssuranceLevel.Loa1, "urn:identity:acr:loa1")]
    [InlineData(Sufficit.Identity.Application.Security.CaepAssuranceLevel.Loa2, "urn:identity:acr:loa2")]
    [InlineData(Sufficit.Identity.Application.Security.CaepAssuranceLevel.Loa3, "urn:identity:acr:loa3")]
    [InlineData(Sufficit.Identity.Application.Security.CaepAssuranceLevel.PhishingResistant, "urn:identity:acr:loa3")]
    public void Mapper_spells_levels_with_the_neutral_default_prefix(
        Sufficit.Identity.Application.Security.CaepAssuranceLevel level,
        string expected)
    {
        var mapper = new ConfigurableAuthenticationContextClassMapper(
            new AuthenticationContextOptions());

        Assert.Equal(expected, mapper.Map(level));
    }

    [Fact]
    public void Mapper_uses_the_configured_prefix()
    {
        // The acr vocabulary is a deployment's public contract: relying parties
        // that already check another prefix keep receiving it.
        var mapper = new ConfigurableAuthenticationContextClassMapper(
            new AuthenticationContextOptions { AcrPrefix = "urn:example:loa:" });

        Assert.Equal(
            "urn:example:loa:loa2",
            mapper.Map(Sufficit.Identity.Application.Security.CaepAssuranceLevel.Loa2));
    }

    [Fact]
    public void Projector_spells_a_stamped_level_instead_of_concatenating_its_name()
    {
        // Regression: the fallback concatenated the enum name, emitting values
        // such as "...acr:loaLoa2".
        var sourceIdentity = new ClaimsIdentity(
        [
            new Claim("amr", "pwd mfa"),
            new Claim(OidcSessionClaimsPrincipalFactory.AssuranceLevelClaimType, "Loa2"),
        ]);
        var destination = new ClaimsIdentity();

        new AuthenticationContextProjector(
                new ConfigurableAuthenticationContextClassMapper(
                    new AuthenticationContextOptions()))
            .Project(new ClaimsPrincipal(sourceIdentity), destination);

        Assert.Equal("urn:identity:acr:loa2", destination.FindFirst("acr")?.Value);
    }

    [Theory]
    [InlineData(false, false, false, false, true)]
    [InlineData(true, false, false, false, true)]
    [InlineData(true, true, false, false, true)]
    [InlineData(true, true, true, false, true)]
    [InlineData(true, true, false, true, true)]
    [InlineData(true, true, false, false, false)]
    public async Task Session_evidence_is_owned_and_replaced_not_merged(
        bool sameUser, bool persisted, bool fresh, bool expired, bool authenticated)
    {
        using var factory = SufficitIdentityTestFactory.CreateIsolated(new Dictionary<string, string?>());
        await ((IAsyncLifetime)factory).InitializeAsync();
        await using var scope = factory.Services.CreateAsyncScope();
        var users = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        var user = (await users.FindByNameAsync(TestDataSeeder.DefaultUsername))!;
        Assert.True((await users.AddClaimsAsync(user, new[]
        {
            new Claim("amr", "passkey"), new Claim("amr", "mfa"),
            new Claim("aal", "PhishingResistant"), new Claim("acr", "stored-acr"),
            new Claim("identity:mfa_remembered", "true"), new Claim("auth_time", "42")
        })).Succeeded);
        if (persisted)
        {
            await using var db = await scope.ServiceProvider
                .GetRequiredService<IDbContextFactory<Sufficit.Identity.Core.Data.AppDbContext>>()
                .CreateDbContextAsync();
            db.OidcUserSessions.Add(new OidcUserSession
            {
                SessionId = "owned-evidence", Subject = user.Id,
                ExpiresUtc = expired ? DateTime.UtcNow.AddMinutes(-5) : null,
                CreatedAtUtc = DateTime.UtcNow, LastActivityUtc = DateTime.UtcNow
            });
            await db.SaveChangesAsync();
        }
        scope.ServiceProvider.GetRequiredService<IHttpContextAccessor>().HttpContext = new DefaultHttpContext
        {
            User = new ClaimsPrincipal(new ClaimsIdentity(new[]
            {
                new Claim(ClaimTypes.NameIdentifier, sameUser ? user.Id : "other-user"),
                new Claim("sid", "owned-evidence"), new Claim("amr", "pwd mfa"),
                new Claim("identity:mfa_remembered", "true"), new Claim("auth_time", "123456")
            }, authenticated ? "Test" : null))
        };
        if (fresh)
            scope.ServiceProvider.GetRequiredService<IAuthenticationContextAccessor>().Set(
                new AuthenticationContextEvidence(new[] { "pwd", "otp", "mfa" },
                    DateTimeOffset.FromUnixTimeSeconds(234567), "urn:identity:acr:loa2"));
        var principal = await scope.ServiceProvider
            .GetRequiredService<IUserClaimsPrincipalFactory<ApplicationUser>>().CreateAsync(user);
        var retained = sameUser && persisted && !expired && authenticated;
        Assert.DoesNotContain(principal.FindAll("amr"), c => c.Value == "passkey");
        Assert.Equal(fresh || retained ? "Loa2" : "Loa1", principal.FindFirst("aal")?.Value);
        Assert.Equal(fresh || retained ? "urn:identity:acr:loa2" : "urn:identity:acr:loa1",
            principal.FindFirst("acr")?.Value);
        Assert.Equal(retained && !fresh,
            Sufficit.Identity.Application.Security.MfaEvidencePolicy.IsSecondFactorRemembered(principal));
        if (fresh || retained)
            Assert.Equal(fresh ? "234567" : "123456", principal.FindFirst("auth_time")?.Value);
        else
        {
            Assert.Empty(principal.FindAll("amr"));
            Assert.NotEqual("123456", principal.FindFirst("auth_time")?.Value);
        }
        var token = new ClaimsIdentity();
        scope.ServiceProvider.GetRequiredService<IAuthenticationContextProjector>().Project(principal, token);
        Assert.Equal(principal.FindFirst("acr")?.Value, token.FindFirst("acr")?.Value);
        Assert.Equal(principal.FindFirst("auth_time")?.Value, token.FindFirst("auth_time")?.Value);
    }

    [Fact]
    public async Task Session_factory_without_sign_in_evidence_spells_the_resolved_level()
    {
        using var factory = SufficitIdentityTestFactory.CreateIsolated(
            new Dictionary<string, string?>());
        await ((IAsyncLifetime)factory).InitializeAsync();
        await using var scope = factory.Services.CreateAsyncScope();
        var users = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        var user = await users.FindByNameAsync(TestDataSeeder.DefaultUsername)
            ?? throw new InvalidOperationException("Seed user not found.");

        var principal = await scope.ServiceProvider
            .GetRequiredService<IUserClaimsPrincipalFactory<ApplicationUser>>()
            .CreateAsync(user);

        Assert.Equal("urn:identity:acr:loa1", principal.FindFirst("acr")?.Value);
    }

    [Fact]
    public async Task Cookie_renewal_normalizes_old_assurance_without_losing_remembered_evidence()
    {
        using var factory = SufficitIdentityTestFactory.CreateIsolated(new Dictionary<string, string?>());
        await ((IAsyncLifetime)factory).InitializeAsync();
        var options = factory.Services.GetRequiredService<Microsoft.Extensions.Options.IOptions<SecurityStampValidatorOptions>>().Value;
        var context = new SecurityStampRefreshingPrincipalContext
        {
            CurrentPrincipal = new ClaimsPrincipal(new ClaimsIdentity(new[]
            {
                new Claim("amr", "passkey hwk"), new Claim("aal", "PhishingResistant"),
                new Claim("acr", "urn:identity:acr:loa3"), new Claim("auth_time", "123456"),
                new Claim("identity:mfa_remembered", "true"), new Claim("sid", "renewed-session")
            }, "test")),
            NewPrincipal = new ClaimsPrincipal(new ClaimsIdentity())
        };
        await options.OnRefreshingPrincipal!(context);
        Assert.Equal("Loa1", context.NewPrincipal.FindFirst("aal")?.Value);
        Assert.Equal("urn:identity:acr:loa1", context.NewPrincipal.FindFirst("acr")?.Value);
        Assert.Equal("true", context.NewPrincipal.FindFirst("identity:mfa_remembered")?.Value);
        Assert.Equal("123456", context.NewPrincipal.FindFirst("auth_time")?.Value);
    }

    [Fact]
    public void Refresh_projection_downgrades_stale_acr_and_retains_remembered_marker()
    {
        var source = new ClaimsPrincipal(new ClaimsIdentity(new[]
        {
            new Claim("amr", "passkey hwk"), new Claim("acr", "urn:identity:acr:loa3"),
            new Claim("auth_time", "123456"), new Claim("identity:mfa_remembered", "true")
        }));
        var token = new ClaimsIdentity();
        new AuthenticationContextProjector(new ConfigurableAuthenticationContextClassMapper(
            new AuthenticationContextOptions())).Project(source, token);
        Assert.Equal("urn:identity:acr:loa1", token.FindFirst("acr")?.Value);
        Assert.Equal("123456", token.FindFirst("auth_time")?.Value);
        Assert.Equal("true", token.FindFirst("identity:mfa_remembered")?.Value);
    }

    [Fact]
    public async Task Password_grant_projects_amr_acr_and_auth_time_into_access_token()
    {
        using var factory = SufficitIdentityTestFactory.CreateIsolated(
            new Dictionary<string, string?>());
        await ((IAsyncLifetime)factory).InitializeAsync();
        using (var scope = factory.Services.CreateScope())
        {
            var users = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
            var user = (await users.FindByNameAsync(TestDataSeeder.DefaultUsername))!;
            Assert.True((await users.AddClaimsAsync(user, new[]
            {
                new Claim("amr", "mfa"), new Claim("acr", "urn:identity:acr:loa3"),
                new Claim("aal", "PhishingResistant"), new Claim("auth_time", "1")
            })).Succeeded);
        }
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
            "urn:identity:acr:loa1",
            introspection.GetProperty("acr").GetString());
        Assert.True(introspection.GetProperty("auth_time").GetInt64() > 0);
    }
}
