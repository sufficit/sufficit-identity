using System.Globalization;
using System.Net;
using System.Net.Http.Json;
using System.Security.Claims;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using OpenIddict.Abstractions;
using OpenIddict.EntityFrameworkCore.Models;
using OpenIddict.Server;
using Sufficit.Identity.Application.Security;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.Core.Services;
using Sufficit.Identity.Management.Authorization;
using Sufficit.Identity.Management.Users;
using Sufficit.Identity.STS;
using Sufficit.Identity.STS.Tokens;
using Sufficit.Identity.Tests.Infrastructure;
using Xunit;

namespace Sufficit.Identity.Tests;

public sealed class AdministrativeMfaResetTests
{
    [Fact]
    public async Task Reset_revokes_only_target_credentials_sessions_and_codes_and_records_reason()
    {
        using var factory = new ManagementTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        var email = new RecordingEmailSender();
        using var host = factory.WithWebHostBuilder(builder => builder.ConfigureServices(services =>
            services.Replace(ServiceDescriptor.Singleton<IEmailSender>(email))));
        await using var scope = host.Services.CreateAsyncScope();
        var users = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var target = await TargetAsync(users);
        var other = await TargetAsync(users);
        var key = await users.GetAuthenticatorKeyAsync(target);
        var stamp = target.SecurityStamp;
        var oldCodes = (await users.GenerateNewTwoFactorRecoveryCodesAsync(target, 2))!.ToArray();
        var authorizationId = Guid.NewGuid().ToString();
        var tokenId = Guid.NewGuid().ToString();
        db.Set<OpenIddictEntityFrameworkCoreAuthorization>().Add(new()
        {
            Id = authorizationId, Subject = target.Id, Status = OpenIddictConstants.Statuses.Valid,
            Type = OpenIddictConstants.AuthorizationTypes.Permanent,
        });
        db.Set<OpenIddictEntityFrameworkCoreToken>().Add(new()
        {
            Id = tokenId, Subject = target.Id, Status = OpenIddictConstants.Statuses.Valid,
            Type = OpenIddictConstants.TokenTypeHints.RefreshToken,
        });
        db.Set<OidcUserSession>().AddRange(Session(target.Id), Session(other.Id));
        await db.SaveChangesAsync();

        var result = await scope.ServiceProvider.GetRequiredService<IUserManagementService>()
            .ResetTwoFactorAsync(target.Id, Command(target), Operator());

        Assert.False(result.User.TwoFactorEnabled);
        Assert.True(result.User.TwoFactorReenrollmentRequired);
        Assert.True(result.NotificationQueued);
        Assert.Equal(target.Email, Assert.Single(email.Recipients));
        db.ChangeTracker.Clear();
        target = (await users.FindByIdAsync(target.Id))!;
        Assert.NotEqual(key, await users.GetAuthenticatorKeyAsync(target));
        Assert.NotEqual(stamp, target.SecurityStamp);
        Assert.True(await users.CheckPasswordAsync(target, TestDataSeeder.DefaultPassword));
        Assert.Equal(0, await users.CountRecoveryCodesAsync(target));
        Assert.False((await users.RedeemTwoFactorRecoveryCodeAsync(target, oldCodes[0])).Succeeded);
        Assert.Equal(OpenIddictConstants.Statuses.Revoked,
            (await db.Set<OpenIddictEntityFrameworkCoreToken>().SingleAsync(x => x.Id == tokenId)).Status);
        Assert.Equal(OpenIddictConstants.Statuses.Revoked,
            (await db.Set<OpenIddictEntityFrameworkCoreAuthorization>().SingleAsync(x => x.Id == authorizationId)).Status);
        Assert.False(await db.Set<OidcUserSession>().AnyAsync(x => x.Subject == target.Id));
        Assert.True(await db.Set<OidcUserSession>().AnyAsync(x => x.Subject == other.Id));
        Assert.True((await users.FindByIdAsync(other.Id))!.TwoFactorEnabled);
        var audit = await db.ManagementAuditEvents.SingleAsync(x => x.ResourceId == target.Id && x.ReasonCode == "user_mfa_reset");
        Assert.Equal("operator-1", audit.OperatorSubject);
        Assert.Contains("Chamado 123: aparelho perdido", audit.AfterJson);
        Assert.DoesNotContain(key!, audit.AfterJson!);
    }

    [Theory]
    [InlineData("missing")]
    [InlineData("remembered")]
    [InlineData("stale")]
    [InlineData("future")]
    [InlineData("self")]
    public async Task Unsafe_operator_evidence_cannot_reset(string evidence)
    {
        using var factory = new ManagementTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        await using var scope = factory.Services.CreateAsyncScope();
        var users = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        var target = await TargetAsync(users);
        var principal = Operator(evidence == "self" ? target.Id : "operator-1").Operator;
        var identity = (ClaimsIdentity)principal.Identity!;
        if (evidence == "missing") identity.RemoveClaim(identity.FindFirst("amr")!);
        if (evidence == "remembered") identity.AddClaim(new(MfaEvidencePolicy.RememberedSecondFactorClaimType, "true"));
        if (evidence is "stale" or "future")
        {
            identity.RemoveClaim(identity.FindFirst("auth_time")!);
            identity.AddClaim(new("auth_time", DateTimeOffset.UtcNow.AddHours(evidence == "stale" ? -1 : 1).ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture)));
        }
        await Assert.ThrowsAsync<ManagementAccessException>(() => scope.ServiceProvider.GetRequiredService<IUserManagementService>()
            .ResetTwoFactorAsync(target.Id, Command(target), new(principal, "test-denied")));
        Assert.True((await users.FindByIdAsync(target.Id))!.TwoFactorEnabled);
        Assert.False(await MfaRecoveryState.IsRequiredAsync(users, target));
    }

    [Theory]
    [InlineData("reason")]
    [InlineData("confirmation")]
    [InlineData("identity")]
    public async Task Missing_recovery_verification_does_not_mutate(string invalid)
    {
        using var factory = new ManagementTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        await using var scope = factory.Services.CreateAsyncScope();
        var users = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        var target = await TargetAsync(users);
        var command = Command(target);
        command = invalid switch
        {
            "reason" => command with { Reason = "short" },
            "confirmation" => command with { Confirmation = "another-account" },
            _ => command with { IdentityVerified = false },
        };
        await Assert.ThrowsAsync<ManagementValidationException>(() => scope.ServiceProvider.GetRequiredService<IUserManagementService>()
            .ResetTwoFactorAsync(target.Id, command, Operator()));
        Assert.True((await users.FindByIdAsync(target.Id))!.TwoFactorEnabled);
    }

    [Fact]
    public async Task Failed_revocation_rolls_back_key_codes_stamp_and_recovery_state()
    {
        using var factory = new ManagementTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        using var host = factory.WithWebHostBuilder(builder => builder.ConfigureServices(services =>
            services.Replace(ServiceDescriptor.Singleton<IIdentityUserSessionRevoker>(new FailingRevoker()))));
        await using var scope = host.Services.CreateAsyncScope();
        var users = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var target = await TargetAsync(users);
        var key = await users.GetAuthenticatorKeyAsync(target);
        var stamp = target.SecurityStamp;
        var codes = (await users.GenerateNewTwoFactorRecoveryCodesAsync(target, 2))!.ToArray();
        await Assert.ThrowsAsync<ManagementConflictException>(() => scope.ServiceProvider.GetRequiredService<IUserManagementService>()
            .ResetTwoFactorAsync(target.Id, Command(target), Operator()));
        db.ChangeTracker.Clear();
        target = (await users.FindByIdAsync(target.Id))!;
        Assert.True(target.TwoFactorEnabled);
        Assert.Equal(stamp, target.SecurityStamp);
        Assert.Equal(key, await users.GetAuthenticatorKeyAsync(target));
        Assert.Equal(2, await users.CountRecoveryCodesAsync(target));
        Assert.True((await users.RedeemTwoFactorRecoveryCodeAsync(target, codes[0])).Succeeded);
        Assert.False(await MfaRecoveryState.IsRequiredAsync(users, target));
        Assert.True(await db.ManagementAuditEvents.AnyAsync(x => x.ResourceId == target.Id && x.ReasonCode == "user_mfa_reset_failed"));
    }

    [Fact]
    public async Task Notification_failure_does_not_disguise_committed_reset()
    {
        using var factory = new ManagementTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        using var host = factory.WithWebHostBuilder(builder => builder.ConfigureServices(services =>
            services.Replace(ServiceDescriptor.Singleton<IEmailSender>(new RecordingEmailSender { Fail = true }))));
        await using var scope = host.Services.CreateAsyncScope();
        var target = await TargetAsync(scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>());
        var result = await scope.ServiceProvider.GetRequiredService<IUserManagementService>()
            .ResetTwoFactorAsync(target.Id, Command(target), Operator());
        Assert.False(result.NotificationQueued);
        Assert.False(result.User.TwoFactorEnabled);
        Assert.True(result.User.TwoFactorReenrollmentRequired);
    }

    [Fact]
    public async Task Recovery_marker_blocks_token_generation_and_redirects_browser_but_allows_setup()
    {
        using var factory = new ManagementTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        await using var scope = factory.Services.CreateAsyncScope();
        var users = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        var target = await TargetAsync(users);
        Assert.True((await MfaRecoveryState.RequireAsync(users, target)).Succeeded);
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var principal = Operator(target.Id).Operator;
        ((ClaimsIdentity)principal.Identity!).AddClaim(new("sub", target.Id));
        var token = new OpenIddictServerEvents.GenerateTokenContext(new OpenIddictServerTransaction()) { Principal = principal };
        await new MfaRecoveryTokenGuard(db).HandleAsync(token);
        Assert.True(token.IsRejected);
        var called = false;
        var middleware = new MfaRecoveryNavigationMiddleware(_ => { called = true; return Task.CompletedTask; });
        var context = new DefaultHttpContext { User = principal };
        context.Request.Method = "GET";
        context.Request.Headers.Accept = "text/html";
        context.Request.Path = "/management/";
        await middleware.InvokeAsync(context, db);
        Assert.False(called);
        Assert.Equal("/manage/twofactor", context.Response.Headers.Location.ToString());
        context.Request.Path = "/manage/twofactor";
        await middleware.InvokeAsync(context, db);
        Assert.True(called);
        Assert.True((await MfaRecoveryState.CompleteAsync(users, target)).Succeeded);
        var allowed = new OpenIddictServerEvents.GenerateTokenContext(new OpenIddictServerTransaction()) { Principal = principal };
        await new MfaRecoveryTokenGuard(db).HandleAsync(allowed);
        Assert.False(allowed.IsRejected);
    }

    [Fact]
    public async Task Http_endpoint_denies_anonymous_requests()
    {
        using var factory = ManagementTestFactory.CreateWithRealAuthz();
        await ((IAsyncLifetime)factory).InitializeAsync();
        using var response = await factory.CreateClient().PostAsJsonAsync("/api/users/unknown/reset-two-factor",
            new ResetManagementUserTwoFactorCommand("Chamado verificado", "unknown", true));
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Theory]
    [InlineData("allowed")]
    [InlineData("missing-permission")]
    [InlineData("protected-target")]
    [InlineData("recovering-operator")]
    public async Task Real_authorization_enforces_dedicated_capability_and_protected_principals(string scenario)
    {
        using var factory = new ManagementTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        using var host = factory.WithWebHostBuilder(builder => builder.ConfigureServices(services =>
        {
            services.Replace(ServiceDescriptor.Scoped<IManagementAuthorizationEvaluator, CapabilityManagementAuthorizationEvaluator>());
            services.Replace(ServiceDescriptor.Scoped<IManagementEntitlementResolver, ScopeAndRoleManagementEntitlementResolver>());
            services.Replace(ServiceDescriptor.Singleton<IEmailSender>(new RecordingEmailSender()));
        }));
        await using var scope = host.Services.CreateAsyncScope();
        var users = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        var target = await TargetAsync(users);
        var actor = await TargetAsync(users);
        var context = Operator(actor.Id);
        if (scenario == "missing-permission")
        {
            var identity = (ClaimsIdentity)context.Operator.Identity!;
            identity.RemoveClaim(identity.FindFirst(x => x.Type == "permission" && x.Value == ManagementCapabilities.UsersResetMfa)!);
            identity.AddClaim(new("permission", ManagementCapabilities.UsersReset));
        }
        if (scenario == "protected-target")
            Assert.True((await users.AddClaimAsync(target, new("identity_principal_tier", "2"))).Succeeded);
        if (scenario == "recovering-operator")
            Assert.True((await MfaRecoveryState.RequireAsync(users, actor)).Succeeded);
        var service = scope.ServiceProvider.GetRequiredService<IUserManagementService>();
        if (scenario == "allowed")
        {
            var reset = await service.ResetTwoFactorAsync(target.Id, Command(target), context);
            Assert.False(reset.User.TwoFactorEnabled);
        }
        else
        {
            await Assert.ThrowsAsync<ManagementAccessException>(() => service.ResetTwoFactorAsync(target.Id, Command(target), context));
            Assert.True((await users.FindByIdAsync(target.Id))!.TwoFactorEnabled);
        }
    }

    private static async Task<ApplicationUser> TargetAsync(UserManager<ApplicationUser> users)
    {
        var user = await TestDataSeeder.CreateUserAsync(users, $"mfa-recovery-{Guid.NewGuid():N}", TestDataSeeder.DefaultPassword);
        user.EmailConfirmed = true;
        Assert.True((await users.UpdateAsync(user)).Succeeded);
        Assert.True((await users.ResetAuthenticatorKeyAsync(user)).Succeeded);
        Assert.True((await users.SetTwoFactorEnabledAsync(user, true)).Succeeded);
        return user;
    }

    private static ResetManagementUserTwoFactorCommand Command(ApplicationUser user) => new("Chamado 123: aparelho perdido", user.UserName!, true);
    private static ManagementRequestContext Operator(string id = "operator-1") => new(new ClaimsPrincipal(new ClaimsIdentity(
        [new Claim(ClaimTypes.NameIdentifier, id), new Claim("amr", "mfa"),
         new Claim("auth_time", DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture)),
         new Claim("permission", ManagementCapabilities.UsersRead), new Claim("permission", ManagementCapabilities.UsersResetMfa)], "test")), "test-mfa-reset");
    private static OidcUserSession Session(string subject) => new()
    {
        Subject = subject, SessionId = Guid.NewGuid().ToString(), CreatedAtUtc = DateTime.UtcNow,
        LastActivityUtc = DateTime.UtcNow, ExpiresUtc = DateTime.UtcNow.AddHours(1), ProtectedTicket = [1],
    };
    private sealed class RecordingEmailSender : IEmailSender
    {
        public bool Fail { get; init; }
        public List<string> Recipients { get; } = [];
        public Task SendEmailAsync(string email, string subject, string htmlMessage)
        {
            if (Fail) throw new InvalidOperationException("Test email transport unavailable");
            Recipients.Add(email);
            return Task.CompletedTask;
        }
    }
    private sealed class FailingRevoker : IIdentityUserSessionRevoker
    {
        public Task<long> RevokeTokensAsync(string subject, CancellationToken cancellationToken = default) => throw new InvalidOperationException("Test revocation failure");
        public Task<IdentityUserSessionRevocation> RevokeAsync(string subject, CancellationToken cancellationToken = default) => throw new InvalidOperationException("Test revocation failure");
        public Task<IdentityUserSessionRevocation> RevokeAsync(string subject, string? exceptBrowserSessionId, CancellationToken cancellationToken = default) => throw new InvalidOperationException("Test revocation failure");
    }
}
