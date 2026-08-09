using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using OpenIddict.Abstractions;
using Sufficit.Identity.Application.Accounts;
using Sufficit.Identity.Application.Security;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.Core.Services;
using Sufficit.Identity.STS;
using Sufficit.Identity.Tests.Infrastructure;
using Xunit;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Sufficit.Identity.Tests;

/// <summary>
/// A password reset is the flow a victim uses after losing control of the
/// account, so an attacker's already-issued tokens, authorizations and browser
/// sessions must not survive it.
/// </summary>
[Collection(StsCollection.Name)]
public sealed class PasswordResetRevocationTests(
    SufficitIdentityTestFactory factory)
{
    [Fact]
    public async Task Password_reset_retries_and_revokes_every_session_artifact()
    {
        string userId;
        string authorizationId;
        string tokenId;
        string beforeStamp;
        var sessionId = $"reset-session-{Guid.NewGuid():N}";
        var trigger = new CapturingSecurityEventTrigger();
        RetryingSessionRevoker revoker;

        await using (var scope = factory.Services.CreateAsyncScope())
        {
            var services = scope.ServiceProvider;
            var users = services.GetRequiredService<UserManager<ApplicationUser>>();
            SetHttpContext(services);

            var email = $"reset-revocation-{Guid.NewGuid():N}@example.test";
            var user = new ApplicationUser
            {
                UserName = email,
                Email = email,
                EmailConfirmed = true,
            };
            Assert.True((await users.CreateAsync(
                user, TestDataSeeder.DefaultPassword)).Succeeded);
            userId = user.Id;

            var applications = services
                .GetRequiredService<IOpenIddictApplicationManager>();
            var application = await applications.FindByClientIdAsync(
                TestDataSeeder.PasswordClientId)
                ?? throw new InvalidOperationException(
                    "Seeded application is missing.");
            var applicationId = await applications.GetIdAsync(application)
                ?? throw new InvalidOperationException(
                    "Seeded application has no id.");

            var authorizations = services
                .GetRequiredService<IOpenIddictAuthorizationManager>();
            var authorization = await authorizations.CreateAsync(
                new OpenIddictAuthorizationDescriptor
                {
                    ApplicationId = applicationId,
                    CreationDate = DateTimeOffset.UtcNow,
                    Subject = userId,
                    Status = Statuses.Valid,
                    Type = AuthorizationTypes.Permanent,
                });
            authorizationId = await authorizations.GetIdAsync(authorization)
                ?? throw new InvalidOperationException(
                    "Created authorization has no id.");

            var tokens = services.GetRequiredService<IOpenIddictTokenManager>();
            var token = await tokens.CreateAsync(new OpenIddictTokenDescriptor
            {
                ApplicationId = applicationId,
                AuthorizationId = authorizationId,
                CreationDate = DateTimeOffset.UtcNow,
                ExpirationDate = DateTimeOffset.UtcNow.AddHours(1),
                Status = Statuses.Valid,
                Subject = userId,
                Type = TokenTypeHints.RefreshToken,
            });
            tokenId = await tokens.GetIdAsync(token)
                ?? throw new InvalidOperationException("Created token has no id.");

            var databaseFactory = services
                .GetRequiredService<IDbContextFactory<AppDbContext>>();
            await using (var database = await databaseFactory.CreateDbContextAsync())
            {
                database.OidcUserSessions.Add(new OidcUserSession
                {
                    SessionId = sessionId,
                    Subject = userId,
                    CreatedAtUtc = DateTime.UtcNow,
                    LastActivityUtc = DateTime.UtcNow,
                    ProtectedTicket = [],
                });
                await database.SaveChangesAsync();
            }

            beforeStamp = await users.GetSecurityStampAsync(user);
            revoker = new RetryingSessionRevoker(
                services.GetRequiredService<IIdentityUserSessionRevoker>(),
                failuresBeforeSuccess: 2);
            var accounts = CreateAccountService(
                services,
                users,
                revoker,
                trigger);

            var resetToken = await users.GeneratePasswordResetTokenAsync(user);
            var reset = await accounts.ResetPasswordAsync(
                new AccountPasswordResetCommand(
                    userId,
                    EncodeToken(resetToken),
                    "An0ther!Str0ng#Password27"));

            Assert.Equal(AccountPasswordResetStatus.Succeeded, reset.Status);
        }

        // OpenIddict revocation uses ExecuteUpdateAsync and intentionally
        // bypasses EF's change tracker. Verify persisted state from a fresh
        // scope instead of reading the stale objects created above.
        await using (var verificationScope = factory.Services.CreateAsyncScope())
        {
            var services = verificationScope.ServiceProvider;
            var users = services.GetRequiredService<UserManager<ApplicationUser>>();
            var refreshed = await users.FindByIdAsync(userId);
            Assert.NotNull(refreshed);
            Assert.NotEqual(
                beforeStamp,
                await users.GetSecurityStampAsync(refreshed));

            var authorizations = services
                .GetRequiredService<IOpenIddictAuthorizationManager>();
            var persistedAuthorization = await authorizations.FindByIdAsync(
                authorizationId)
                ?? throw new InvalidOperationException(
                    "Created authorization is missing.");
            Assert.Equal(
                Statuses.Revoked,
                await authorizations.GetStatusAsync(persistedAuthorization));

            var tokens = services.GetRequiredService<IOpenIddictTokenManager>();
            var persistedToken = await tokens.FindByIdAsync(tokenId)
                ?? throw new InvalidOperationException("Created token is missing.");
            Assert.Equal(
                Statuses.Revoked,
                await tokens.GetStatusAsync(persistedToken));

            var databaseFactory = services
                .GetRequiredService<IDbContextFactory<AppDbContext>>();
            await using var database = await databaseFactory.CreateDbContextAsync();
            Assert.False(await database.OidcUserSessions
                .AnyAsync(session => session.SessionId == sessionId));
        }

        Assert.Equal(3, revoker.Attempts);
        Assert.Equal(userId, trigger.Subject);
        Assert.Null(trigger.SessionId);
        Assert.Equal(CaepCredentialType.Password, trigger.Change?.CredentialType);
        Assert.Equal(CaepChangeOperation.Updated, trigger.Change?.Operation);
    }

    [Fact]
    public async Task Password_reset_keeps_success_and_emits_caep_when_revocation_exhausts_retries()
    {
        await using var scope = factory.Services.CreateAsyncScope();
        var services = scope.ServiceProvider;
        var users = services.GetRequiredService<UserManager<ApplicationUser>>();
        SetHttpContext(services);

        var email = $"reset-failure-{Guid.NewGuid():N}@example.test";
        var user = new ApplicationUser
        {
            UserName = email,
            Email = email,
            EmailConfirmed = true,
        };
        Assert.True((await users.CreateAsync(
            user, TestDataSeeder.DefaultPassword)).Succeeded);

        var trigger = new CapturingSecurityEventTrigger();
        var revoker = new RetryingSessionRevoker(
            services.GetRequiredService<IIdentityUserSessionRevoker>(),
            failuresBeforeSuccess: int.MaxValue);
        var accounts = CreateAccountService(
            services,
            users,
            revoker,
            trigger);
        var resetToken = await users.GeneratePasswordResetTokenAsync(user);

        var reset = await accounts.ResetPasswordAsync(
            new AccountPasswordResetCommand(
                user.Id,
                EncodeToken(resetToken),
                "An0ther!Str0ng#Password28"));

        Assert.Equal(AccountPasswordResetStatus.Succeeded, reset.Status);
        Assert.Equal(3, revoker.Attempts);
        Assert.Equal(user.Id, trigger.Subject);
        Assert.Equal(CaepCredentialType.Password, trigger.Change?.CredentialType);
        Assert.Equal(CaepChangeOperation.Updated, trigger.Change?.Operation);
    }

    private static AspNetCoreIdentityAccountOnboardingService CreateAccountService(
        IServiceProvider services,
        UserManager<ApplicationUser> users,
        IIdentityUserSessionRevoker revoker,
        ISecurityEventTrigger trigger) =>
        new(
            users,
            services.GetRequiredService<IEmailSender>(),
            services.GetRequiredService<IHttpContextAccessor>(),
            services.GetRequiredService<IConfiguration>(),
            services.GetRequiredService<IPublicOriginResolver>(),
            services.GetRequiredService<IAccountLookupPolicy>(),
            revoker,
            trigger,
            NullLogger<AspNetCoreIdentityAccountOnboardingService>.Instance);

    private static string EncodeToken(string token) =>
        Microsoft.AspNetCore.WebUtilities.WebEncoders.Base64UrlEncode(
            System.Text.Encoding.UTF8.GetBytes(token));

    private static void SetHttpContext(IServiceProvider services)
    {
        var context = new DefaultHttpContext
        {
            RequestServices = services,
        };
        context.Request.Scheme = "https";
        context.Request.Host = new HostString("sts.tests.local");
        services.GetRequiredService<IHttpContextAccessor>().HttpContext = context;
    }

    private sealed class RetryingSessionRevoker(
        IIdentityUserSessionRevoker inner,
        int failuresBeforeSuccess) : IIdentityUserSessionRevoker
    {
        public int Attempts { get; private set; }

        public Task<long> RevokeTokensAsync(
            string subject,
            CancellationToken cancellationToken = default) =>
            inner.RevokeTokensAsync(subject, cancellationToken);

        public async Task<IdentityUserSessionRevocation> RevokeAsync(
            string subject,
            CancellationToken cancellationToken = default)
        {
            Attempts++;
            if (Attempts <= failuresBeforeSuccess)
            {
                throw new InvalidOperationException("Simulated transient failure.");
            }

            return await inner.RevokeAsync(subject, cancellationToken);
        }
    }

    private sealed class CapturingSecurityEventTrigger : ISecurityEventTrigger
    {
        public string? Subject { get; private set; }
        public string? SessionId { get; private set; }
        public CaepCredentialChange? Change { get; private set; }

        public Task CredentialChangedAsync(
            string subject,
            string? sessionId,
            CaepCredentialChange change,
            CancellationToken cancellationToken = default)
        {
            Subject = subject;
            SessionId = sessionId;
            Change = change;
            return Task.CompletedTask;
        }

        public Task DeviceChangedAsync(
            string subject,
            string? sessionId,
            CaepDeviceChange change,
            CancellationToken cancellationToken = default) =>
            Task.CompletedTask;

        public Task AssuranceLevelChangedAsync(
            string subject,
            string? sessionId,
            CaepAssuranceLevelChange change,
            CancellationToken cancellationToken = default) =>
            Task.CompletedTask;
    }
}
