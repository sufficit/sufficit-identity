using System.Net;
using System.Net.Http.Json;
using System.Security.Claims;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;
using OpenIddict.EntityFrameworkCore.Models;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.Core.Services;
using Sufficit.Identity.Application.Accounts;
using Sufficit.Identity.Management;
using Sufficit.Identity.Management.Authorization;
using Sufficit.Identity.Management.Users;
using Sufficit.Identity.Tests.Infrastructure;
using Xunit;

namespace Sufficit.Identity.Tests;

public sealed partial class UserManagementControllerTests
{
    [Fact]
    public async Task Lockout_revokes_identity_tokens_and_authorizations()
    {
        using var factory = new ManagementTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();

        string targetId;
        string? originalSecurityStamp;
        var authorizationId = Guid.NewGuid().ToString("N");
        var tokenId = Guid.NewGuid().ToString("N");
        await using (var setup = factory.Services.CreateAsyncScope())
        {
            var userManager = setup.ServiceProvider
                .GetRequiredService<UserManager<ApplicationUser>>();
            var target = await TestDataSeeder.CreateUserAsync(
                userManager,
                $"lockout-{Guid.NewGuid():N}",
                "Original!Passw0rd#10");
            targetId = target.Id;
            originalSecurityStamp = target.SecurityStamp;

            var setupDatabase = setup.ServiceProvider
                .GetRequiredService<AppDbContext>();
            setupDatabase.Set<OpenIddictEntityFrameworkCoreAuthorization>().Add(
                new OpenIddictEntityFrameworkCoreAuthorization
                {
                    Id = authorizationId,
                    ConcurrencyToken = Guid.NewGuid().ToString("N"),
                    CreationDate = DateTime.UtcNow,
                    Status = OpenIddictConstants.Statuses.Valid,
                    Subject = targetId,
                    Type = OpenIddictConstants.AuthorizationTypes.Permanent
                });
            setupDatabase.Set<OpenIddictEntityFrameworkCoreToken>().Add(
                new OpenIddictEntityFrameworkCoreToken
                {
                    Id = tokenId,
                    ConcurrencyToken = Guid.NewGuid().ToString("N"),
                    CreationDate = DateTime.UtcNow,
                    Status = OpenIddictConstants.Statuses.Valid,
                    Subject = targetId,
                    Type = OpenIddictConstants.TokenTypeHints.RefreshToken
                });
            await setupDatabase.SaveChangesAsync();
        }

        await using var scope = factory.Services.CreateAsyncScope();
        var service = scope.ServiceProvider
            .GetRequiredService<IUserManagementService>();
        var locked = await service.SetLockoutAsync(
            targetId,
            new SetManagementUserLockoutCommand(Locked: true),
            RequestContext("provider-operator"));

        Assert.True(locked.LockoutEnabled);
        Assert.True(locked.LockoutEnd > DateTimeOffset.UtcNow);

        var database = scope.ServiceProvider
            .GetRequiredService<AppDbContext>();
        database.ChangeTracker.Clear();
        var persisted = await database.Users.SingleAsync(
            user => user.Id == targetId);
        var authorization = await database
            .Set<OpenIddictEntityFrameworkCoreAuthorization>()
            .SingleAsync(entry => entry.Id == authorizationId);
        var token = await database
            .Set<OpenIddictEntityFrameworkCoreToken>()
            .SingleAsync(entry => entry.Id == tokenId);

        Assert.NotEqual(originalSecurityStamp, persisted.SecurityStamp);
        Assert.Equal(
            OpenIddictConstants.Statuses.Revoked,
            authorization.Status);
        Assert.Equal(OpenIddictConstants.Statuses.Revoked, token.Status);

        var stampOptions = scope.ServiceProvider
            .GetRequiredService<IOptions<SecurityStampValidatorOptions>>();
        Assert.Equal(TimeSpan.Zero, stampOptions.Value.ValidationInterval);
    }

    [Fact]
    public async Task Failed_session_revocation_rolls_back_lockout_and_audits_failure()
    {
        using var factory = new ManagementTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        using var failingFactory = factory.WithWebHostBuilder(builder =>
            builder.ConfigureServices(services =>
            {
                services.RemoveAll<IIdentityUserSessionRevoker>();
                services.AddSingleton<
                    IIdentityUserSessionRevoker,
                    ThrowingManagementUserSessionRevoker>();
            }));

        string targetId;
        string? originalSecurityStamp;
        await using (var setup = failingFactory.Services.CreateAsyncScope())
        {
            var userManager = setup.ServiceProvider
                .GetRequiredService<UserManager<ApplicationUser>>();
            var target = await TestDataSeeder.CreateUserAsync(
                userManager,
                $"lockout-rollback-{Guid.NewGuid():N}",
                "Original!Passw0rd#13");
            targetId = target.Id;
            originalSecurityStamp = target.SecurityStamp;
        }

        await using var scope = failingFactory.Services.CreateAsyncScope();
        var service = scope.ServiceProvider
            .GetRequiredService<IUserManagementService>();
        var failure = await Assert.ThrowsAsync<ManagementConflictException>(
            () => service.SetLockoutAsync(
                targetId,
                new SetManagementUserLockoutCommand(Locked: true),
                RequestContext("provider-operator")));
        Assert.Equal("user_lock_failed", failure.ReasonCode);

        var database = scope.ServiceProvider
            .GetRequiredService<AppDbContext>();
        database.ChangeTracker.Clear();
        var persisted = await database.Users.SingleAsync(
            user => user.Id == targetId);
        Assert.Null(persisted.LockoutEnd);
        Assert.Equal(originalSecurityStamp, persisted.SecurityStamp);
        Assert.Contains(
            await database.ManagementAuditEvents
                .Where(entry => entry.ResourceId == targetId)
                .ToArrayAsync(),
            entry =>
                entry.Capability == ManagementCapabilities.UsersDisable
                && entry.OperationOutcome == "failed"
                && entry.ReasonCode == "user_lock_failed");
    }

    [Fact]
    public async Task Operator_cannot_lock_own_account()
    {
        using var factory = new ManagementTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();

        string targetId;
        await using (var setup = factory.Services.CreateAsyncScope())
        {
            var userManager = setup.ServiceProvider
                .GetRequiredService<UserManager<ApplicationUser>>();
            var target = await TestDataSeeder.CreateUserAsync(
                userManager,
                $"self-lockout-{Guid.NewGuid():N}",
                "Original!Passw0rd#12");
            targetId = target.Id;
        }

        await using var scope = factory.Services.CreateAsyncScope();
        var service = scope.ServiceProvider
            .GetRequiredService<IUserManagementService>();
        var denied = await Assert.ThrowsAsync<ManagementAccessException>(
            () => service.SetLockoutAsync(
                targetId,
                new SetManagementUserLockoutCommand(Locked: true),
                RequestContextForSubject(targetId)));

        Assert.Equal(
            "user_self_lockout_not_allowed",
            denied.Decision.ReasonCode);
    }

    [Fact]
    public async Task Delete_revokes_sessions_removes_identity_data_and_audits()
    {
        using var factory = new ManagementTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();

        string targetId;
        var authorizationId = Guid.NewGuid().ToString("N");
        var tokenId = Guid.NewGuid().ToString("N");
        await using (var setup = factory.Services.CreateAsyncScope())
        {
            var userManager = setup.ServiceProvider
                .GetRequiredService<UserManager<ApplicationUser>>();
            var target = await TestDataSeeder.CreateUserAsync(
                userManager,
                $"delete-{Guid.NewGuid():N}",
                "Original!Passw0rd#14");
            targetId = target.Id;
            Assert.True((await userManager.AddClaimAsync(
                target,
                new Claim("department", "identity-tests"))).Succeeded);

            var setupDatabase = setup.ServiceProvider
                .GetRequiredService<AppDbContext>();
            setupDatabase.Set<OpenIddictEntityFrameworkCoreAuthorization>().Add(
                new OpenIddictEntityFrameworkCoreAuthorization
                {
                    Id = authorizationId,
                    ConcurrencyToken = Guid.NewGuid().ToString("N"),
                    CreationDate = DateTime.UtcNow,
                    Status = OpenIddictConstants.Statuses.Valid,
                    Subject = targetId,
                    Type = OpenIddictConstants.AuthorizationTypes.Permanent
                });
            setupDatabase.Set<OpenIddictEntityFrameworkCoreToken>().Add(
                new OpenIddictEntityFrameworkCoreToken
                {
                    Id = tokenId,
                    ConcurrencyToken = Guid.NewGuid().ToString("N"),
                    CreationDate = DateTime.UtcNow,
                    Status = OpenIddictConstants.Statuses.Valid,
                    Subject = targetId,
                    Type = OpenIddictConstants.TokenTypeHints.RefreshToken
                });
            await setupDatabase.SaveChangesAsync();
        }

        var client = factory.CreateClient();
        using var response = await client.DeleteAsync(
            $"/api/users/{targetId}");
        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);

        await using var scope = factory.Services.CreateAsyncScope();
        var database = scope.ServiceProvider
            .GetRequiredService<AppDbContext>();
        Assert.False(await database.Users.AnyAsync(user => user.Id == targetId));
        Assert.False(await database.UserClaims.AnyAsync(
            claim => claim.UserId == targetId));

        var authorization = await database
            .Set<OpenIddictEntityFrameworkCoreAuthorization>()
            .SingleAsync(entry => entry.Id == authorizationId);
        var token = await database
            .Set<OpenIddictEntityFrameworkCoreToken>()
            .SingleAsync(entry => entry.Id == tokenId);
        Assert.Equal(
            OpenIddictConstants.Statuses.Revoked,
            authorization.Status);
        Assert.Equal(OpenIddictConstants.Statuses.Revoked, token.Status);
        Assert.Contains(
            await database.ManagementAuditEvents
                .Where(entry => entry.ResourceId == targetId)
                .ToArrayAsync(),
            entry =>
                entry.Capability == ManagementCapabilities.UsersDelete
                && entry.OperationOutcome == "succeeded"
                && entry.ReasonCode == "user_deleted");
    }

    [Fact]
    public async Task Operator_cannot_delete_own_account()
    {
        using var factory = new ManagementTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();

        string targetId;
        await using (var setup = factory.Services.CreateAsyncScope())
        {
            var userManager = setup.ServiceProvider
                .GetRequiredService<UserManager<ApplicationUser>>();
            var target = await TestDataSeeder.CreateUserAsync(
                userManager,
                $"self-delete-{Guid.NewGuid():N}",
                "Original!Passw0rd#15");
            targetId = target.Id;
        }

        await using var scope = factory.Services.CreateAsyncScope();
        var service = scope.ServiceProvider
            .GetRequiredService<IUserManagementService>();
        var denied = await Assert.ThrowsAsync<ManagementAccessException>(
            () => service.DeleteAsync(
                targetId,
                RequestContextForSubject(targetId)));

        Assert.Equal(
            "user_self_delete_not_allowed",
            denied.Decision.ReasonCode);
        Assert.True(await scope.ServiceProvider
            .GetRequiredService<AppDbContext>()
            .Users.AnyAsync(user => user.Id == targetId));
    }

    [Fact]
    public async Task Failed_session_revocation_rolls_back_user_deletion()
    {
        using var factory = new ManagementTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        using var failingFactory = factory.WithWebHostBuilder(builder =>
            builder.ConfigureServices(services =>
            {
                services.RemoveAll<IIdentityUserSessionRevoker>();
                services.AddSingleton<
                    IIdentityUserSessionRevoker,
                    ThrowingManagementUserSessionRevoker>();
            }));

        string targetId;
        await using (var setup = failingFactory.Services.CreateAsyncScope())
        {
            var userManager = setup.ServiceProvider
                .GetRequiredService<UserManager<ApplicationUser>>();
            targetId = (await TestDataSeeder.CreateUserAsync(
                userManager,
                $"delete-rollback-{Guid.NewGuid():N}",
                "Original!Passw0rd#16")).Id;
        }

        await using var scope = failingFactory.Services.CreateAsyncScope();
        var service = scope.ServiceProvider
            .GetRequiredService<IUserManagementService>();
        var failure = await Assert.ThrowsAsync<ManagementConflictException>(
            () => service.DeleteAsync(
                targetId,
                RequestContext("provider-operator")));
        Assert.Equal("user_delete_failed", failure.ReasonCode);

        var database = scope.ServiceProvider
            .GetRequiredService<AppDbContext>();
        Assert.True(await database.Users.AnyAsync(
            user => user.Id == targetId));
        Assert.Contains(
            await database.ManagementAuditEvents
                .Where(entry => entry.ResourceId == targetId)
                .ToArrayAsync(),
            entry =>
                entry.Capability == ManagementCapabilities.UsersDelete
                && entry.OperationOutcome == "failed"
                && entry.ReasonCode == "user_delete_failed");
    }
}
