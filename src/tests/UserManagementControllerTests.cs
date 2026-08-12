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

public sealed class UserManagementControllerTests
{
    [Fact]
    public async Task Global_list_and_detail_are_paged_redacted_and_audited()
    {
        using var factory = new ManagementTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        var client = factory.CreateClient();

        using var listed = await client.GetAsync(
            "/api/users?search=alice&page=1&pageSize=10");
        var page = await listed.Content.ReadFromJsonAsync<ManagementUserPage>();

        Assert.Equal(HttpStatusCode.OK, listed.StatusCode);
        Assert.NotNull(page);
        var summary = Assert.Single(page.Items);
        Assert.Equal(TestDataSeeder.DefaultUsername, summary.UserName);
        Assert.NotEqual(default, summary.CreatedAtUtc);

        using var detailResponse = await client.GetAsync(
            $"/api/users/{summary.Id}");
        var detailJson = await detailResponse.Content.ReadAsStringAsync();
        var detail = await detailResponse.Content
            .ReadFromJsonAsync<ManagementUserDetail>();

        Assert.Equal(HttpStatusCode.OK, detailResponse.StatusCode);
        Assert.NotNull(detail);
        Assert.DoesNotContain(
            "passwordHash",
            detailJson,
            StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(
            "securityStamp",
            detailJson,
            StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(
            "concurrencyStamp",
            detailJson,
            StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(
            "\"roles\"",
            detailJson,
            StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(
            "contextIds",
            detailJson,
            StringComparison.OrdinalIgnoreCase);

        await using var scope = factory.Services.CreateAsyncScope();
        var database = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var events = await database.ManagementAuditEvents
            .Where(entry =>
                entry.Capability == ManagementCapabilities.UsersRead
                && entry.ResourceId == summary.Id)
            .ToArrayAsync();
        Assert.Contains(events, entry => entry.ReasonCode == "user_read");
    }

    [Fact]
    public async Task Registration_dashboard_filters_sorts_and_marks_daily_spikes()
    {
        using var factory = new ManagementTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        var spikeDay = DateTime.UtcNow.Date.AddDays(-3);

        await using (var setup = factory.Services.CreateAsyncScope())
        {
            var userManager = setup.ServiceProvider
                .GetRequiredService<UserManager<ApplicationUser>>();
            var database = setup.ServiceProvider.GetRequiredService<AppDbContext>();
            for (var index = 0; index < 4; index++)
            {
                var user = await TestDataSeeder.CreateUserAsync(
                    userManager,
                    $"spike-{index}-{Guid.NewGuid():N}",
                    "Valid!Passw0rd#42");
                user.CreatedAtUtc = spikeDay.AddHours(index);
                database.Update(user);
            }
            await database.SaveChangesAsync();
        }

        var client = factory.CreateClient();
        var day = DateOnly.FromDateTime(spikeDay).ToString("yyyy-MM-dd");
        using var response = await client.GetAsync(
            $"/api/users?registeredOn={day}&sort=CreatedOldest&analyticsDays=14");
        var page = await response.Content.ReadFromJsonAsync<ManagementUserPage>();

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.NotNull(page);
        Assert.Equal(4, page.TotalCount);
        Assert.Equal(4, page.Items.Count);
        Assert.Equal(
            page.Items.OrderBy(user => user.CreatedAtUtc).Select(user => user.Id),
            page.Items.Select(user => user.Id));
        Assert.NotNull(page.Analytics);
        var spike = Assert.Single(page.Analytics.Days, item =>
            item.Date == DateOnly.FromDateTime(spikeDay));
        Assert.Equal(4, spike.Count);
        Assert.True(spike.IsAnomaly);
        Assert.Equal(3, page.Analytics.AnomalyThreshold);
    }

    [Fact]
    public async Task Stale_unverified_review_excludes_recent_confirmed_and_external_accounts()
    {
        using var factory = new ManagementTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        var oldDate = DateTime.UtcNow.AddDays(-20);

        await using (var setup = factory.Services.CreateAsyncScope())
        {
            var userManager = setup.ServiceProvider
                .GetRequiredService<UserManager<ApplicationUser>>();
            var database = setup.ServiceProvider.GetRequiredService<AppDbContext>();

            var matching = await TestDataSeeder.CreateUserAsync(
                userManager, $"stale-match-{Guid.NewGuid():N}", "Valid!Passw0rd#42");
            var external = await TestDataSeeder.CreateUserAsync(
                userManager, $"stale-external-{Guid.NewGuid():N}", "Valid!Passw0rd#42");
            var confirmed = await TestDataSeeder.CreateUserAsync(
                userManager, $"stale-confirmed-{Guid.NewGuid():N}", "Valid!Passw0rd#42");
            var recent = await TestDataSeeder.CreateUserAsync(
                userManager, $"recent-unverified-{Guid.NewGuid():N}", "Valid!Passw0rd#42");

            matching.CreatedAtUtc = oldDate;
            matching.EmailConfirmed = false;
            external.CreatedAtUtc = oldDate;
            external.EmailConfirmed = false;
            confirmed.CreatedAtUtc = oldDate;
            confirmed.EmailConfirmed = true;
            recent.CreatedAtUtc = DateTime.UtcNow.AddDays(-5);
            recent.EmailConfirmed = false;
            database.UpdateRange(matching, external, confirmed, recent);
            await database.SaveChangesAsync();

            var login = await userManager.AddLoginAsync(external,
                new UserLoginInfo("Google", "stale-external-key", "Google"));
            Assert.True(login.Succeeded);
        }

        var client = factory.CreateClient();
        using var response = await client.GetAsync(
            "/api/users?review=StaleUnverifiedWithoutExternal&sort=CreatedOldest");
        var page = await response.Content.ReadFromJsonAsync<ManagementUserPage>();

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.NotNull(page);
        var match = Assert.Single(page.Items);
        Assert.StartsWith("stale-match-", match.UserName, StringComparison.Ordinal);
        Assert.False(match.EmailConfirmed);
        Assert.False(match.HasExternalLogin);
        Assert.True(match.CreatedAtUtc < DateTime.UtcNow.AddDays(-15));
        Assert.Equal(1, page.Analytics?.StaleUnverifiedWithoutExternalTotal);
    }

    [Fact]
    public async Task Create_reset_and_lockout_manage_only_the_identity_account()
    {
        using var factory = new ManagementTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        var client = factory.CreateClient();
        var userName = $"created-{Guid.NewGuid():N}";
        const string initialPassword = "Initial!Passw0rd#42";
        const string replacementPassword = "Replacement!Passw0rd#84";

        using var createdResponse = await client.PostAsJsonAsync(
            "/api/users",
            new CreateManagementUserCommand(
                userName,
                $"{userName}@tests.local",
                initialPassword));
        var createdJson = await createdResponse.Content.ReadAsStringAsync();
        var created = await createdResponse.Content
            .ReadFromJsonAsync<ManagementUserDetail>();

        Assert.Equal(HttpStatusCode.OK, createdResponse.StatusCode);
        Assert.NotNull(created);
        Assert.True(created.Actions.CanResetPassword);
        Assert.True(created.Actions.CanSetLockout);
        Assert.True(created.Actions.CanDelete);
        Assert.DoesNotContain(
            initialPassword,
            createdJson,
            StringComparison.Ordinal);
        Assert.DoesNotContain(
            "\"roles\"",
            createdJson,
            StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(
            "context",
            createdJson,
            StringComparison.OrdinalIgnoreCase);

        using var resetResponse = await client.PostAsJsonAsync(
            $"/api/users/{created.Id}/reset-password",
            new ResetManagementUserPasswordCommand(replacementPassword));
        var resetJson = await resetResponse.Content.ReadAsStringAsync();
        Assert.Equal(HttpStatusCode.OK, resetResponse.StatusCode);
        Assert.DoesNotContain(
            replacementPassword,
            resetJson,
            StringComparison.Ordinal);

        using var lockedResponse = await client.PostAsJsonAsync(
            $"/api/users/{created.Id}/lockout",
            new SetManagementUserLockoutCommand(Locked: true));
        var locked = await lockedResponse.Content
            .ReadFromJsonAsync<ManagementUserDetail>();
        Assert.Equal(HttpStatusCode.OK, lockedResponse.StatusCode);
        Assert.NotNull(locked);
        Assert.True(locked.LockoutEnd > DateTimeOffset.UtcNow);

        using var unlockedResponse = await client.PostAsJsonAsync(
            $"/api/users/{created.Id}/lockout",
            new SetManagementUserLockoutCommand(Locked: false));
        var unlocked = await unlockedResponse.Content
            .ReadFromJsonAsync<ManagementUserDetail>();
        Assert.Equal(HttpStatusCode.OK, unlockedResponse.StatusCode);
        Assert.NotNull(unlocked);
        Assert.Null(unlocked.LockoutEnd);

        await using var scope = factory.Services.CreateAsyncScope();
        var userManager = scope.ServiceProvider
            .GetRequiredService<UserManager<ApplicationUser>>();
        var persisted = await userManager.FindByIdAsync(created.Id);
        Assert.NotNull(persisted);
        Assert.True(await userManager.CheckPasswordAsync(
            persisted,
            replacementPassword));
        Assert.Empty(await userManager.GetRolesAsync(persisted));
        Assert.Empty(await userManager.GetClaimsAsync(persisted));

        var database = scope.ServiceProvider
            .GetRequiredService<AppDbContext>();
        var audit = await database.ManagementAuditEvents
            .Where(entry => entry.ResourceId == created.Id)
            .ToArrayAsync();
        Assert.Contains(
            audit,
            entry =>
                entry.Capability == ManagementCapabilities.UsersCreate
                && entry.ReasonCode == "user_created");
        Assert.Contains(
            audit,
            entry =>
                entry.Capability
                    == ManagementCapabilities.UsersReset
                && entry.ReasonCode == "user_password_reset");
        Assert.Contains(
            audit,
            entry =>
                entry.Capability == ManagementCapabilities.UsersDisable
                && entry.ReasonCode == "user_locked");
        Assert.Contains(
            audit,
            entry =>
                entry.Capability == ManagementCapabilities.UsersDisable
                && entry.ReasonCode == "user_unlocked");
    }

    [Fact]
    public async Task Invalid_initial_password_is_rejected_without_persisting_user()
    {
        using var factory = new ManagementTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        var client = factory.CreateClient();
        var userName = $"invalid-{Guid.NewGuid():N}";

        using var response = await client.PostAsJsonAsync(
            "/api/users",
            new CreateManagementUserCommand(
                userName,
                $"{userName}@tests.local",
                "weak"));
        var problem = await response.Content
            .ReadFromJsonAsync<Dictionary<string, object>>();

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.NotNull(problem);
        Assert.Contains(
            "user_password_invalid",
            problem["reasonCode"].ToString(),
            StringComparison.Ordinal);
        Assert.Contains(
            "initialPassword",
            problem["field"].ToString(),
            StringComparison.Ordinal);

        await using var scope = factory.Services.CreateAsyncScope();
        var userManager = scope.ServiceProvider
            .GetRequiredService<UserManager<ApplicationUser>>();
        Assert.Null(await userManager.FindByNameAsync(userName));
        var database = scope.ServiceProvider
            .GetRequiredService<AppDbContext>();
        Assert.Contains(
            await database.ManagementAuditEvents.ToArrayAsync(),
            entry =>
                entry.Capability == ManagementCapabilities.UsersCreate
                && entry.OperationOutcome == "failed"
                && entry.ReasonCode == "user_password_invalid");
    }

    [Fact]
    public async Task Profile_update_changes_identity_fields_and_security_stamp()
    {
        using var factory = new ManagementTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();

        string targetId;
        string? originalSecurityStamp;
        await using (var setup = factory.Services.CreateAsyncScope())
        {
            var userManager = setup.ServiceProvider
                .GetRequiredService<UserManager<ApplicationUser>>();
            var target = await TestDataSeeder.CreateUserAsync(
                userManager,
                $"profile-{Guid.NewGuid():N}",
                "Original!Passw0rd#20");
            targetId = target.Id;
            originalSecurityStamp = target.SecurityStamp;
        }

        await using var scope = factory.Services.CreateAsyncScope();
        var service = scope.ServiceProvider
            .GetRequiredService<IUserManagementService>();
        var command = new UpdateManagementUserProfileCommand(
            $"profile-updated-{Guid.NewGuid():N}",
            $"profile-updated-{Guid.NewGuid():N}@tests.local",
            "+5511999999999");

        var updated = await service.UpdateProfileAsync(
            targetId,
            command,
            RequestContext("provider-operator"));

        Assert.Equal(command.UserName, updated.UserName);
        Assert.Equal(command.Email, updated.Email);
        Assert.Equal(command.PhoneNumber, updated.PhoneNumber);
        Assert.False(updated.EmailConfirmed);
        Assert.False(updated.PhoneNumberConfirmed);

        var database = scope.ServiceProvider
            .GetRequiredService<AppDbContext>();
        database.ChangeTracker.Clear();
        var persisted = await database.Users.SingleAsync(
            user => user.Id == targetId);
        Assert.NotEqual(originalSecurityStamp, persisted.SecurityStamp);
        Assert.Contains(
            await database.ManagementAuditEvents
                .Where(entry => entry.ResourceId == targetId)
                .ToArrayAsync(),
            entry =>
                entry.Capability == ManagementCapabilities.UsersUpdate
                && entry.ReasonCode == "user_profile_updated");
    }

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

    private static ManagementRequestContext RequestContext(string role) =>
        RequestContextForSubject($"operator-{role}", role);

    private static ManagementRequestContext RequestContextForSubject(
        string subject,
        string role = "provider-operator") =>
        new(
            new ClaimsPrincipal(
                new ClaimsIdentity(
                    [
                        new Claim(ClaimTypes.NameIdentifier, subject),
                        new Claim(ClaimTypes.Role, role)
                    ],
                    "test",
                    ClaimTypes.Name,
                    ClaimTypes.Role)),
            $"test-{Guid.NewGuid():N}");

    private sealed class ThrowingManagementUserSessionRevoker
        : IIdentityUserSessionRevoker
    {
        public Task<long> RevokeTokensAsync(
            string subject,
            CancellationToken cancellationToken = default) =>
            throw new InvalidOperationException(
                "Session revocation failed for test.");

        public Task<IdentityUserSessionRevocation> RevokeAsync(
            string subject,
            CancellationToken cancellationToken = default) =>
            throw new InvalidOperationException(
                "Session revocation failed for test.");
    }
}
