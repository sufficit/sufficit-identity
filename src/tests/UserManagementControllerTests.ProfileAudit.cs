using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Sufficit.Identity.Core.Services;
using Sufficit.Identity.Management.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.Management.Users;
using Sufficit.Identity.Tests.Infrastructure;
using Xunit;

namespace Sufficit.Identity.Tests;

public sealed partial class UserManagementControllerTests
{
    [Fact]
    public async Task Profile_audit_records_only_changed_fields_and_confirmation_side_effects()
    {
        using var factory = new ManagementTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        await using var scope = factory.Services.CreateAsyncScope();
        var manager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        var user = await TestDataSeeder.CreateUserAsync(manager,
            $"profile-audit-{Guid.NewGuid():N}", "Original!Passw0rd#20");
        var oldEmail = user.Email;
        Assert.True(user.EmailConfirmed);
        var service = scope.ServiceProvider.GetRequiredService<IUserManagementService>();
        var command = new UpdateManagementUserProfileCommand(user.UserName!, "new@example.test", null);
        await service.UpdateProfileAsync(user.Id, command, RequestContext("provider-operator"));

        var database = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var entry = await database.ManagementAuditEvents.SingleAsync(x =>
            x.ResourceId == user.Id && x.ReasonCode == "user_profile_updated");
        Assert.NotNull(entry.BeforeJson);
        Assert.NotNull(entry.AfterJson);
        using var before = JsonDocument.Parse(entry.BeforeJson);
        using var after = JsonDocument.Parse(entry.AfterJson);
        Assert.Equal(new[] { "email", "emailConfirmed" },
            before.RootElement.EnumerateObject().Select(x => x.Name).Order().ToArray());
        Assert.Equal(new[] { "email", "emailConfirmed" },
            after.RootElement.EnumerateObject().Select(x => x.Name).Order().ToArray());
        Assert.Equal(oldEmail, before.RootElement.GetProperty("email").GetString());
        Assert.Equal(command.Email, after.RootElement.GetProperty("email").GetString());
        Assert.True(before.RootElement.GetProperty("emailConfirmed").GetBoolean());
        Assert.False(after.RootElement.GetProperty("emailConfirmed").GetBoolean());
        Assert.Equal("operator-provider-operator", entry.OperatorSubject);

        await service.UpdateProfileAsync(user.Id, command, RequestContext("provider-operator"));
        var unchanged = await database.ManagementAuditEvents.SingleAsync(x =>
            x.ResourceId == user.Id && x.ReasonCode == "user_profile_unchanged");
        Assert.Null(unchanged.BeforeJson);
        Assert.Null(unchanged.AfterJson);
    }
    [Fact]
    public async Task Profile_audit_captures_username_and_phone_clear_without_credentials()
    {
        using var factory = new ManagementTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        await using var scope = factory.Services.CreateAsyncScope();
        var manager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        var user = await TestDataSeeder.CreateUserAsync(manager,
            $"profile-phone-{Guid.NewGuid():N}", "Original!Passw0rd#20");
        user.PhoneNumber = "+12025550123";
        user.PhoneNumberConfirmed = true;
        Assert.True((await manager.UpdateAsync(user)).Succeeded);
        var oldName = user.UserName;
        var service = scope.ServiceProvider.GetRequiredService<IUserManagementService>();
        await service.UpdateProfileAsync(user.Id,
            new UpdateManagementUserProfileCommand("renamed-user", user.Email!, null),
            RequestContext("provider-operator"));
        var database = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var entry = await database.ManagementAuditEvents.SingleAsync(x =>
            x.ResourceId == user.Id && x.ReasonCode == "user_profile_updated");
        using var before = JsonDocument.Parse(entry.BeforeJson!);
        using var after = JsonDocument.Parse(entry.AfterJson!);
        var keys = new[] { "phoneNumber", "phoneNumberConfirmed", "userName" };
        Assert.Equal(keys, before.RootElement.EnumerateObject().Select(x => x.Name).Order().ToArray());
        Assert.Equal(keys, after.RootElement.EnumerateObject().Select(x => x.Name).Order().ToArray());
        Assert.Equal(oldName, before.RootElement.GetProperty("userName").GetString());
        Assert.Equal("renamed-user", after.RootElement.GetProperty("userName").GetString());
        Assert.Equal("+12025550123", before.RootElement.GetProperty("phoneNumber").GetString());
        Assert.Equal(JsonValueKind.Null, after.RootElement.GetProperty("phoneNumber").ValueKind);
        Assert.True(before.RootElement.GetProperty("phoneNumberConfirmed").GetBoolean());
        Assert.False(after.RootElement.GetProperty("phoneNumberConfirmed").GetBoolean());
    }

    [Fact]
    public async Task Profile_audit_does_not_record_success_or_snapshots_when_transaction_rolls_back()
    {
        using var factory = new ManagementTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        using var failingFactory = factory.WithWebHostBuilder(builder => builder.ConfigureServices(services =>
        {
            services.RemoveAll<IIdentityUserSessionRevoker>();
            services.AddSingleton<IIdentityUserSessionRevoker, ThrowingManagementUserSessionRevoker>();
        }));
        await using var scope = failingFactory.Services.CreateAsyncScope();
        var manager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        var user = await TestDataSeeder.CreateUserAsync(manager,
            $"profile-rollback-{Guid.NewGuid():N}", "Original!Passw0rd#20");
        var oldEmail = user.Email;
        var oldStamp = user.SecurityStamp;
        var service = scope.ServiceProvider.GetRequiredService<IUserManagementService>();
        await Assert.ThrowsAsync<ManagementConflictException>(() => service.UpdateProfileAsync(user.Id,
            new UpdateManagementUserProfileCommand(user.UserName!, "rollback@example.test", null),
            RequestContext("provider-operator")));
        var database = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        database.ChangeTracker.Clear();
        var persisted = await database.Users.SingleAsync(x => x.Id == user.Id);
        Assert.Equal(oldEmail, persisted.Email);
        Assert.Equal(oldStamp, persisted.SecurityStamp);
        var entry = await database.ManagementAuditEvents.SingleAsync(x =>
            x.ResourceId == user.Id && x.Capability == ManagementCapabilities.UsersUpdate);
        Assert.Equal("failed", entry.OperationOutcome);
        Assert.Null(entry.BeforeJson);
        Assert.Null(entry.AfterJson);
    }

    [Fact]
    public async Task Profile_audit_omits_snapshots_for_rejected_username_change()
    {
        using var factory = new ManagementTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        await using var scope = factory.Services.CreateAsyncScope();
        var manager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        var user = await TestDataSeeder.CreateUserAsync(manager,
            $"profile-rejected-{Guid.NewGuid():N}", "Original!Passw0rd#20");
        var oldName = user.UserName;
        var oldEmail = user.Email;
        var service = scope.ServiceProvider.GetRequiredService<IUserManagementService>();
        await Assert.ThrowsAsync<ManagementConflictException>(() => service.UpdateProfileAsync(user.Id,
            new UpdateManagementUserProfileCommand(TestDataSeeder.DefaultUsername, "rejected@example.test", null),
            RequestContext("provider-operator")));
        var database = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        database.ChangeTracker.Clear();
        var persisted = await database.Users.SingleAsync(x => x.Id == user.Id);
        Assert.Equal(oldName, persisted.UserName);
        Assert.Equal(oldEmail, persisted.Email);
        var entry = await database.ManagementAuditEvents.SingleAsync(x =>
            x.ResourceId == user.Id && x.Capability == ManagementCapabilities.UsersUpdate);
        Assert.Equal("failed", entry.OperationOutcome);
        Assert.Null(entry.BeforeJson);
        Assert.Null(entry.AfterJson);
    }

}
