using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.Management;
using Sufficit.Identity.Management.Authorization;
using Sufficit.Identity.Management.Users;
using Sufficit.Identity.Tests.Infrastructure;
using Xunit;

namespace Sufficit.Identity.Tests;

public sealed partial class UserManagementControllerTests
{
    [Fact]
    public async Task Operator_removes_one_external_login_and_audits()
    {
        using var factory = new ManagementTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();

        string targetId;
        string stamp;
        await using (var setup = factory.Services.CreateAsyncScope())
        {
            var userManager = setup.ServiceProvider
                .GetRequiredService<UserManager<ApplicationUser>>();
            var target = await TestDataSeeder.CreateUserAsync(
                userManager,
                $"external-logins-{Guid.NewGuid():N}",
                "Original!Passw0rd#12");
            Assert.True((await userManager.AddLoginAsync(target,
                new UserLoginInfo("Google", "google-key", "Google"))).Succeeded);
            Assert.True((await userManager.AddLoginAsync(target,
                new UserLoginInfo("GitHub", "github-key", "GitHub"))).Succeeded);
            targetId = target.Id;
            stamp = (await userManager.FindByIdAsync(targetId))!.SecurityStamp!;
        }

        await using var scope = factory.Services.CreateAsyncScope();
        var service = scope.ServiceProvider
            .GetRequiredService<IUserManagementService>();
        var context = RequestContext("provider-operator");

        var before = await service.GetExternalLoginsAsync(targetId, context);
        Assert.Equal(["GitHub", "Google"], before.Logins.Select(login => login.LoginProvider));
        Assert.True(before.HasPassword);
        Assert.True(before.CanRemove);

        var after = await service.RemoveExternalLoginAsync(
            targetId,
            new RemoveManagementUserExternalLoginCommand("Google", "google-key"),
            context);

        var remaining = Assert.Single(after.Logins);
        Assert.Equal("GitHub", remaining.LoginProvider);
        var users = scope.ServiceProvider
            .GetRequiredService<UserManager<ApplicationUser>>();
        Assert.NotEqual(stamp, (await users.FindByIdAsync(targetId))!.SecurityStamp);

        var missing = await Assert.ThrowsAsync<ManagementNotFoundException>(
            () => service.RemoveExternalLoginAsync(
                targetId,
                new RemoveManagementUserExternalLoginCommand("Google", "google-key"),
                context));
        Assert.Equal("user_external_login_not_found", missing.ReasonCode);

        var database = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var audit = await database.ManagementAuditEvents
            .Where(entry => entry.ResourceId == targetId
                && entry.Capability == ManagementCapabilities.UsersReset)
            .Select(entry => entry.ReasonCode)
            .ToArrayAsync();
        Assert.Contains("user_external_login_removed", audit);
        Assert.Contains("user_external_login_not_found", audit);
    }
}
