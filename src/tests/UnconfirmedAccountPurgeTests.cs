using System.Security.Claims;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.Management;
using Sufficit.Identity.Management.Users;
using Sufficit.Identity.Tests.Infrastructure;
using Xunit;

namespace Sufficit.Identity.Tests;

public sealed class UnconfirmedAccountPurgeTests
{
    [Fact]
    public async Task Only_an_abandoned_unconfirmed_account_holding_nothing_is_deleted_and_audited()
    {
        using var factory = new ManagementTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        var old = DateTime.UtcNow.AddDays(-200);
        string abandoned, recent, confirmed, withClaim, withoutEmail, withFailures;
        await using (var scope = factory.Services.CreateAsyncScope())
        {
            var users = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
            abandoned = await CreateAsync(users, "abandoned", emailConfirmed: false, old);
            recent = await CreateAsync(users, "recent", emailConfirmed: false, DateTime.UtcNow.AddDays(-10));
            confirmed = await CreateAsync(users, "confirmed", emailConfirmed: true, old);
            withClaim = await CreateAsync(users, "with-claim", emailConfirmed: false, old);
            await users.AddClaimAsync((await users.FindByIdAsync(withClaim))!, new Claim("entitlements", "aiuser:1"));
            withoutEmail = await CreateAsync(users, "system", emailConfirmed: false, old, email: null);
            withFailures = await CreateAsync(users, "tried", emailConfirmed: false, old);
            await users.AccessFailedAsync((await users.FindByIdAsync(withFailures))!);
        }

        var worker = new UnconfirmedAccountPurgeWorker(
            factory.Services.GetRequiredService<IServiceScopeFactory>(),
            Options.Create(new ManagementOptions { UnconfirmedAccountPurgeDays = 90 }),
            NullLogger<UnconfirmedAccountPurgeWorker>.Instance);

        Assert.Equal(1, await worker.PurgeAsync(default));
        Assert.Equal(0, await worker.PurgeAsync(default));

        await using var check = factory.Services.CreateAsyncScope();
        var database = check.ServiceProvider.GetRequiredService<AppDbContext>();
        var remaining = await database.Users.Select(user => user.Id).ToListAsync();
        Assert.DoesNotContain(abandoned, remaining);
        Assert.All(new[] { recent, confirmed, withClaim, withoutEmail, withFailures }, id => Assert.Contains(id, remaining));
        var audit = await database.ManagementAuditEvents.SingleAsync(item => item.ResourceId == abandoned);
        Assert.Equal(UnconfirmedAccountPurgeWorker.ReasonCode, audit.ReasonCode);
        Assert.DoesNotContain("@", audit.AfterJson);
    }

    [Fact]
    public async Task Nothing_is_deleted_while_the_purge_is_off()
    {
        using var factory = new ManagementTestFactory();
        await ((IAsyncLifetime)factory).InitializeAsync();
        await using (var scope = factory.Services.CreateAsyncScope())
            await CreateAsync(scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>(),
                "abandoned-off", emailConfirmed: false, DateTime.UtcNow.AddDays(-400));

        var worker = new UnconfirmedAccountPurgeWorker(
            factory.Services.GetRequiredService<IServiceScopeFactory>(),
            Options.Create(new ManagementOptions()),
            NullLogger<UnconfirmedAccountPurgeWorker>.Instance);

        Assert.Equal(0, await worker.PurgeAsync(default));
    }

    private static async Task<string> CreateAsync(UserManager<ApplicationUser> users, string name, bool emailConfirmed,
        DateTime createdAtUtc, string? email = "")
    {
        var user = new ApplicationUser
        {
            UserName = $"{name}-{Guid.NewGuid():N}",
            Email = email == "" ? $"{name}-{Guid.NewGuid():N}@tests.local" : email,
            EmailConfirmed = emailConfirmed,
            CreatedAtUtc = createdAtUtc,
        };
        Assert.True((await users.CreateAsync(user)).Succeeded);
        return user.Id;
    }
}
