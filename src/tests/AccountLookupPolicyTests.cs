using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.STS;
using Sufficit.Identity.Tests.Infrastructure;
using Xunit;

namespace Sufficit.Identity.Tests;

public sealed class AccountLookupPolicyTests
{
    [Fact]
    public async Task Unique_email_resolves_the_single_account()
    {
        using var factory = SufficitIdentityTestFactory.CreateIsolated(
            new Dictionary<string, string?>());
        await ((IAsyncLifetime)factory).InitializeAsync();
        await using var scope = factory.Services.CreateAsyncScope();
        var users = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        var user = new ApplicationUser
        {
            UserName = "lookup-unique",
            Email = "lookup-unique@tests.local",
        };
        var created = await users.CreateAsync(user, "Str0ng!Passw0rd#1");
        Assert.True(created.Succeeded);

        var policy = scope.ServiceProvider.GetRequiredService<IAccountLookupPolicy>();
        var result = await policy.FindUniqueByEmailAsync("LOOKUP-UNIQUE@TESTS.LOCAL");

        Assert.Equal(user.Id, result?.Id);
    }

    [Fact]
    public async Task A_second_account_cannot_take_an_email_while_accounts_without_one_coexist()
    {
        // Plan F9: one account per normalized email, enforced by the validator
        // and, against races, by the unique EmailIndex. The lookup policy still
        // treats an ambiguous match as none, but it can no longer be created.
        using var factory = SufficitIdentityTestFactory.CreateIsolated(
            new Dictionary<string, string?>());
        await ((IAsyncLifetime)factory).InitializeAsync();
        await using var scope = factory.Services.CreateAsyncScope();
        var users = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();

        var first = await users.CreateAsync(new ApplicationUser
        {
            UserName = "lookup-duplicate-a",
            Email = "lookup-duplicate@tests.local",
        }, "Str0ng!Passw0rd#1");
        var second = await users.CreateAsync(new ApplicationUser
        {
            UserName = "lookup-duplicate-b",
            Email = "Lookup-Duplicate@Tests.Local",
        }, "Str0ng!Passw0rd#1");
        IdentityResult[] withoutEmail =
        [
            await users.CreateAsync(new ApplicationUser { UserName = "lookup-no-email-a" }),
            await users.CreateAsync(new ApplicationUser { UserName = "lookup-no-email-b" }),
        ];

        Assert.True(first.Succeeded);
        Assert.False(second.Succeeded);
        Assert.Contains(second.Errors, error => error.Code == "DuplicateEmail");
        Assert.All(withoutEmail, result => Assert.True(result.Succeeded));
        var policy = scope.ServiceProvider.GetRequiredService<IAccountLookupPolicy>();
        Assert.NotNull(await policy.FindUniqueByEmailAsync("lookup-duplicate@tests.local"));
    }
}
