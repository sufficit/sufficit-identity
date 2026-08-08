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
    public async Task Duplicate_normalized_email_is_rejected_as_ambiguous()
    {
        using var factory = SufficitIdentityTestFactory.CreateIsolated(
            new Dictionary<string, string?>());
        await ((IAsyncLifetime)factory).InitializeAsync();
        await using var scope = factory.Services.CreateAsyncScope();
        var users = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        foreach (var name in new[] { "lookup-duplicate-a", "lookup-duplicate-b" })
        {
            var created = await users.CreateAsync(new ApplicationUser
            {
                UserName = name,
                Email = "lookup-duplicate@tests.local",
            }, "Str0ng!Passw0rd#1");
            Assert.True(created.Succeeded);
        }

        var policy = scope.ServiceProvider.GetRequiredService<IAccountLookupPolicy>();
        var result = await policy.FindUniqueByEmailAsync("lookup-duplicate@tests.local");

        Assert.Null(result);
    }
}
