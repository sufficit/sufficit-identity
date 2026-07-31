using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.Core.Services;
using Sufficit.Identity.Tests.Infrastructure;
using Xunit;

namespace Sufficit.Identity.Tests;

[Collection(StsCollection.Name)]
public sealed class AccountExternalIdentityServiceTests(
    SufficitIdentityTestFactory factory)
{
    [Fact]
    public async Task Overview_separates_linked_and_available_providers()
    {
        await using var scope = factory.Services.CreateAsyncScope();
        var services = scope.ServiceProvider;
        var users = services.GetRequiredService<UserManager<ApplicationUser>>();
        var service = services
            .GetRequiredService<IAccountExternalIdentityService>();
        var user = await CreateUserAsync(users, hasPassword: true);
        var linkedProvider = await RegisterProviderAsync(
            services,
            "Linked Provider");
        var availableProvider = await RegisterProviderAsync(
            services,
            "Available Provider");
        var add = await users.AddLoginAsync(
            user,
            new UserLoginInfo(
                linkedProvider.Name,
                "linked-user-key",
                "Linked account"));
        Assert.True(add.Succeeded);

        var overview = await service.GetOverviewAsync(PrincipalFor(user));

        Assert.NotNull(overview);
        var linked = Assert.Single(overview.LinkedIdentities);
        Assert.Equal(linkedProvider.Name, linked.LoginProvider);
        Assert.Equal("Linked account", linked.DisplayName);
        Assert.True(linked.CanRemove);
        Assert.Null(linked.RemovalBlockedReason);
        Assert.Contains(
            overview.AvailableProviders,
            provider => provider.AuthenticationScheme
                == availableProvider.Name);
        Assert.DoesNotContain(
            overview.AvailableProviders,
            provider => provider.AuthenticationScheme
                == linkedProvider.Name);
    }

    [Fact]
    public async Task Last_sign_in_method_cannot_be_removed()
    {
        await using var scope = factory.Services.CreateAsyncScope();
        var services = scope.ServiceProvider;
        var users = services.GetRequiredService<UserManager<ApplicationUser>>();
        var service = services
            .GetRequiredService<IAccountExternalIdentityService>();
        var user = await CreateUserAsync(users, hasPassword: false);
        var provider = await RegisterProviderAsync(
            services,
            "Only Provider");
        var add = await users.AddLoginAsync(
            user,
            new UserLoginInfo(provider.Name, "only-key", provider.DisplayName));
        Assert.True(add.Succeeded);

        var overview = await service.GetOverviewAsync(PrincipalFor(user));
        var linked = Assert.Single(overview!.LinkedIdentities);
        var removal = await service.RemoveAsync(
            PrincipalFor(user),
            provider.Name,
            "only-key");

        Assert.False(linked.CanRemove);
        Assert.NotNull(linked.RemovalBlockedReason);
        Assert.False(removal.Succeeded);
        Assert.Contains(
            removal.Errors,
            error => error.Code == "last-sign-in-method");
        Assert.Single(await users.GetLoginsAsync(user));
    }

    [Fact]
    public async Task Link_and_remove_enforce_account_ownership()
    {
        await using var scope = factory.Services.CreateAsyncScope();
        var services = scope.ServiceProvider;
        var users = services.GetRequiredService<UserManager<ApplicationUser>>();
        var service = services
            .GetRequiredService<IAccountExternalIdentityService>();
        var owner = await CreateUserAsync(users, hasPassword: true);
        var other = await CreateUserAsync(users, hasPassword: true);
        var provider = await RegisterProviderAsync(
            services,
            "Ownership Provider");
        var addOther = await users.AddLoginAsync(
            other,
            new UserLoginInfo(
                provider.Name,
                "foreign-key",
                provider.DisplayName));
        Assert.True(addOther.Succeeded);

        var foreignRemoval = await service.RemoveAsync(
            PrincipalFor(owner),
            provider.Name,
            "foreign-key");
        var foreignLink = await service.LinkAsync(
            PrincipalFor(owner),
            new AccountExternalIdentityLink(
                provider.Name,
                "foreign-key",
                provider.DisplayName));
        var ownLink = await service.LinkAsync(
            PrincipalFor(owner),
            new AccountExternalIdentityLink(
                provider.Name,
                "owner-key",
                provider.DisplayName));
        var ownRemoval = await service.RemoveAsync(
            PrincipalFor(owner),
            provider.Name,
            "owner-key");

        Assert.False(foreignRemoval.Succeeded);
        Assert.Contains(
            foreignRemoval.Errors,
            error => error.Code == "external-identity-not-found");
        Assert.False(foreignLink.Succeeded);
        Assert.Contains(
            foreignLink.Errors,
            error => error.Code == "external-identity-in-use");
        Assert.True(ownLink.Succeeded);
        Assert.True(ownRemoval.Succeeded);
        Assert.NotNull(await users.FindByLoginAsync(
            provider.Name,
            "foreign-key"));
        Assert.Null(await users.FindByLoginAsync(
            provider.Name,
            "owner-key"));
    }

    [Fact]
    public async Task Unauthenticated_principals_fail_closed()
    {
        await using var scope = factory.Services.CreateAsyncScope();
        var service = scope.ServiceProvider
            .GetRequiredService<IAccountExternalIdentityService>();
        var anonymous = new ClaimsPrincipal(new ClaimsIdentity());

        Assert.Null(await service.GetOverviewAsync(anonymous));
        var link = await service.LinkAsync(
            anonymous,
            new AccountExternalIdentityLink(
                "provider",
                "key",
                "Provider"));
        var removal = await service.RemoveAsync(
            anonymous,
            "provider",
            "key");

        Assert.All(
            new[] { link, removal },
            result =>
            {
                Assert.False(result.Succeeded);
                Assert.Contains(
                    result.Errors,
                    error => error.Code == "unauthenticated");
            });
    }

    private static async Task<ApplicationUser> CreateUserAsync(
        UserManager<ApplicationUser> users,
        bool hasPassword)
    {
        var name = $"external-identity-{Guid.NewGuid():N}";
        if (hasPassword)
        {
            return await TestDataSeeder.CreateUserAsync(
                users,
                name,
                TestDataSeeder.DefaultPassword);
        }

        var user = new ApplicationUser
        {
            UserName = name,
            Email = $"{name}@tests.local",
            EmailConfirmed = true,
        };
        var result = await users.CreateAsync(user);
        Assert.True(
            result.Succeeded,
            string.Join(", ", result.Errors.Select(error => error.Description)));
        return user;
    }

    private static async Task<AuthenticationScheme> RegisterProviderAsync(
        IServiceProvider services,
        string displayName)
    {
        var name = $"Test-{Guid.NewGuid():N}";
        var scheme = new AuthenticationScheme(
            name,
            displayName,
            typeof(CookieAuthenticationHandler));
        var provider = services.GetRequiredService<IAuthenticationSchemeProvider>();
        provider.AddScheme(scheme);
        await Task.CompletedTask;
        return scheme;
    }

    private static ClaimsPrincipal PrincipalFor(ApplicationUser user) =>
        new(
            new ClaimsIdentity(
                [
                    new Claim(ClaimTypes.NameIdentifier, user.Id),
                    new Claim(ClaimTypes.Name, user.UserName!),
                ],
                IdentityConstants.ApplicationScheme,
                ClaimTypes.Name,
                ClaimTypes.Role));
}
