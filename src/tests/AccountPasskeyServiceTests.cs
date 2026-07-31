using System.Security.Claims;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.Core.Services;
using Sufficit.Identity.Tests.Infrastructure;
using Xunit;

namespace Sufficit.Identity.Tests;

[Collection(StsCollection.Name)]
public sealed class AccountPasskeyServiceTests(
    SufficitIdentityTestFactory factory)
{
    [Fact]
    public async Task Overview_is_account_scoped_and_exposes_runtime_limits()
    {
        await using var scope = factory.Services.CreateAsyncScope();
        var users = scope.ServiceProvider
            .GetRequiredService<UserManager<ApplicationUser>>();
        var service = scope.ServiceProvider
            .GetRequiredService<IAccountPasskeyService>();
        var user = await CreateUserAsync(users);

        var overview = await service.GetOverviewAsync(PrincipalFor(user));

        Assert.NotNull(overview);
        Assert.Empty(overview.Credentials);
        Assert.Equal(10, overview.MaximumCredentials);
        Assert.Equal(100, overview.MaximumNameLength);
        Assert.True(overview.CanRegister);
    }

    [Fact]
    public async Task Registration_validation_rejects_invalid_input_before_the_ceremony()
    {
        await using var scope = factory.Services.CreateAsyncScope();
        var users = scope.ServiceProvider
            .GetRequiredService<UserManager<ApplicationUser>>();
        var service = scope.ServiceProvider
            .GetRequiredService<IAccountPasskeyService>();
        var user = await CreateUserAsync(users);
        var principal = PrincipalFor(user);

        var missing = await service.RegisterAsync(
            principal,
            new AccountPasskeyRegistration(null, null));
        var longName = await service.RegisterAsync(
            principal,
            new AccountPasskeyRegistration("{}", new string('x', 101)));

        Assert.False(missing.Succeeded);
        Assert.Contains(
            missing.Errors,
            error => error.Code == "passkey-credential-required");
        Assert.False(longName.Succeeded);
        Assert.Contains(
            longName.Errors,
            error => error.Code == "passkey-name-too-long");
        Assert.Empty(await users.GetPasskeysAsync(user));
    }

    [Fact]
    public async Task Removal_is_scoped_to_the_authenticated_account()
    {
        await using var scope = factory.Services.CreateAsyncScope();
        var users = scope.ServiceProvider
            .GetRequiredService<UserManager<ApplicationUser>>();
        var service = scope.ServiceProvider
            .GetRequiredService<IAccountPasskeyService>();
        var user = await CreateUserAsync(users);

        var result = await service.RemoveAsync(
            PrincipalFor(user),
            "opaque-credential-owned-by-nobody");

        Assert.False(result.Succeeded);
        Assert.Contains(
            result.Errors,
            error => error.Code == "passkey-not-found");
        Assert.Empty(result.State!.Credentials);
    }

    [Fact]
    public async Task Unauthenticated_operations_fail_closed()
    {
        await using var scope = factory.Services.CreateAsyncScope();
        var account = scope.ServiceProvider
            .GetRequiredService<IAccountPasskeyService>();
        var authentication = scope.ServiceProvider
            .GetRequiredService<IPasskeyAuthenticationService>();
        var anonymous = new ClaimsPrincipal(new ClaimsIdentity());

        Assert.Null(await account.GetOverviewAsync(anonymous));
        var options = await account.CreateRegistrationOptionsAsync(anonymous);
        var registration = await account.RegisterAsync(
            anonymous,
            new AccountPasskeyRegistration("{}", null));
        var removal = await account.RemoveAsync(anonymous, "credential");
        var signIn = await authentication.SignInAsync(null);
        var longUsername = await authentication.CreateRequestOptionsAsync(
            new string('u', 257));

        Assert.All(
            new[] { options.Errors, registration.Errors, removal.Errors },
            errors => Assert.Contains(
                errors,
                error => error.Code == "unauthenticated"));
        Assert.Contains(
            signIn.Errors,
            error => error.Code == "passkey-credential-required");
        Assert.Contains(
            longUsername.Errors,
            error => error.Code == "username-too-long");
    }

    private static async Task<ApplicationUser> CreateUserAsync(
        UserManager<ApplicationUser> users) =>
        await TestDataSeeder.CreateUserAsync(
            users,
            $"passkey-{Guid.NewGuid():N}",
            TestDataSeeder.DefaultPassword);

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
