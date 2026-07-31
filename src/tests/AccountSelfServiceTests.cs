using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.Core.Services;
using Sufficit.Identity.Tests.Infrastructure;
using Xunit;

namespace Sufficit.Identity.Tests;

[Collection(StsCollection.Name)]
public sealed class AccountSelfServiceTests(
    SufficitIdentityTestFactory factory)
{
    [Fact]
    public async Task Profile_and_personal_data_export_use_the_authenticated_account()
    {
        await using var scope = factory.Services.CreateAsyncScope();
        var userManager = scope.ServiceProvider
            .GetRequiredService<UserManager<ApplicationUser>>();
        var service = scope.ServiceProvider
            .GetRequiredService<IAccountSelfService>();
        var user = await CreateUserAsync(
            userManager,
            directive: "self-service:export");
        var principal = PrincipalFor(user);

        var profile = await service.GetProfileAsync(principal);
        var export = await service.ExportPersonalDataAsync(principal);

        Assert.NotNull(profile);
        Assert.Equal(user.Id, profile.UserId);
        Assert.Equal(user.UserName, profile.UserName);
        Assert.Equal(user.Email, profile.Email);
        Assert.True(profile.EmailConfirmed);

        Assert.NotNull(export);
        Assert.StartsWith(
            $"personal-data-{user.Id}-",
            export.FileName,
            StringComparison.Ordinal);
        Assert.Equal("application/json", export.ContentType);
        var json = Encoding.UTF8.GetString(export.Content);
        Assert.Contains(user.UserName!, json, StringComparison.Ordinal);
        Assert.Contains(
            "directive=self-service:export",
            json,
            StringComparison.Ordinal);
        Assert.DoesNotContain(
            nameof(ApplicationUser.PasswordHash),
            json,
            StringComparison.Ordinal);
        Assert.DoesNotContain(
            nameof(ApplicationUser.SecurityStamp),
            json,
            StringComparison.Ordinal);
        Assert.DoesNotContain(
            nameof(ApplicationUser.ConcurrencyStamp),
            json,
            StringComparison.Ordinal);
    }

    [Fact]
    public async Task Password_change_validates_confirmation_and_updates_identity()
    {
        await using var scope = factory.Services.CreateAsyncScope();
        var userManager = scope.ServiceProvider
            .GetRequiredService<UserManager<ApplicationUser>>();
        var service = scope.ServiceProvider
            .GetRequiredService<IAccountSelfService>();
        var user = await CreateUserAsync(userManager);
        var principal = PrincipalFor(user);
        const string replacementPassword = "Replacement!Passw0rd#84";

        var mismatch = await service.ChangePasswordAsync(
            principal,
            new AccountPasswordChange(
                TestDataSeeder.DefaultPassword,
                replacementPassword,
                "Different!Passw0rd#85"));

        Assert.False(mismatch.Succeeded);
        Assert.Contains(
            mismatch.Errors,
            error => error.Code == "password-confirmation-mismatch");
        Assert.True(await userManager.CheckPasswordAsync(
            user,
            TestDataSeeder.DefaultPassword));

        var changed = await service.ChangePasswordAsync(
            principal,
            new AccountPasswordChange(
                TestDataSeeder.DefaultPassword,
                replacementPassword,
                replacementPassword));

        Assert.True(changed.Succeeded);
        Assert.True(await userManager.CheckPasswordAsync(
            user,
            replacementPassword));
    }

    [Fact]
    public async Task Account_deletion_requires_both_confirmations_and_removes_the_user()
    {
        await using var scope = factory.Services.CreateAsyncScope();
        var userManager = scope.ServiceProvider
            .GetRequiredService<UserManager<ApplicationUser>>();
        var service = scope.ServiceProvider
            .GetRequiredService<IAccountSelfService>();
        var user = await CreateUserAsync(userManager);
        var principal = PrincipalFor(user);

        var wrongEmail = await service.DeleteAccountAsync(
            principal,
            new AccountDeletionRequest(
                "different@tests.local",
                TestDataSeeder.DefaultPassword));
        Assert.False(wrongEmail.Succeeded);
        Assert.Contains(
            wrongEmail.Errors,
            error => error.Code == "email-confirmation-mismatch");
        Assert.NotNull(await userManager.FindByIdAsync(user.Id));

        var wrongPassword = await service.DeleteAccountAsync(
            principal,
            new AccountDeletionRequest(
                user.Email!,
                "Incorrect!Passw0rd#99"));
        Assert.False(wrongPassword.Succeeded);
        Assert.Contains(
            wrongPassword.Errors,
            error => error.Code == "password-incorrect");
        Assert.NotNull(await userManager.FindByIdAsync(user.Id));

        var deleted = await service.DeleteAccountAsync(
            principal,
            new AccountDeletionRequest(
                user.Email!,
                TestDataSeeder.DefaultPassword));

        Assert.True(deleted.Succeeded);
        Assert.Null(await userManager.FindByIdAsync(user.Id));
    }

    [Fact]
    public async Task Unauthenticated_principals_fail_closed()
    {
        await using var scope = factory.Services.CreateAsyncScope();
        var service = scope.ServiceProvider
            .GetRequiredService<IAccountSelfService>();
        var anonymous = new ClaimsPrincipal(new ClaimsIdentity());

        Assert.Null(await service.GetProfileAsync(anonymous));
        Assert.Null(await service.ExportPersonalDataAsync(anonymous));

        var password = await service.ChangePasswordAsync(
            anonymous,
            new AccountPasswordChange("old", "new", "new"));
        var deletion = await service.DeleteAccountAsync(
            anonymous,
            new AccountDeletionRequest(
                "anonymous@tests.local",
                "password"));

        Assert.False(password.Succeeded);
        Assert.Contains(
            password.Errors,
            error => error.Code == "unauthenticated");
        Assert.False(deletion.Succeeded);
        Assert.Contains(
            deletion.Errors,
            error => error.Code == "unauthenticated");
    }

    private static async Task<ApplicationUser> CreateUserAsync(
        UserManager<ApplicationUser> userManager,
        string? directive = null) =>
        await TestDataSeeder.CreateUserAsync(
            userManager,
            $"self-service-{Guid.NewGuid():N}",
            TestDataSeeder.DefaultPassword,
            directive);

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
