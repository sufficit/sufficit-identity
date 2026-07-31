using System.Security.Claims;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using Sufficit.Identity.Core.Data;
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
        var missingRenameCredential = await service.RenameAsync(
            principal,
            new AccountPasskeyRename("", "workstation"));
        var longRename = await service.RenameAsync(
            principal,
            new AccountPasskeyRename("missing", new string('x', 101)));

        Assert.False(missing.Succeeded);
        Assert.Contains(
            missing.Errors,
            error => error.Code == "passkey-credential-required");
        Assert.False(longName.Succeeded);
        Assert.Contains(
            longName.Errors,
            error => error.Code == "passkey-name-too-long");
        Assert.Contains(
            missingRenameCredential.Errors,
            error => error.Code == "passkey-credential-required");
        Assert.Contains(
            longRename.Errors,
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
    public async Task Rename_updates_only_the_optional_friendly_name()
    {
        await using var scope = factory.Services.CreateAsyncScope();
        var users = scope.ServiceProvider
            .GetRequiredService<UserManager<ApplicationUser>>();
        var database = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var service = scope.ServiceProvider
            .GetRequiredService<IAccountPasskeyService>();
        var user = await CreateUserAsync(users);
        var credentialId = Guid.NewGuid().ToByteArray();
        var publicKey = new byte[] { 1, 2, 3, 4 };
        database.Set<IdentityUserPasskey<string>>().Add(
            new IdentityUserPasskey<string>
            {
                UserId = user.Id,
                CredentialId = credentialId,
                Data = new IdentityPasskeyData
                {
                    PublicKey = publicKey,
                    Name = "Original",
                    CreatedAt = DateTimeOffset.UtcNow,
                    Transports = ["internal"],
                    AttestationObject = [5, 6],
                    ClientDataJson = [7, 8],
                },
            });
        await database.SaveChangesAsync();
        var encodedCredentialId = WebEncoders.Base64UrlEncode(credentialId);

        var renamed = await service.RenameAsync(
            PrincipalFor(user),
            new AccountPasskeyRename(encodedCredentialId, "  Notebook pessoal  "));
        var stored = Assert.Single(await users.GetPasskeysAsync(user));

        Assert.True(renamed.Succeeded);
        Assert.Equal("Notebook pessoal", stored.Name);
        Assert.Equal(publicKey, stored.PublicKey);
        Assert.Equal(credentialId, stored.CredentialId);

        var cleared = await service.RenameAsync(
            PrincipalFor(user),
            new AccountPasskeyRename(encodedCredentialId, "  "));
        stored = Assert.Single(await users.GetPasskeysAsync(user));

        Assert.True(cleared.Succeeded);
        Assert.Null(stored.Name);
        Assert.Equal(publicKey, stored.PublicKey);
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
        var rename = await account.RenameAsync(
            anonymous,
            new AccountPasskeyRename("credential", "name"));
        var removal = await account.RemoveAsync(anonymous, "credential");
        var signIn = await authentication.SignInAsync(null);
        var longUsername = await authentication.CreateRequestOptionsAsync(
            new string('u', 257));

        Assert.All(
            new[] { options.Errors, registration.Errors, rename.Errors, removal.Errors },
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
