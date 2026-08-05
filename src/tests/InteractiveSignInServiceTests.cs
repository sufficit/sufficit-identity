using System.Security.Cryptography;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.Application.Accounts;
using Sufficit.Identity.Tests.Infrastructure;
using Xunit;

namespace Sufficit.Identity.Tests;

[Collection(StsCollection.Name)]
public sealed class InteractiveSignInServiceTests(
    SufficitIdentityTestFactory factory)
{
    [Fact]
    public async Task Password_sign_in_projects_framework_outcomes()
    {
        await using var scope = factory.Services.CreateAsyncScope();
        var services = scope.ServiceProvider;
        var users = services.GetRequiredService<UserManager<ApplicationUser>>();
        var signIns = services.GetRequiredService<SignInManager<ApplicationUser>>();
        var service = services.GetRequiredService<IInteractiveSignInService>();

        var expectedProviders = (await signIns
                .GetExternalAuthenticationSchemesAsync())
            .Select(scheme => new InteractiveSignInProvider(
                scheme.Name,
                string.IsNullOrWhiteSpace(scheme.DisplayName)
                    ? scheme.Name
                    : scheme.DisplayName))
            .ToArray();
        Assert.Equal(
            expectedProviders,
            await service.GetExternalProvidersAsync());

        var valid = await CreateUserAsync(users, "valid");
        SetHttpContext(services);
        var invalidPassword = await service.PasswordSignInAsync(
            new PasswordSignInCommand(
                valid.UserName!,
                "Incorrect!Passw0rd#91",
                false));
        Assert.Equal(InteractiveSignInStatus.Failed, invalidPassword.Status);

        SetHttpContext(services);
        var succeeded = await service.PasswordSignInAsync(
            new PasswordSignInCommand(
                valid.UserName!,
                TestDataSeeder.DefaultPassword,
                false));
        Assert.Equal(InteractiveSignInStatus.Succeeded, succeeded.Status);

        var locked = await CreateUserAsync(users, "locked");
        Assert.True((await users.SetLockoutEndDateAsync(
            locked,
            DateTimeOffset.UtcNow.AddMinutes(10))).Succeeded);
        SetHttpContext(services);
        var lockedOut = await service.PasswordSignInAsync(
            new PasswordSignInCommand(
                locked.UserName!,
                TestDataSeeder.DefaultPassword,
                false));
        Assert.Equal(InteractiveSignInStatus.LockedOut, lockedOut.Status);

        var unconfirmed = await CreateUserAsync(users, "unconfirmed");
        unconfirmed.EmailConfirmed = false;
        Assert.True((await users.UpdateAsync(unconfirmed)).Succeeded);
        SetHttpContext(services);
        var notAllowed = await service.PasswordSignInAsync(
            new PasswordSignInCommand(
                unconfirmed.UserName!,
                TestDataSeeder.DefaultPassword,
                false));
        Assert.Equal(InteractiveSignInStatus.NotAllowed, notAllowed.Status);

        var secondFactor = await CreateUserAsync(users, "two-factor");
        Assert.True((await users.SetTwoFactorEnabledAsync(
            secondFactor,
            true)).Succeeded);
        SetHttpContext(services);
        var requiresTwoFactor = await service.PasswordSignInAsync(
            new PasswordSignInCommand(
                secondFactor.UserName!,
                TestDataSeeder.DefaultPassword,
                true));
        Assert.Equal(
            InteractiveSignInStatus.RequiresTwoFactor,
            requiresTwoFactor.Status);
    }

    [Fact]
    public async Task Authenticator_sign_in_uses_protected_pending_state()
    {
        await using var scope = factory.Services.CreateAsyncScope();
        var services = scope.ServiceProvider;
        var users = services.GetRequiredService<UserManager<ApplicationUser>>();
        var service = services.GetRequiredService<IInteractiveSignInService>();
        var user = await CreateUserAsync(users, "authenticator");
        Assert.True((await users.ResetAuthenticatorKeyAsync(user)).Succeeded);
        var key = await users.GetAuthenticatorKeyAsync(user);
        Assert.False(string.IsNullOrWhiteSpace(key));
        Assert.True((await users.SetTwoFactorEnabledAsync(user, true)).Succeeded);

        var passwordContext = SetHttpContext(services);
        var password = await service.PasswordSignInAsync(
            new PasswordSignInCommand(
                user.UserName!,
                TestDataSeeder.DefaultPassword,
                true));
        Assert.Equal(
            InteractiveSignInStatus.RequiresTwoFactor,
            password.Status);

        SetHttpContext(services, ExtractCookies(passwordContext));
        Assert.True(await service.HasPendingTwoFactorSignInAsync());
        var code = CurrentAuthenticatorCode(key!);
        var result = await service.AuthenticatorSignInAsync(
            new AuthenticatorSignInCommand(
                $"{code[..3]}-{code[3..]}",
                true,
                false));

        Assert.Equal(InteractiveSignInStatus.Succeeded, result.Status);
    }

    [Fact]
    public async Task Recovery_code_sign_in_consumes_the_code()
    {
        await using var scope = factory.Services.CreateAsyncScope();
        var services = scope.ServiceProvider;
        var users = services.GetRequiredService<UserManager<ApplicationUser>>();
        var service = services.GetRequiredService<IInteractiveSignInService>();
        var user = await CreateUserAsync(users, "recovery");
        Assert.True((await users.SetTwoFactorEnabledAsync(user, true)).Succeeded);
        var recoveryCodes = await users.GenerateNewTwoFactorRecoveryCodesAsync(
            user,
            1);
        var recoveryCode = Assert.Single(recoveryCodes!);

        var passwordContext = SetHttpContext(services);
        var password = await service.PasswordSignInAsync(
            new PasswordSignInCommand(
                user.UserName!,
                TestDataSeeder.DefaultPassword,
                false));
        Assert.Equal(
            InteractiveSignInStatus.RequiresTwoFactor,
            password.Status);

        SetHttpContext(services, ExtractCookies(passwordContext));
        Assert.True(await service.HasPendingTwoFactorSignInAsync());
        var result = await service.RecoveryCodeSignInAsync(
            $" {recoveryCode} ");

        Assert.Equal(InteractiveSignInStatus.Succeeded, result.Status);
        Assert.Equal(0, await users.CountRecoveryCodesAsync(user));
    }

    [Fact]
    public async Task Second_factor_operations_fail_without_pending_state()
    {
        await using var scope = factory.Services.CreateAsyncScope();
        var services = scope.ServiceProvider;
        var service = services.GetRequiredService<IInteractiveSignInService>();
        SetHttpContext(services);

        Assert.False(await service.HasPendingTwoFactorSignInAsync());
        var authenticator = await service.AuthenticatorSignInAsync(
            new AuthenticatorSignInCommand("123456", false, false));
        var recovery = await service.RecoveryCodeSignInAsync("unused-code");

        Assert.Equal(InteractiveSignInStatus.Failed, authenticator.Status);
        Assert.Equal(InteractiveSignInStatus.Failed, recovery.Status);
    }

    private static async Task<ApplicationUser> CreateUserAsync(
        UserManager<ApplicationUser> users,
        string prefix) =>
        await TestDataSeeder.CreateUserAsync(
            users,
            $"sign-in-{prefix}-{Guid.NewGuid():N}",
            TestDataSeeder.DefaultPassword);

    private static DefaultHttpContext SetHttpContext(
        IServiceProvider services,
        string? cookies = null)
    {
        var context = new DefaultHttpContext
        {
            RequestServices = services,
        };
        context.Request.Scheme = "https";
        context.Request.Host = new HostString("sts.tests.local");
        if (!string.IsNullOrWhiteSpace(cookies))
        {
            context.Request.Headers.Cookie = cookies;
        }

        services.GetRequiredService<IHttpContextAccessor>().HttpContext = context;
        return context;
    }

    private static string ExtractCookies(DefaultHttpContext context) =>
        string.Join(
            "; ",
            context.Response.Headers.SetCookie.Select(header =>
                header!.Split(';', 2, StringSplitOptions.None)[0]));

    private static string CurrentAuthenticatorCode(string sharedKey)
    {
        var key = DecodeBase32(sharedKey);
        var timeStep = DateTimeOffset.UtcNow.ToUnixTimeSeconds() / 30;
        Span<byte> counter = stackalloc byte[8];
        for (var index = counter.Length - 1; index >= 0; index--)
        {
            counter[index] = (byte)(timeStep & 0xff);
            timeStep >>= 8;
        }

        using var hmac = new HMACSHA1(key);
        var hash = hmac.ComputeHash(counter.ToArray());
        var offset = hash[^1] & 0x0f;
        var binaryCode = ((hash[offset] & 0x7f) << 24)
            | ((hash[offset + 1] & 0xff) << 16)
            | ((hash[offset + 2] & 0xff) << 8)
            | (hash[offset + 3] & 0xff);
        return (binaryCode % 1_000_000).ToString("D6");
    }

    private static byte[] DecodeBase32(string value)
    {
        const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        var output = new List<byte>((value.Length * 5 + 7) / 8);
        var buffer = 0;
        var bits = 0;
        foreach (var character in value.ToUpperInvariant())
        {
            var digit = alphabet.IndexOf(character, StringComparison.Ordinal);
            if (digit < 0)
            {
                continue;
            }

            buffer = (buffer << 5) | digit;
            bits += 5;
            if (bits < 8)
            {
                continue;
            }

            bits -= 8;
            output.Add((byte)(buffer >> bits));
            buffer &= (1 << bits) - 1;
        }

        return output.ToArray();
    }
}
