using System.Security.Cryptography;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Sufficit.Identity.Core.Data;
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
                false));
        Assert.Equal(
            InteractiveSignInStatus.RequiresTwoFactor,
            password.Status);

        SetHttpContext(
            services,
            ExtractCookies(passwordContext));
        Assert.True(await service.HasPendingTwoFactorSignInAsync());
        var code = CurrentAuthenticatorCode(key!);
        var result = await service.AuthenticatorSignInAsync(
            new AuthenticatorSignInCommand(
                $"{code[..3]}-{code[3..]}",
                false,
                true));

        Assert.Equal(InteractiveSignInStatus.Succeeded, result.Status);

        var databaseFactory = services.GetRequiredService<IDbContextFactory<AppDbContext>>();
        await using var database = await databaseFactory.CreateDbContextAsync();
        var session = await database.OidcUserSessions
            .SingleAsync(session => session.Subject == user.Id);
        var protector = services.GetRequiredService<IDataProtectionProvider>()
            .CreateProtector("Sufficit.Identity.OidcUserSessionTicketStore.v1");
        var ticket = TicketSerializer.Default.Deserialize(
            protector.Unprotect(session.ProtectedTicket));
        Assert.NotNull(ticket);
        var methods = ticket!.Principal
            .FindAll("amr")
            .SelectMany(claim => claim.Value.Split(' ', StringSplitOptions.RemoveEmptyEntries))
            .ToHashSet(StringComparer.Ordinal);
        Assert.Contains("pwd", methods);
        Assert.Contains("otp", methods);
        Assert.Contains("mfa", methods);
        Assert.Equal("Loa2", ticket.Principal.FindFirst("aal")?.Value);
        Assert.Equal(
            "urn:sufficit:acr:loa2",
            ticket.Principal.FindFirst("acr")?.Value);
        Assert.True(ticket.Properties.IsPersistent);
    }

    [Fact]
    public async Task Remembered_mfa_device_projects_loa2_and_persists_the_session()
    {
        var username = $"sign-in-remembered-mfa-{Guid.NewGuid():N}";
        string userId;
        string rememberedDeviceCookie;
        await using (var rememberScope = factory.Services.CreateAsyncScope())
        {
            var services = rememberScope.ServiceProvider;
            var users = services.GetRequiredService<UserManager<ApplicationUser>>();
            var rememberedUser = await TestDataSeeder.CreateUserAsync(
                users,
                username,
                TestDataSeeder.DefaultPassword);
            userId = rememberedUser.Id;
            Assert.True((await users.SetTwoFactorEnabledAsync(
                rememberedUser,
                true)).Succeeded);

            var rememberContext = SetHttpContext(services);
            var rememberSignIns = services
                .GetRequiredService<SignInManager<ApplicationUser>>();
            await rememberSignIns.RememberTwoFactorClientAsync(rememberedUser);
            rememberedDeviceCookie = ExtractCookies(rememberContext);
        }
        Assert.False(string.IsNullOrWhiteSpace(rememberedDeviceCookie));

        await using var loginScope = factory.Services.CreateAsyncScope();
        var loginServices = loginScope.ServiceProvider;
        SetHttpContext(loginServices, rememberedDeviceCookie);
        var loginUsers = loginServices
            .GetRequiredService<UserManager<ApplicationUser>>();
        var user = await loginUsers.FindByIdAsync(userId)
            ?? throw new InvalidOperationException("Remembered MFA user not found.");
        var signIns = loginServices
            .GetRequiredService<SignInManager<ApplicationUser>>();
        Assert.True(await signIns.IsTwoFactorClientRememberedAsync(user));
        var service = loginServices
            .GetRequiredService<IInteractiveSignInService>();
        var result = await service.PasswordSignInAsync(
            new PasswordSignInCommand(
                username,
                TestDataSeeder.DefaultPassword,
                IsPersistent: false));

        Assert.Equal(InteractiveSignInStatus.Succeeded, result.Status);

        var databaseFactory = loginServices
            .GetRequiredService<IDbContextFactory<AppDbContext>>();
        await using var database = await databaseFactory.CreateDbContextAsync();
        var session = await database.OidcUserSessions
            .SingleAsync(session => session.Subject == userId);
        var protector = loginServices.GetRequiredService<IDataProtectionProvider>()
            .CreateProtector("Sufficit.Identity.OidcUserSessionTicketStore.v1");
        var ticket = TicketSerializer.Default.Deserialize(
            protector.Unprotect(session.ProtectedTicket));

        Assert.NotNull(ticket);
        var methods = ticket!.Principal.FindAll("amr")
            .Select(claim => claim.Value)
            .ToHashSet(StringComparer.Ordinal);
        Assert.Contains("pwd", methods);
        Assert.Contains("mfa", methods);
        Assert.DoesNotContain("otp", methods);
        Assert.Equal("Loa2", ticket.Principal.FindFirst("aal")?.Value);
        Assert.Equal(
            "urn:sufficit:acr:loa2",
            ticket.Principal.FindFirst("acr")?.Value);
        Assert.True(ticket.Properties.IsPersistent);
    }

    [Fact]
    public void Interactive_cookie_lifetimes_are_explicit_and_sliding()
    {
        var options = factory.Services
            .GetRequiredService<IOptionsMonitor<CookieAuthenticationOptions>>();
        var application = options.Get(IdentityConstants.ApplicationScheme);
        var rememberedMfa = options.Get(
            IdentityConstants.TwoFactorRememberMeScheme);

        Assert.Equal(TimeSpan.FromDays(30), application.ExpireTimeSpan);
        Assert.True(application.SlidingExpiration);
        Assert.Equal(TimeSpan.FromDays(30), rememberedMfa.ExpireTimeSpan);
        Assert.True(rememberedMfa.SlidingExpiration);
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
