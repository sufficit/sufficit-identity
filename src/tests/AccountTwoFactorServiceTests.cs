using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.Application.Accounts;
using Sufficit.Identity.Tests.Infrastructure;
using Xunit;

namespace Sufficit.Identity.Tests;

[Collection(StsCollection.Name)]
public sealed class AccountTwoFactorServiceTests(
    SufficitIdentityTestFactory factory)
{
    [Fact]
    public async Task Setup_reuses_the_persisted_key_and_builds_an_encoded_uri()
    {
        await using var scope = factory.Services.CreateAsyncScope();
        var users = scope.ServiceProvider
            .GetRequiredService<UserManager<ApplicationUser>>();
        var service = scope.ServiceProvider
            .GetRequiredService<IAccountTwoFactorService>();
        var user = await CreateUserAsync(users);
        var principal = PrincipalFor(user);

        var started = await service.BeginSetupAsync(principal);
        var reloaded = await service.GetOverviewAsync(principal);

        Assert.True(started.Succeeded);
        var setup = Assert.IsType<AccountAuthenticatorSetup>(
            started.State?.AuthenticatorSetup);
        var persistedSetup = Assert.IsType<AccountAuthenticatorSetup>(
            reloaded?.AuthenticatorSetup);
        Assert.Equal(setup.SharedKey, persistedSetup.SharedKey);
        Assert.Equal(setup.AuthenticatorUri, persistedSetup.AuthenticatorUri);
        Assert.Contains(
            "otpauth://totp/Sufficit%20Identity:",
            setup.AuthenticatorUri,
            StringComparison.Ordinal);
        Assert.Contains("%40tests.local", setup.AuthenticatorUri, StringComparison.Ordinal);
        Assert.Contains(
            $"secret={Uri.EscapeDataString(setup.SharedKey)}",
            setup.AuthenticatorUri,
            StringComparison.Ordinal);
        Assert.Contains(
            "issuer=Sufficit%20Identity&digits=6",
            setup.AuthenticatorUri,
            StringComparison.Ordinal);
        Assert.Equal(
            setup.SharedKey.Replace(" ", "", StringComparison.Ordinal),
            setup.ManualKey.Replace(" ", "", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Current_authenticator_code_enables_two_factor_and_returns_recovery_codes()
    {
        await using var scope = factory.Services.CreateAsyncScope();
        var users = scope.ServiceProvider
            .GetRequiredService<UserManager<ApplicationUser>>();
        var service = scope.ServiceProvider
            .GetRequiredService<IAccountTwoFactorService>();
        var user = await CreateUserAsync(users);
        var principal = PrincipalFor(user);
        var started = await service.BeginSetupAsync(principal);
        var key = Assert.IsType<AccountAuthenticatorSetup>(
            started.State?.AuthenticatorSetup).SharedKey;
        var code = CurrentAuthenticatorCode(key);

        var enabled = await service.EnableAsync(
            principal,
            $"{code[..3]}-{code[3..]}");

        Assert.True(enabled.Succeeded);
        Assert.True(enabled.State?.IsEnabled);
        Assert.Equal(10, enabled.RecoveryCodes.Count);
        Assert.Equal(10, enabled.RecoveryCodes.Distinct(StringComparer.Ordinal).Count());
        Assert.True(await users.GetTwoFactorEnabledAsync(user));
        Assert.Equal(10, await users.CountRecoveryCodesAsync(user));
    }

    [Fact]
    public async Task Enable_succeeds_after_the_interactive_response_has_started()
    {
        await using var scope = factory.Services.CreateAsyncScope();
        var services = scope.ServiceProvider;
        var users = services.GetRequiredService<UserManager<ApplicationUser>>();
        var service = services.GetRequiredService<IAccountTwoFactorService>();
        var user = await CreateUserAsync(users);
        var principal = PrincipalFor(user);
        var context = new DefaultHttpContext
        {
            RequestServices = services,
            User = principal,
        };
        context.Features.Set<IHttpResponseFeature>(new StartedHttpResponseFeature());
        services.GetRequiredService<IHttpContextAccessor>().HttpContext = context;
        var started = await service.BeginSetupAsync(principal);
        var key = Assert.IsType<AccountAuthenticatorSetup>(
            started.State?.AuthenticatorSetup).SharedKey;

        var enabled = await service.EnableAsync(
            principal,
            CurrentAuthenticatorCode(key));

        Assert.True(context.Response.HasStarted);
        Assert.True(enabled.Succeeded);
        Assert.True(enabled.State?.IsEnabled);
        Assert.Equal(10, enabled.RecoveryCodes.Count);
        Assert.True(await users.GetTwoFactorEnabledAsync(user));
    }

    [Fact]
    public async Task Invalid_code_fails_without_enabling_two_factor()
    {
        await using var scope = factory.Services.CreateAsyncScope();
        var users = scope.ServiceProvider
            .GetRequiredService<UserManager<ApplicationUser>>();
        var service = scope.ServiceProvider
            .GetRequiredService<IAccountTwoFactorService>();
        var user = await CreateUserAsync(users);
        var principal = PrincipalFor(user);
        Assert.True((await service.BeginSetupAsync(principal)).Succeeded);

        var result = await service.EnableAsync(principal, "12-abcd");

        Assert.False(result.Succeeded);
        Assert.Contains(
            result.Errors,
            error => error.Code == "authenticator-code-invalid");
        Assert.Contains(
            "data e hora automáticas",
            Assert.Single(result.Errors).Description,
            StringComparison.OrdinalIgnoreCase);
        Assert.False(await users.GetTwoFactorEnabledAsync(user));
        Assert.Equal(0, await users.CountRecoveryCodesAsync(user));
    }

    [Fact]
    public async Task Repeated_enable_after_success_reports_the_authoritative_enabled_state()
    {
        await using var scope = factory.Services.CreateAsyncScope();
        var users = scope.ServiceProvider
            .GetRequiredService<UserManager<ApplicationUser>>();
        var service = scope.ServiceProvider
            .GetRequiredService<IAccountTwoFactorService>();
        var user = await CreateUserAsync(users);
        var principal = PrincipalFor(user);
        var started = await service.BeginSetupAsync(principal);
        var key = Assert.IsType<AccountAuthenticatorSetup>(
            started.State?.AuthenticatorSetup).SharedKey;
        var code = CurrentAuthenticatorCode(key);

        Assert.True((await service.EnableAsync(principal, code)).Succeeded);

        var repeated = await service.EnableAsync(principal, code);

        Assert.False(repeated.Succeeded);
        Assert.True(repeated.State?.IsEnabled);
        Assert.Contains(
            repeated.Errors,
            error => error.Code == "two-factor-already-enabled");
    }

    [Fact]
    public async Task Recovery_regeneration_and_authenticator_reset_rotate_credentials()
    {
        await using var scope = factory.Services.CreateAsyncScope();
        var users = scope.ServiceProvider
            .GetRequiredService<UserManager<ApplicationUser>>();
        var service = scope.ServiceProvider
            .GetRequiredService<IAccountTwoFactorService>();
        var user = await CreateUserAsync(users);
        var principal = PrincipalFor(user);
        var started = await service.BeginSetupAsync(principal);
        var originalKey = started.State?.AuthenticatorSetup?.SharedKey;
        Assert.False(string.IsNullOrWhiteSpace(originalKey));
        var code = CurrentAuthenticatorCode(originalKey!);
        var enabled = await service.EnableAsync(principal, code);
        Assert.True(enabled.Succeeded);

        var regenerated = await service.GenerateRecoveryCodesAsync(principal);
        var disabled = await service.DisableAsync(principal);
        var reset = await service.ResetAuthenticatorAsync(principal);

        Assert.True(regenerated.Succeeded);
        Assert.Equal(10, regenerated.RecoveryCodes.Count);
        Assert.Empty(
            enabled.RecoveryCodes.Intersect(
                regenerated.RecoveryCodes,
                StringComparer.Ordinal));
        Assert.True(disabled.Succeeded);
        Assert.False(disabled.State?.IsEnabled);
        Assert.Equal(
            originalKey,
            disabled.State?.AuthenticatorSetup?.SharedKey);
        Assert.True(reset.Succeeded);
        Assert.False(reset.State?.IsEnabled);
        Assert.NotNull(reset.State?.AuthenticatorSetup);
        Assert.NotEqual(
            originalKey,
            reset.State!.AuthenticatorSetup!.SharedKey);
        Assert.False(await users.GetTwoFactorEnabledAsync(user));
    }

    [Fact]
    public async Task Unauthenticated_principals_fail_closed()
    {
        await using var scope = factory.Services.CreateAsyncScope();
        var service = scope.ServiceProvider
            .GetRequiredService<IAccountTwoFactorService>();
        var anonymous = new ClaimsPrincipal(new ClaimsIdentity());

        Assert.Null(await service.GetOverviewAsync(anonymous));
        var results = new[]
        {
            await service.BeginSetupAsync(anonymous),
            await service.EnableAsync(anonymous, "123456"),
            await service.GenerateRecoveryCodesAsync(anonymous),
            await service.ResetAuthenticatorAsync(anonymous),
            await service.DisableAsync(anonymous),
        };

        Assert.All(
            results,
            result =>
            {
                Assert.False(result.Succeeded);
                Assert.Contains(
                    result.Errors,
                    error => error.Code == "unauthenticated");
            });
    }

    private static async Task<ApplicationUser> CreateUserAsync(
        UserManager<ApplicationUser> users) =>
        await TestDataSeeder.CreateUserAsync(
            users,
            $"two-factor-{Guid.NewGuid():N}",
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

    private sealed class StartedHttpResponseFeature : IHttpResponseFeature
    {
        public int StatusCode { get; set; } = StatusCodes.Status200OK;

        public string? ReasonPhrase { get; set; }

        public IHeaderDictionary Headers { get; set; } = new HeaderDictionary();

        public Stream Body { get; set; } = Stream.Null;

        public bool HasStarted => true;

        public void OnStarting(Func<object, Task> callback, object state)
        {
        }

        public void OnCompleted(Func<object, Task> callback, object state)
        {
        }
    }
}
