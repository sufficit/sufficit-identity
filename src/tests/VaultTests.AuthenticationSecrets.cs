using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.STS;
using Sufficit.Identity.STS.Security;
using Sufficit.Identity.Vault;
using Xunit;

namespace Sufficit.Identity.Tests;

/// <summary>Authenticator keys and recovery codes encrypted at rest (plan C3).</summary>
public sealed partial class VaultTests
{
    private const string LegacyKey = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";

    [Fact]
    public async Task Second_factor_secrets_are_stored_encrypted_and_read_back_as_they_were()
    {
        var (vault, factory) = CreateRealVault();
        var user = await NewUserAsync(factory);

        await using (var database = await factory.CreateDbContextAsync())
        {
            var store = Store(database, vault);
            var tracked = await store.FindByIdAsync(user.Id);
            await store.SetAuthenticatorKeyAsync(tracked!, LegacyKey, default);
            await store.ReplaceCodesAsync(tracked!, ["AAAAA-11111", "BBBBB-22222"], default);
            await store.UpdateAsync(tracked!);
        }

        await using (var database = await factory.CreateDbContextAsync())
        {
            var stored = await database.UserTokens.AsNoTracking().Where(token => token.UserId == user.Id).ToListAsync();
            Assert.Equal(2, stored.Count);
            Assert.All(stored, token =>
            {
                Assert.StartsWith("v1.", token.Value);
                Assert.DoesNotContain("AAAAA", token.Value);
                Assert.DoesNotContain(LegacyKey, token.Value);
            });

            var store = Store(database, vault);
            var tracked = await store.FindByIdAsync(user.Id);
            Assert.Equal(LegacyKey, await store.GetAuthenticatorKeyAsync(tracked!, default));
            Assert.Equal(2, await store.CountCodesAsync(tracked!, default));
            Assert.True(await store.RedeemCodeAsync(tracked!, "BBBBB-22222", default));
            await store.UpdateAsync(tracked!);
            Assert.Equal(1, await store.CountCodesAsync(tracked!, default));
        }
    }

    [Fact]
    public async Task A_ciphertext_moved_to_another_user_does_not_decrypt()
    {
        var (vault, factory) = CreateRealVault();
        var victim = await NewUserAsync(factory);
        var attacker = await NewUserAsync(factory);
        await SeedTokenAsync(factory, victim.Id, AuthenticationSecretProtection.AuthenticatorKey,
            await AuthenticationSecretProtection.EncryptAsync(vault, victim.Id, AuthenticationSecretProtection.Provider,
                AuthenticationSecretProtection.AuthenticatorKey, LegacyKey, default));
        var copied = await ReadTokenAsync(factory, victim.Id);
        await SeedTokenAsync(factory, attacker.Id, AuthenticationSecretProtection.AuthenticatorKey, copied);

        await using var database = await factory.CreateDbContextAsync();
        var store = Store(database, vault);
        var tracked = await store.FindByIdAsync(attacker.Id);
        await Assert.ThrowsAnyAsync<Exception>(() => store.GetAuthenticatorKeyAsync(tracked!, default));
    }

    [Fact]
    public async Task A_plain_text_second_factor_is_read_until_it_is_no_longer_accepted()
    {
        var (vault, factory) = CreateRealVault();
        var user = await NewUserAsync(factory);
        await SeedTokenAsync(factory, user.Id, AuthenticationSecretProtection.AuthenticatorKey, LegacyKey);

        await using var database = await factory.CreateDbContextAsync();
        var tracked = await Store(database, vault).FindByIdAsync(user.Id);
        Assert.Equal(LegacyKey, await Store(database, vault).GetAuthenticatorKeyAsync(tracked!, default));

        // Never "no authenticator": that would let the account enroll a new one without MFA.
        var strict = Store(database, vault, new TwoFactorOptions { AcceptPlaintextSecrets = false });
        await Assert.ThrowsAsync<InvalidOperationException>(() => strict.GetAuthenticatorKeyAsync(tracked!, default));
    }

    [Fact]
    public async Task The_migration_encrypts_plain_text_secrets_in_place_and_leaves_the_rest()
    {
        var (vault, factory) = CreateRealVault();
        var legacy = await NewUserAsync(factory);
        var current = await NewUserAsync(factory);
        await SeedTokenAsync(factory, legacy.Id, AuthenticationSecretProtection.AuthenticatorKey, LegacyKey);
        await SeedTokenAsync(factory, legacy.Id, AuthenticationSecretProtection.RecoveryCodes, "AAAAA-11111;BBBBB-22222");
        await SeedTokenAsync(factory, legacy.Id, "Sufficit.Identity.Recovery", "untouched", "MfaReenrollmentRequired");
        var alreadyEncrypted = await AuthenticationSecretProtection.EncryptAsync(vault, current.Id,
            AuthenticationSecretProtection.Provider, AuthenticationSecretProtection.AuthenticatorKey, LegacyKey, default);
        await SeedTokenAsync(factory, current.Id, AuthenticationSecretProtection.AuthenticatorKey, alreadyEncrypted);

        var worker = new AuthenticationSecretMigrationWorker(factory, vault, NullLogger<AuthenticationSecretMigrationWorker>.Instance);
        var first = await worker.MigrateAsync(default);
        var second = await worker.MigrateAsync(default);

        Assert.Equal((2, 0), first);
        Assert.Equal((0, 0), second);
        Assert.Equal(alreadyEncrypted, await ReadTokenAsync(factory, current.Id));
        await using var database = await factory.CreateDbContextAsync();
        Assert.Equal("untouched", (await database.UserTokens.SingleAsync(token => token.Name == "MfaReenrollmentRequired")).Value);
        var store = Store(database, vault, new TwoFactorOptions { AcceptPlaintextSecrets = false });
        var tracked = await store.FindByIdAsync(legacy.Id);
        Assert.Equal(LegacyKey, await store.GetAuthenticatorKeyAsync(tracked!, default));
        Assert.Equal(2, await store.CountCodesAsync(tracked!, default));
    }

    private static ProtectedSecretsUserStore Store(AppDbContext database, IKeyVault vault, TwoFactorOptions? twoFactor = null) =>
        new(database, vault, twoFactor ?? new TwoFactorOptions());

    private static async Task<ApplicationUser> NewUserAsync(IDbContextFactory<AppDbContext> factory)
    {
        var id = Guid.NewGuid().ToString("D");
        var user = new ApplicationUser { Id = id, UserName = "u" + id[..8], NormalizedUserName = "U" + id[..8].ToUpperInvariant() };
        await using var database = await factory.CreateDbContextAsync();
        // The users table defaults to MariaDB's UTC_TIMESTAMP (same shim as the test factories).
        var sqlite = (Microsoft.Data.Sqlite.SqliteConnection)database.Database.GetDbConnection();
        sqlite.CreateFunction("UTC_TIMESTAMP", () => DateTime.UtcNow);
        sqlite.CreateFunction<int, DateTime>("UTC_TIMESTAMP", _ => DateTime.UtcNow);
        database.Users.Add(user);
        await database.SaveChangesAsync();
        return user;
    }

    private static async Task SeedTokenAsync(IDbContextFactory<AppDbContext> factory, string userId, string name, string value,
        string? overrideName = null)
    {
        var provider = overrideName is null ? AuthenticationSecretProtection.Provider : name;
        await using var database = await factory.CreateDbContextAsync();
        database.UserTokens.Add(new IdentityUserToken<string>
        {
            UserId = userId, LoginProvider = provider, Name = overrideName ?? name, Value = value,
        });
        await database.SaveChangesAsync();
    }

    private static async Task<string> ReadTokenAsync(IDbContextFactory<AppDbContext> factory, string userId)
    {
        await using var database = await factory.CreateDbContextAsync();
        return (await database.UserTokens.AsNoTracking().SingleAsync(token => token.UserId == userId
            && token.Name == AuthenticationSecretProtection.AuthenticatorKey)).Value!;
    }
}
