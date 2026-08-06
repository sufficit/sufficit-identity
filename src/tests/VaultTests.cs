using System.Security.Cryptography;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Tests.Infrastructure;
using Sufficit.Identity.Vault;
using Sufficit.Identity.Vault.Crypto;
using Xunit;

namespace Sufficit.Identity.Tests;

/// <summary>
/// Covers the internal secret vault: envelope crypto primitives, self-describing
/// ciphertext format, pass-through (disabled) round-trip, and the real KeyVault
/// (encrypt/decrypt/rotate with a SQLite-backed AppDbContext + EphemeralDataProtectionProvider).
/// </summary>
public sealed class VaultTests
{
    // ---- EnvelopeCrypto (AES-256-GCM) ----

    [Fact]
    public void Envelope_round_trips_plaintext()
    {
        var key = EnvelopeCrypto.GenerateKey();
        var plaintext = "Bearer my-secret-token"u8.ToArray();
        var aad = "owner=stream-1"u8.ToArray();

        var ciphertext = EnvelopeCrypto.Encrypt(plaintext, key, aad);
        var decrypted = EnvelopeCrypto.Decrypt(ciphertext, key, aad);

        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public void Envelope_rejects_tampered_ciphertext()
    {
        var key = EnvelopeCrypto.GenerateKey();
        var plaintext = "secret"u8.ToArray();
        var ciphertext = EnvelopeCrypto.Encrypt(plaintext, key, []);

        // Flip a byte in the ciphertext (tamper).
        ciphertext[^1] ^= 0xFF;

        Assert.ThrowsAny<CryptographicException>(
            () => EnvelopeCrypto.Decrypt(ciphertext, key, []));
    }

    [Fact]
    public void Envelope_rejects_aad_mismatch()
    {
        var key = EnvelopeCrypto.GenerateKey();
        var plaintext = "secret"u8.ToArray();
        var ciphertext = EnvelopeCrypto.Encrypt(plaintext, key, "owner=A"u8.ToArray());

        Assert.ThrowsAny<CryptographicException>(
            () => EnvelopeCrypto.Decrypt(ciphertext, key, "owner=B"u8.ToArray()));
    }

    [Fact]
    public void Wrap_and_unwrap_round_trip()
    {
        var kek = EnvelopeCrypto.GenerateKey();
        var dek = EnvelopeCrypto.GenerateKey();

        var wrapped = EnvelopeCrypto.Wrap(dek, kek);
        var unwrapped = EnvelopeCrypto.Unwrap(wrapped, kek);

        Assert.Equal(dek, unwrapped);
    }

    // ---- PassThroughKeyVault (disabled vault) ----

    [Fact]
    public async Task Pass_through_round_trips_without_crypto()
    {
        IKeyVault vault = new PassThroughKeyVault();
        const string plaintext = "Bearer plaintext-token";

        var ciphertext = await vault.EncryptAsync("test-key", plaintext);
        var decrypted = await vault.DecryptStringAsync(ciphertext);

        Assert.Equal(plaintext, decrypted);
        // The ciphertext must NOT equal the plaintext (it's marker-prefixed).
        Assert.NotEqual(plaintext, ciphertext);
    }

    // ---- KeyVault (real, with SQLite + EphemeralDataProtection) ----

    [Fact]
    public async Task Real_vault_round_trips_and_persists_keys()
    {
        var (vault, _) = CreateRealVault();
        const string plaintext = "Bearer my-push-token";

        var ciphertext = await vault.EncryptAsync(
            "ssf-stream-authz",
            System.Text.Encoding.UTF8.GetBytes(plaintext),
            new Dictionary<string, string> { ["stream_id"] = "s1" });
        var decrypted = await vault.DecryptStringAsync(
            ciphertext,
            new Dictionary<string, string> { ["stream_id"] = "s1" });

        Assert.Equal(plaintext, decrypted);
        // Ciphertext must not contain the plaintext.
        Assert.DoesNotContain(plaintext, ciphertext);
    }

    [Fact]
    public async Task Real_vault_rejects_wrong_aad()
    {
        var (vault, _) = CreateRealVault();
        const string plaintext = "secret";

        var ciphertext = await vault.EncryptAsync(
            "test-key",
            System.Text.Encoding.UTF8.GetBytes(plaintext),
            new Dictionary<string, string> { ["stream_id"] = "s1" });

        await Assert.ThrowsAnyAsync<CryptographicException>(
            () => vault.DecryptStringAsync(
                ciphertext,
                new Dictionary<string, string> { ["stream_id"] = "s2" }));
    }

    [Fact]
    public async Task Real_vault_old_ciphertext_decrypts_after_rotation()
    {
        var (vault, dbFactory) = CreateRealVault();
        const string plaintext = "Bearer rotate-me";

        var oldCiphertext = await vault.EncryptAsync("rot-key", plaintext);

        // Rotate — new encrypts use v2.
        await vault.RotateKeyAsync("rot-key");
        var newCiphertext = await vault.EncryptAsync("rot-key", plaintext);

        // Both old and new must decrypt.
        Assert.Equal(plaintext, await vault.DecryptStringAsync(oldCiphertext));
        Assert.Equal(plaintext, await vault.DecryptStringAsync(newCiphertext));

        // Two key versions persisted.
        await using var db = await dbFactory.CreateDbContextAsync();
        var versions = await db.VaultKeys
            .Where(k => k.KeyName == "rot-key")
            .ToListAsync();
        Assert.Equal(2, versions.Count);
    }

    // ---- VaultBackedClientSecretResolver (M1 fix) ----

    [Fact]
    public async Task Client_secret_resolver_round_trips_with_pass_through()
    {
        IKeyVault vault = new PassThroughKeyVault();
        var resolver = new VaultBackedClientSecretResolver(vault);

        // With pass-through, the reference is the plaintext secret itself
        // (dev/migration convenience). Resolve returns it unchanged.
        const string secret = "my-confidential-client-secret";
        var resolved = await resolver.ResolveAsync(secret);

        Assert.Equal(secret, resolved);
    }

    [Fact]
    public async Task Client_secret_resolver_round_trips_with_real_vault()
    {
        var (vault, _) = CreateRealVault();
        var resolver = new VaultBackedClientSecretResolver(vault);

        // Store a secret, then resolve the reference back to the plaintext.
        const string plaintext = "super-secret-client-credential";
        var reference = await resolver.StoreAsync(plaintext);
        var resolved = await resolver.ResolveAsync(reference);

        Assert.Equal(plaintext, resolved);
        // The reference must not contain the plaintext.
        Assert.DoesNotContain(plaintext, reference);
    }

    // ---- Helpers ----

    private static (IKeyVault vault, IDbContextFactory<AppDbContext> dbFactory) CreateRealVault()
    {
        // Hold a single in-memory SQLite connection open for the lifetime of
        // the test so every DbContext created by the factory shares the same
        // database (SQLite :memory: is per-connection).
        var connection = new Microsoft.Data.Sqlite.SqliteConnection("DataSource=:memory:");
        connection.Open();

        var services = new ServiceCollection();
        services.AddLogging();
        services.AddDataProtection().UseEphemeralDataProtectionProvider();
        services.AddDbContextFactory<AppDbContext>(db =>
        {
            db.UseSqlite(connection);
            db.UseOpenIddict();
        });
        var provider = services.BuildServiceProvider();
        var dbFactory = provider.GetRequiredService<IDbContextFactory<AppDbContext>>();

        // Ensure schema exists.
        using var db = dbFactory.CreateDbContext();
        db.Database.EnsureCreated();

        var dpProvider = provider.GetRequiredService<IDataProtectionProvider>();
        var kek = new DataProtectionKeySource(dpProvider, new VaultOptions());
        var logger = provider.GetRequiredService<ILogger<KeyVault>>();
        IKeyVault vault = new KeyVault(dbFactory, kek, logger);
        return (vault, dbFactory);
    }
}
