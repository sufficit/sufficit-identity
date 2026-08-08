using System.Security.Cryptography;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Configuration;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Tests.Infrastructure;
using Sufficit.Identity.STS.Vault;
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
    [Fact]
    public void Registration_exposes_the_configured_state_through_options()
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                [$"{VaultOptions.SectionName}:Enabled"] = "true",
                [$"{VaultOptions.SectionName}:KeySource"] = "dataprotection"
            })
            .Build();
        var services = new ServiceCollection();

        services.AddSufficitVault(configuration);

        using var provider = services.BuildServiceProvider();
        var configured = provider.GetRequiredService<IOptions<VaultOptions>>().Value;
        Assert.True(configured.Enabled);
        Assert.Equal("dataprotection", configured.KeySource);
    }

    [Fact]
    public async Task Registration_exposes_environment_configuration_secret_boundary()
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Secrets:database/password"] = "configured-secret",
            })
            .Build();
        var services = new ServiceCollection();
        services.AddSufficitVault(configuration);

        using var provider = services.BuildServiceProvider();
        var store = provider.GetRequiredService<ISecretStore>();

        Assert.Equal("configured-secret",
            await store.GetSecretAsync("database/password"));
    }

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
    public async Task Real_vault_reads_legacy_pass_through_values_during_migration()
    {
        IKeyVault compatibility = new PassThroughKeyVault();
        var legacy = await compatibility.EncryptAsync(
            "ssf-stream-authz",
            "Bearer legacy-token");
        var (vault, _) = CreateRealVault();

        var decrypted = await vault.DecryptStringAsync(
            legacy,
            new Dictionary<string, string> { ["stream_id"] = "legacy" });

        Assert.Equal("Bearer legacy-token", decrypted);
        var replacement = await vault.EncryptAsync(
            "ssf-stream-authz",
            "Bearer legacy-token",
            new Dictionary<string, string> { ["stream_id"] = "legacy" });
        Assert.StartsWith("v1.", replacement, StringComparison.Ordinal);
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

    [Fact]
    public async Task Named_secret_store_persists_only_ciphertext_and_round_trips()
    {
        var (vault, dbFactory) = CreateRealVault();
        var store = new VaultBackedSecretStore(
            dbFactory,
            vault,
            new VaultOptions { Enabled = true });

        var metadata = await store.PutAsync(
            "providers/google/client-secret",
            "super-secret-value",
            "operator-1");

        Assert.Equal("providers/google/client-secret", metadata.Name);
        Assert.Equal("super-secret-value", await store.GetSecretAsync(metadata.Name));
        Assert.Contains(await store.ListAsync(), item => item.Name == metadata.Name);

        await using var database = await dbFactory.CreateDbContextAsync();
        var row = await database.VaultSecrets.SingleAsync(
            item => item.Name == metadata.Name);
        Assert.DoesNotContain("super-secret-value", row.Ciphertext,
            StringComparison.Ordinal);
        Assert.True(await store.DeleteAsync(metadata.Name));
        Assert.Null(await store.GetSecretAsync(metadata.Name));
    }

    [Fact]
    public async Task Vault_signatures_verify_across_rotation_without_exposing_private_key()
    {
        var (vault, dbFactory) = CreateRealVault();
        var payload = System.Text.Encoding.UTF8.GetBytes("jwt-digest");

        var first = await vault.SignAsync("identity-signing", payload);
        Assert.StartsWith("sig1.identity-signing:1.", first,
            StringComparison.Ordinal);
        Assert.True(await vault.VerifyAsync(first, payload));
        Assert.False(await vault.VerifyAsync(first,
            System.Text.Encoding.UTF8.GetBytes("tampered")));

        await vault.RotateSigningKeyAsync("identity-signing");
        var second = await vault.SignAsync("identity-signing", payload);
        Assert.Contains(":2.", second, StringComparison.Ordinal);
        Assert.True(await vault.VerifyAsync(first, payload));
        Assert.True(await vault.VerifyAsync(second, payload));

        await using var database = await dbFactory.CreateDbContextAsync();
        var keys = await database.VaultKeys
            .Where(key => key.KeyName == "identity-signing")
            .ToArrayAsync();
        Assert.Equal(2, keys.Length);
        Assert.All(keys, key => Assert.Equal("signing", key.Purpose));
        Assert.All(keys, key => Assert.Contains("\"kty\":\"RSA\"",
            key.PublicJwk, StringComparison.Ordinal));
    }

    [Fact]
    public async Task IdentityModel_provider_delegates_signing_to_vault_and_uses_public_rotation_keys()
    {
        var (vault, _) = CreateRealVault();
        var payload = System.Text.Encoding.UTF8.GetBytes("identity-model-signature");
        var descriptor = (await vault.GetSigningKeysAsync("oidc-signing")).Single();
        var key = new VaultSigningSecurityKey(descriptor, vault);

        using var signer = key.CryptoProviderFactory.CreateForSigning(
            key,
            SecurityAlgorithms.RsaSha256);
        var signature = signer.Sign(payload);

        Assert.True(signer.Verify(payload, signature));
        Assert.Equal(descriptor.KeyId, key.KeyId);
        Assert.DoesNotContain("PRIVATE", key.PublicJwk,
            StringComparison.OrdinalIgnoreCase);

        await vault.RotateSigningKeyAsync("oidc-signing");
        var rotated = await vault.GetSigningKeysAsync("oidc-signing");
        Assert.Equal(2, rotated.Count);
        Assert.Contains(rotated, item => item.KeyVersion == descriptor.KeyVersion);
    }

    [Fact]
    public async Task Vault_managed_signing_publishes_versioned_jwks_endpoint()
    {
        using var factory = SufficitIdentityTestFactory.CreateIsolated(
            new Dictionary<string, string?>
            {
                [$"{VaultOptions.SectionName}:Enabled"] = "true",
                [$"{VaultOptions.SectionName}:ManageSigningKeys"] = "true",
                ["Sufficit:Identity:Tokens:UseReferenceAccessTokens"] = "false",
            });
        await ((IAsyncLifetime)factory).InitializeAsync();
        using var client = factory.CreateClient();

        using var response = await client.GetAsync(
            "/.well-known/openid-configuration/jwks");
        response.EnsureSuccessStatusCode();
        var body = await response.Content.ReadAsStringAsync();

        Assert.Contains("vault:oidc-signing:1", body,
            StringComparison.Ordinal);
        Assert.Contains("\"kty\":\"RSA\"", body,
            StringComparison.Ordinal);

        await factory.Services.GetRequiredService<IKeyVault>()
            .RotateSigningKeyAsync("oidc-signing");
        using var rotatedResponse = await client.GetAsync(
            "/.well-known/openid-configuration/jwks");
        rotatedResponse.EnsureSuccessStatusCode();
        var rotatedBody = await rotatedResponse.Content.ReadAsStringAsync();
        Assert.Contains("vault:oidc-signing:1", rotatedBody,
            StringComparison.Ordinal);
        Assert.Contains("vault:oidc-signing:2", rotatedBody,
            StringComparison.Ordinal);

    }

    [Theory]
    [InlineData("../escape")]
    [InlineData("name with spaces")]
    [InlineData("name?query")]
    public void Named_secret_store_rejects_unsafe_names(string name)
    {
        Assert.Throws<ArgumentException>(
            () => VaultBackedSecretStore.NormalizeName(name));
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
