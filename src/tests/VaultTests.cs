using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Claims;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Configuration;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Sufficit.Identity.Core.Entities;
using Sufficit.Identity.Core.Data;
using Sufficit.Identity.Tests.Infrastructure;
using Sufficit.Identity.Management.Provisioning;
using Sufficit.Identity.Management;
using Sufficit.Identity.Management.Authorization;
using Sufficit.Identity.Management.Vault;
using Sufficit.Identity.STS;
using Sufficit.Identity.STS.Email;
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
    public async Task Personal_secrets_are_scoped_by_owner_and_never_return_plaintext()
    {
        var (vault, dbFactory) = CreateRealVault();
        var service = new UserVaultPersonalSecretService(
            dbFactory,
            vault,
            new VaultOptions
            {
                Enabled = true,
                SigningKeyOverlapSeconds = 1,
            });

        await service.PutAsync(
            "user-a", "personal", "provider/api-key",
            new SaveUserVaultSecret("secret-a"));
        await service.PutAsync(
            "user-b", "personal", "provider/api-key",
            new SaveUserVaultSecret("secret-b"));

        var userA = await service.ListAsync("user-a", "personal");
        var userB = await service.ListAsync("user-b", "personal");

        Assert.Single(userA);
        Assert.Single(userB);
        Assert.Equal("user-a", userA[0].UpdatedBy);
        Assert.Equal("user-b", userB[0].UpdatedBy);

        await using var database = await dbFactory.CreateDbContextAsync();
        var stored = await database.VaultPersonalSecrets
            .OrderBy(secret => secret.OwnerSubject)
            .ToArrayAsync();
        Assert.Equal(2, stored.Length);
        Assert.DoesNotContain("secret-a", stored[0].Ciphertext, StringComparison.Ordinal);
        Assert.DoesNotContain("secret-b", stored[1].Ciphertext, StringComparison.Ordinal);

        await service.DeleteAsync("user-a", "personal", "provider/api-key");
        Assert.Empty(await service.ListAsync("user-a", "personal"));
        Assert.Single(await service.ListAsync("user-b", "personal"));
    }

    [Fact]
    public void Registration_exposes_the_configured_state_through_options()
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["ASPNETCORE_ENVIRONMENT"] = "Development",
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
    public void Encryption_is_required_by_default_and_cannot_be_disabled_outside_development()
    {
        var defaults = new VaultOptions();
#pragma warning disable CS0618
        Assert.True(defaults.RequireEncryptionInProduction);
        var legacyOverride = new VaultOptions
        {
            Enabled = false,
            RequireEncryptionInProduction = false,
        };
#pragma warning restore CS0618

        var exception = Assert.Throws<InvalidOperationException>(() =>
            Sufficit.Identity.Vault.ServiceCollectionExtensions.ValidateRuntimeMode(
                legacyOverride,
                isDevelopment: false));
        Assert.Contains("development-only", exception.Message,
            StringComparison.Ordinal);

        Sufficit.Identity.Vault.ServiceCollectionExtensions.ValidateRuntimeMode(
            new VaultOptions { Enabled = false },
            isDevelopment: true);
    }

    [Fact]
    public void Production_kek_policy_requires_dedicated_certificate_and_rejects_token_signing_reuse()
    {
        var emptyConfiguration = new ConfigurationBuilder().Build();
        var dataProtection = Assert.Throws<InvalidOperationException>(() =>
            Sufficit.Identity.Vault.ServiceCollectionExtensions
                .ValidateKeyEncryptionKeyPolicy(
                    new VaultOptions
                    {
                        Enabled = true,
                        KeySource = "dataprotection",
                    },
                    emptyConfiguration,
                    isDevelopment: false));
        Assert.Contains("certificate", dataProtection.Message,
            StringComparison.OrdinalIgnoreCase);

        var sharedPath = Path.GetFullPath("shared-signing-and-kek.pfx");
        var sharedConfiguration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Sufficit:Identity:Certificates:SigningPath"] = sharedPath,
            })
            .Build();
        var reuse = Assert.Throws<InvalidOperationException>(() =>
            Sufficit.Identity.Vault.ServiceCollectionExtensions
                .ValidateKeyEncryptionKeyPolicy(
                    new VaultOptions
                    {
                        Enabled = true,
                        KeySource = "certificate",
                        CertificatePath = sharedPath,
                    },
                    sharedConfiguration,
                    isDevelopment: false));
        Assert.Contains("different", reuse.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void External_kms_adapter_pins_identifier_and_round_trips()
    {
        var provider = new XorExternalKeyEncryptionProvider("kms://test/kek/7");
        var source = new ExternalKeySource(provider, new VaultOptions
        {
            ExternalKeyIdentifier = "kms://test/kek/7",
        });
        var plaintext = RandomNumberGenerator.GetBytes(32);

        Assert.Equal(plaintext, source.Unwrap(source.Wrap(plaintext)));
        Assert.Throws<InvalidOperationException>(() =>
            new ExternalKeySource(provider, new VaultOptions
            {
                ExternalKeyIdentifier = "kms://test/kek/8",
            }));
    }

    [Fact]
    public void Legacy_data_protection_certificate_fallback_is_bounded_and_attributed()
    {
        var now = new DateTimeOffset(2026, 8, 9, 12, 0, 0, TimeSpan.Zero);
        Assert.Throws<InvalidOperationException>(() =>
            Sufficit.Identity.Vault.ServiceCollectionExtensions
                .ValidateLegacyCertificateMigration(
                    new VaultLegacyCertificateMigrationOptions
                    {
                        Owner = "identity-platform",
                        ExpiresAtUtc = now.AddDays(30),
                    },
                    now));
        Assert.Throws<InvalidOperationException>(() =>
            Sufficit.Identity.Vault.ServiceCollectionExtensions
                .ValidateLegacyCertificateMigration(
                    new VaultLegacyCertificateMigrationOptions
                    {
                        Owner = "identity-platform",
                        Reason = "rotate the legacy DP ring",
                        ExpiresAtUtc = now,
                    },
                    now));

        Sufficit.Identity.Vault.ServiceCollectionExtensions
            .ValidateLegacyCertificateMigration(
                new VaultLegacyCertificateMigrationOptions
                {
                    Owner = "identity-platform",
                    Reason = "rotate the legacy DP ring",
                    ExpiresAtUtc = now.AddDays(30),
                },
                now);
    }

    [Fact]
    public async Task Registration_does_not_read_configuration_as_secret()
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["ASPNETCORE_ENVIRONMENT"] = "Development",
                [$"{VaultOptions.SectionName}:Enabled"] = "true",
                ["Secrets:database/password"] = "configured-secret",
            })
            .Build();
        var services = new ServiceCollection();
        services.AddSufficitVault(configuration);

        using var provider = services.BuildServiceProvider();
        var store = provider.GetRequiredService<ISecretStore>();

        Assert.Null(
            await store.GetSecretAsync("database/password"));
    }

    [Fact]
    public void Startup_secret_overrides_take_precedence_without_logging_values()
    {
        const string environmentName =
            "SUFFICIT_SECRET_IDENTITY_CERTIFICATES_SIGNING_PASSWORD";
        var previous = Environment.GetEnvironmentVariable(environmentName);
        try
        {
            Environment.SetEnvironmentVariable(environmentName, "from-environment");
            var configuration = new ConfigurationBuilder()
                .AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["Sufficit:Identity:Certificates:SigningPassword"] =
                        "from-json",
                })
                .AddSufficitSecretOverrides()
                .Build();

            Assert.Equal(
                "from-environment",
                configuration["Sufficit:Identity:Certificates:SigningPassword"]);
        }
        finally
        {
            Environment.SetEnvironmentVariable(environmentName, previous);
        }
    }

    [Fact]
    public async Task Environment_secret_store_ignores_legacy_startup_configuration()
    {
        var store = new EnvironmentSecretStore();

        Assert.Null(
            await store.GetSecretAsync(
                "identity/certificates/signing-password"));
    }

    [Fact]
    public void Plaintext_startup_secrets_are_rejected_before_environment_overrides()
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Sufficit:Identity:Certificates:SigningPassword"] =
                    "legacy-signing-password",
            })
            .Build();

        var exception = Assert.Throws<InvalidOperationException>(
            () => SecretConfigurationExtensions.EnsureNoPlaintextSecrets(
                configuration));

        Assert.Contains("SigningPassword", exception.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("legacy-signing-password", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Email_transports_resolve_passwords_from_the_secret_store()
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Sufficit:Exchange:RabbitMQ:HostName"] = "broker",
                ["Sufficit:Exchange:RabbitMQ:Password"] = "legacy-rabbit",
                ["Sufficit:Identity:Smtp:Password"] = "legacy-smtp",
            })
            .Build();
        var store = new DictionarySecretStore(new Dictionary<string, string?>
        {
            ["exchange/rabbitmq/password"] = "store-rabbit",
            ["identity/smtp/password"] = "store-smtp",
        });
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSufficitEmailSender(configuration, store);

        using var provider = services.BuildServiceProvider();
        var rabbit = provider.GetRequiredService<IOptions<RabbitMqEmailOptions>>().Value;

        Assert.Equal("store-rabbit", rabbit.Password);
        Assert.Contains("exchange/rabbitmq/password", store.RequestedNames);
    }

    [Fact]
    public void Startup_secret_overrides_can_be_resolved_through_ISecretStore()
    {
        var store = new DictionarySecretStore(new Dictionary<string, string?>
        {
            ["database/connection-string"] = "server=secret-host;database=identity",
            ["identity/certificates/signing-password"] = "signing-secret",
        });
        var configuration = new ConfigurationBuilder()
            .AddSufficitSecretOverrides(store)
            .Build();

        Assert.Equal(
            "server=secret-host;database=identity",
            configuration["ConnectionStrings:DefaultConnection"]);
        Assert.Equal(
            "signing-secret",
            configuration["Sufficit:Identity:Certificates:SigningPassword"]);
        Assert.Null(configuration["Sufficit:Identity:Certificates:EncryptionPassword"]);
        Assert.Equal(
            SecretConfigurationExtensions.GetSufficitSecretOverrideMappings().Count,
            store.RequestedNames.Count);
        Assert.Contains("database/connection-string", store.RequestedNames);
        Assert.Contains("identity/certificates/signing-password", store.RequestedNames);
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
    public async Task Real_vault_rejects_aad_hash_with_different_length()
    {
        var (vault, _) = CreateRealVault();
        var aad = new Dictionary<string, string> { ["stream_id"] = "s1" };
        var ciphertext = await vault.EncryptAsync("test-key", "secret", aad);
        var parts = ciphertext.Split('.', StringSplitOptions.None);
        parts[^1] = WebEncoders.Base64UrlEncode(new byte[7]);
        var malformed = string.Join('.', parts);

        await Assert.ThrowsAnyAsync<CryptographicException>(
            () => vault.DecryptStringAsync(malformed, aad));
    }

    [Fact]
    public async Task Real_vault_rejects_truncated_ciphertext()
    {
        var (vault, _) = CreateRealVault();
        var ciphertext = await vault.EncryptAsync("test-key", "secret");
        var parts = ciphertext.Split('.', StringSplitOptions.None);
        parts[2] = WebEncoders.Base64UrlEncode([1, 2, 3]);
        var malformed = string.Join('.', parts);

        await Assert.ThrowsAnyAsync<CryptographicException>(
            () => vault.DecryptStringAsync(malformed));
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
    public async Task Named_secrets_are_isolated_by_context_and_namespace()
    {
        var (vault, dbFactory) = CreateRealVault();
        var store = new VaultBackedSecretStore(
            dbFactory,
            vault,
            new VaultOptions { Enabled = true });

        await store.PutAsync(
            "Providers/Google/Client-Secret",
            "tenant-a-secret",
            "operator-a",
            "tenant-a");
        await store.PutAsync(
            "providers/google/client-secret",
            "tenant-b-secret",
            "operator-b",
            "tenant-b");
        await store.PutAsync(
            "billing/gateway/api-key",
            "billing-secret",
            "operator-a",
            "tenant-a");

        Assert.Equal(
            "tenant-a-secret",
            await store.GetSecretAsync(
                "providers/google/client-secret",
                "tenant-a"));
        Assert.Equal(
            "tenant-b-secret",
            await store.GetSecretAsync(
                "providers/google/client-secret",
                "tenant-b"));
        Assert.Null(await store.GetSecretAsync(
            "providers/google/client-secret",
            "tenant-c"));

        var providersOnly = await store.ListAsync(
            "tenant-a",
            new HashSet<string>(["providers"], StringComparer.Ordinal));
        var provider = Assert.Single(providersOnly);
        Assert.Equal("providers", provider.Namespace);
        Assert.Equal("tenant-a", provider.ContextId);
        Assert.Equal("operator-a", provider.OwnerSubject);
        Assert.False(await store.DeleteAsync(
            "providers/google/client-secret",
            "tenant-c"));

        await store.PutAsync(
            "providers/google/client-secret",
            "tenant-a-rotated",
            "operator-c",
            "tenant-a");
        var rotated = Assert.Single(await store.ListAsync(
            "tenant-a",
            new HashSet<string>(["providers"], StringComparer.Ordinal)));
        Assert.Equal("operator-a", rotated.OwnerSubject);
        Assert.Equal("operator-c", rotated.UpdatedBy);
        Assert.Equal(
            "tenant-a-rotated",
            await store.GetSecretAsync(rotated.Name, "tenant-a"));
        Assert.Equal(
            "tenant-b-secret",
            await store.GetSecretAsync(rotated.Name, "tenant-b"));

        await using (var database = await dbFactory.CreateDbContextAsync())
        {
            var moved = await database.VaultSecrets.SingleAsync(secret =>
                secret.ContextId == "tenant-b"
                && secret.Name == rotated.Name);
            moved.ContextId = "tenant-c";
            await database.SaveChangesAsync();
        }
        await Assert.ThrowsAnyAsync<CryptographicException>(() =>
            store.GetSecretAsync(rotated.Name, "tenant-c"));
    }

    [Theory]
    [InlineData(" Providers/Google/Client-Secret ", "providers/google/client-secret")]
    [InlineData("billing/API_KEY", "billing/api_key")]
    public void Named_secret_normalization_is_canonical(
        string input,
        string expected) =>
        Assert.Equal(expected, VaultBackedSecretStore.NormalizeName(input));

    [Fact]
    public async Task Management_named_secrets_filter_namespaces_and_audit_break_glass()
    {
        var vaultOptions = new VaultOptions { Enabled = true };
        var (vault, dbFactory) = CreateRealVault(vaultOptions);
        var store = new VaultBackedSecretStore(
            dbFactory,
            vault,
            vaultOptions);
        await store.PutAsync(
            "providers/google/client-secret",
            "provider-secret",
            "seed",
            "global");
        await store.PutAsync(
            "billing/gateway/api-key",
            "billing-secret",
            "seed",
            "global");

        var managementOptions = Options.Create(
            new Sufficit.Identity.Management.ManagementOptions
        {
            Authorization = new ManagementAuthorizationOptions(),
        });
        var namespacePolicy =
            new ConfigurationVaultSecretNamespaceAccessPolicy(
                managementOptions);
        await using var database = await dbFactory.CreateDbContextAsync();
        var service = new VaultSecretsManagementService(
            database,
            store,
            new AllowingManagementAuthorizationEvaluator(),
            namespacePolicy,
            Options.Create(vaultOptions));
        var scopedPrincipal = new ClaimsPrincipal(new ClaimsIdentity(
            [
                new Claim("sub", "operator-1"),
                new Claim("identity_vault_namespace", "global:providers"),
            ],
            "test"));
        var scopedContext = new ManagementRequestContext(
            scopedPrincipal,
            "namespace-filter-test");

        var visible = await service.ListAsync("global", scopedContext);
        Assert.Equal(
            "providers/google/client-secret",
            Assert.Single(visible).Name);
        var guessed = await Assert.ThrowsAsync<ManagementAccessException>(() =>
            service.GetAsync(
                "billing/gateway/api-key",
                "global",
                scopedContext));
        Assert.Equal(
            "vault_namespace_not_accessible",
            guessed.Decision.ReasonCode);

        var breakGlassPrincipal = new ClaimsPrincipal(new ClaimsIdentity(
            [
                new Claim("sub", "incident-operator"),
                new Claim(
                    "identity_vault_break_glass",
                    "identity.vault.secrets"),
                new Claim("amr", "pwd mfa"),
            ],
            "test"));
        var breakGlassContext = new ManagementRequestContext(
            breakGlassPrincipal,
            "break-glass-test");
        Assert.Equal(2, (await service.ListAsync(
            "global",
            breakGlassContext)).Count);

        var audit = await database.ManagementAuditEvents.AsNoTracking()
            .SingleAsync(item => item.CorrelationId == "break-glass-test");
        Assert.Equal("vault_break_glass", audit.ReasonCode);
        Assert.Equal("global", audit.ContextId);
        Assert.Equal(
            ManagementResourceTypes.VaultSecretCollection,
            audit.ResourceType);
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
    public async Task Signing_rotation_is_idempotent_and_only_the_active_key_can_issue()
    {
        var (vault, dbFactory) = CreateRealVault(new VaultOptions
        {
            Enabled = true,
            SigningKeyOverlapSeconds = 300,
        });
        var payload = System.Text.Encoding.UTF8.GetBytes("rotation-lifecycle");
        var oldSignature = await vault.SignAsync("lifecycle-signing", payload);

        var first = await vault.RotateSigningKeyAsync(
            "lifecycle-signing",
            "rotation-operation-1",
            "scheduled rotation");
        var retry = await vault.RotateSigningKeyAsync(
            "lifecycle-signing",
            "rotation-operation-1",
            "scheduled rotation");

        Assert.Equal(first, retry);
        Assert.Equal(2, first.Version);
        Assert.True(await vault.VerifyAsync(oldSignature, payload));
        await Assert.ThrowsAnyAsync<CryptographicException>(() =>
            vault.SignAsync("lifecycle-signing", 1, payload));

        var published = await vault.GetSigningKeysAsync("lifecycle-signing");
        Assert.Collection(
            published,
            active =>
            {
                Assert.Equal(2, active.KeyVersion);
                Assert.Equal(VaultSigningKeyStatus.Active, active.Status);
            },
            retiring =>
            {
                Assert.Equal(1, retiring.KeyVersion);
                Assert.Equal(VaultSigningKeyStatus.Retiring, retiring.Status);
                Assert.NotNull(retiring.RetireAfterUtc);
            });

        await using var database = await dbFactory.CreateDbContextAsync();
        Assert.Equal(2, await database.VaultKeys.CountAsync(key =>
            key.KeyName == "lifecycle-signing"));
        Assert.Equal(1, await database.VaultSigningKeyLifecycleOperations
            .CountAsync(item => item.Action == "rotate"));
    }

    [Fact]
    public async Task Elapsed_signing_key_is_retired_and_no_longer_verifies()
    {
        var clock = new MutableTimeProvider(
            new DateTimeOffset(2026, 8, 9, 12, 0, 0, TimeSpan.Zero));
        var (vault, dbFactory) = CreateRealVault(
            new VaultOptions
            {
                Enabled = true,
                SigningKeyOverlapSeconds = 60,
            },
            clock);
        var payload = System.Text.Encoding.UTF8.GetBytes("retirement");
        var oldSignature = await vault.SignAsync("retire-signing", payload);
        await vault.RotateSigningKeyAsync(
            "retire-signing",
            "rotation-before-retirement");

        clock.Advance(TimeSpan.FromSeconds(61));
        Assert.Single(await vault.GetSigningKeysAsync("retire-signing"));
        Assert.Equal(1, await vault.RetireSigningKeysAsync("retire-signing"));
        Assert.False(await vault.VerifyAsync(oldSignature, payload));

        await using var database = await dbFactory.CreateDbContextAsync();
        var retired = await database.VaultKeys.SingleAsync(key =>
            key.KeyName == "retire-signing" && key.KeyVersion == 1);
        Assert.Equal(VaultSigningKeyState.Retired, retired.SigningState);
        Assert.Equal(clock.GetUtcNow().UtcDateTime, retired.RetiredAtUtc);
        Assert.Contains(await database.VaultSigningKeyLifecycleOperations
                .ToArrayAsync(),
            item => item.Action == "retire" && item.KeyVersion == 1);
    }

    [Fact]
    public async Task Emergency_revocation_removes_jwks_and_blocks_live_tokens()
    {
        var (vault, dbFactory) = CreateRealVault();
        var payload = System.Text.Encoding.UTF8.GetBytes("emergency-revoke");
        var signature = await vault.SignAsync("revoked-signing", payload);

        Assert.True(await vault.RevokeSigningKeyAsync(
            "revoked-signing",
            1,
            "incident-2026-08-09",
            "private key exposure"));
        Assert.True(await vault.RevokeSigningKeyAsync(
            "revoked-signing",
            1,
            "incident-2026-08-09",
            "private key exposure"));

        Assert.Empty(await vault.GetSigningKeysAsync("revoked-signing"));
        Assert.False(await vault.VerifyAsync(signature, payload));
        await Assert.ThrowsAnyAsync<CryptographicException>(() =>
            vault.SignAsync("revoked-signing", payload));

        await using var database = await dbFactory.CreateDbContextAsync();
        var key = await database.VaultKeys.SingleAsync(item =>
            item.KeyName == "revoked-signing");
        Assert.Equal(VaultSigningKeyState.Revoked, key.SigningState);
        Assert.NotNull(key.RevokedAtUtc);
        Assert.Equal(1, await database.VaultSigningKeyLifecycleOperations
            .CountAsync(item => item.Action == "revoke"));
    }

    [Fact]
    public async Task Rotation_lease_recovers_after_expiry_without_two_active_keys()
    {
        var clock = new MutableTimeProvider(
            new DateTimeOffset(2026, 8, 9, 12, 0, 0, TimeSpan.Zero));
        var options = new VaultOptions
        {
            Enabled = true,
            SigningKeyOverlapSeconds = 60,
            SigningKeyLockSeconds = 5,
        };
        var (vault, dbFactory) = CreateRealVault(options, clock);
        await vault.GetSigningKeysAsync("lease-signing");
        await using (var database = await dbFactory.CreateDbContextAsync())
        {
            database.VaultSigningKeyLocks.Add(new VaultSigningKeyLock
            {
                KeyName = "lease-signing",
                OwnerId = "other-replica",
                ExpiresAtUtc = clock.GetUtcNow().UtcDateTime.AddSeconds(5),
            });
            await database.SaveChangesAsync();
        }

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            vault.RotateSigningKeyAsync("lease-signing", "lease-conflict"));
        clock.Advance(TimeSpan.FromSeconds(6));
        var rotated = await vault.RotateSigningKeyAsync(
            "lease-signing",
            "lease-recovered");
        Assert.Equal(2, rotated.Version);

        await using var verification = await dbFactory.CreateDbContextAsync();
        Assert.Equal(1, await verification.VaultKeys.CountAsync(key =>
            key.KeyName == "lease-signing"
            && key.SigningState == VaultSigningKeyState.Active));
    }

    [Fact]
    public async Task Concurrent_rotation_requests_never_leave_multiple_active_keys()
    {
        var databasePath = Path.Combine(
            Path.GetTempPath(),
            $"vault-concurrency-{Guid.NewGuid():N}.db");
        ServiceProvider? provider = null;
        try
        {
            var services = new ServiceCollection();
            services.AddLogging();
            services.AddDataProtection().UseEphemeralDataProtectionProvider();
            services.AddDbContextFactory<AppDbContext>(database =>
            {
                database.UseSqlite($"Data Source={databasePath}");
                database.UseOpenIddict();
            });
            provider = services.BuildServiceProvider();
            var factory = provider.GetRequiredService<
                IDbContextFactory<AppDbContext>>();
            await using (var setup = await factory.CreateDbContextAsync())
            {
                await setup.Database.EnsureCreatedAsync();
            }
            var options = new VaultOptions
            {
                Enabled = true,
                SigningKeyOverlapSeconds = 60,
                SigningKeyLockSeconds = 60,
            };
            var keySource = new DataProtectionKeySource(
                provider.GetRequiredService<IDataProtectionProvider>(),
                options);
            var logger = provider.GetRequiredService<ILogger<KeyVault>>();
            IKeyVault firstReplica = new KeyVault(
                factory, keySource, logger, options);
            IKeyVault secondReplica = new KeyVault(
                factory, keySource, logger, options);
            await firstReplica.GetSigningKeysAsync("concurrent-signing");

            static async Task<bool> RotateAsync(
                IKeyVault vault,
                string operationId)
            {
                try
                {
                    await vault.RotateSigningKeyAsync(
                        "concurrent-signing",
                        operationId);
                    return true;
                }
                catch (InvalidOperationException)
                {
                    return false;
                }
            }

            var results = await Task.WhenAll(
                RotateAsync(firstReplica, "concurrent-rotation-1"),
                RotateAsync(secondReplica, "concurrent-rotation-2"));
            Assert.Contains(true, results);

            await using var verification = await factory.CreateDbContextAsync();
            Assert.Equal(1, await verification.VaultKeys.CountAsync(key =>
                key.KeyName == "concurrent-signing"
                && key.SigningState == VaultSigningKeyState.Active));
            Assert.Equal(
                1 + results.Count(result => result),
                await verification.VaultKeys.CountAsync(key =>
                    key.KeyName == "concurrent-signing"));
        }
        finally
        {
            if (provider is not null) await provider.DisposeAsync();
            if (File.Exists(databasePath)) File.Delete(databasePath);
        }
    }

    [Fact]
    public async Task Kek_failure_rolls_back_rotation_and_preserves_the_active_key()
    {
        FailingKeySource? failing = null;
        var (vault, dbFactory) = CreateRealVault(
            new VaultOptions
            {
                Enabled = true,
                SigningKeyOverlapSeconds = 60,
            },
            keySourceFactory: provider => failing = new FailingKeySource(
                new DataProtectionKeySource(provider, new VaultOptions())));
        await vault.GetSigningKeysAsync("rollback-signing");
        failing!.FailWrap = true;

        await Assert.ThrowsAnyAsync<CryptographicException>(() =>
            vault.RotateSigningKeyAsync(
                "rollback-signing",
                "failed-rotation"));

        await using var database = await dbFactory.CreateDbContextAsync();
        var onlyKey = Assert.Single(await database.VaultKeys
            .Where(key => key.KeyName == "rollback-signing")
            .ToArrayAsync());
        Assert.Equal(VaultSigningKeyState.Active, onlyKey.SigningState);
        Assert.DoesNotContain(await database.VaultSigningKeyLifecycleOperations
                .ToArrayAsync(),
            item => item.OperationId == "failed-rotation");
    }

    [Fact]
    public async Task Dedicated_certificate_kek_round_trips_and_passes_readiness()
    {
        var directory = Directory.CreateTempSubdirectory("vault-kek-");
        try
        {
            const string password = "test-only-password";
            using var rsa = RSA.Create(3072);
            var request = new CertificateRequest(
                "CN=vault-kek.tests.local",
                rsa,
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pkcs1);
            using var certificate = request.CreateSelfSigned(
                DateTimeOffset.UtcNow.AddMinutes(-5),
                DateTimeOffset.UtcNow.AddDays(30));
            var path = Path.Combine(directory.FullName, "vault-kek.pfx");
            await File.WriteAllBytesAsync(
                path,
                certificate.Export(X509ContentType.Pfx, password));
            using var source = new CertificateKeySource(new VaultOptions
            {
                CertificatePath = path,
                CertificatePassword = password,
            });
            var plaintext = RandomNumberGenerator.GetBytes(32);
            var wrapped = source.Wrap(plaintext);

            Assert.Equal(plaintext, source.Unwrap(wrapped));
            var readiness = new VaultKekReadinessService(
                source,
                Microsoft.Extensions.Logging.Abstractions
                    .NullLogger<VaultKekReadinessService>.Instance);
            await readiness.StartAsync(CancellationToken.None);
        }
        finally
        {
            directory.Delete(recursive: true);
        }
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

    [Fact]
    public async Task Client_secret_resolver_rejects_plaintext_with_real_vault()
    {
        var (vault, _) = CreateRealVault();
        var resolver = new VaultBackedClientSecretResolver(vault);

        await Assert.ThrowsAsync<ClientSecretResolutionException>(
            async () => await resolver.ResolveAsync(
                "raw-client-secret-must-not-fall-back"));
    }

    // ---- Helpers ----

    private static (IKeyVault vault, IDbContextFactory<AppDbContext> dbFactory) CreateRealVault(
        VaultOptions? options = null,
        TimeProvider? timeProvider = null,
        Func<IDataProtectionProvider, IVaultKeyEncryptionKeySource>? keySourceFactory = null)
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
        options ??= new VaultOptions
        {
            Enabled = true,
            // RSA-3072 generation can take longer than one second on a CI
            // runner. Keep the default overlap comfortably above test
            // execution time; expiry behavior is covered with an explicit
            // short window in the lifecycle tests.
            SigningKeyOverlapSeconds = 300,
        };
        var kek = keySourceFactory?.Invoke(dpProvider)
            ?? new DataProtectionKeySource(dpProvider, options);
        var logger = provider.GetRequiredService<ILogger<KeyVault>>();
        IKeyVault vault = new KeyVault(
            dbFactory,
            kek,
            logger,
            options,
            timeProvider);
        return (vault, dbFactory);
    }

    private sealed class MutableTimeProvider(DateTimeOffset utcNow) : TimeProvider
    {
        private DateTimeOffset _utcNow = utcNow;

        public override DateTimeOffset GetUtcNow() => _utcNow;

        public void Advance(TimeSpan duration) => _utcNow += duration;
    }

    private sealed class FailingKeySource(IVaultKeyEncryptionKeySource inner)
        : IVaultKeyEncryptionKeySource
    {
        public bool FailWrap { get; set; }

        public string KeyIdentifier => "test:failable";

        public byte[] Wrap(ReadOnlyMemory<byte> dek) => FailWrap
            ? throw new CryptographicException("Simulated KEK loss.")
            : inner.Wrap(dek);

        public byte[] Unwrap(ReadOnlyMemory<byte> wrappedDek) =>
            inner.Unwrap(wrappedDek);
    }

    private sealed class XorExternalKeyEncryptionProvider(string keyIdentifier)
        : IVaultExternalKeyEncryptionProvider
    {
        public string KeyIdentifier => keyIdentifier;

        public byte[] Wrap(ReadOnlyMemory<byte> plaintextKey) =>
            plaintextKey.Span.ToArray().Select(value => (byte)(value ^ 0xA5)).ToArray();

        public byte[] Unwrap(ReadOnlyMemory<byte> wrappedKey) => Wrap(wrappedKey);
    }

    private sealed class AllowingManagementAuthorizationEvaluator
        : IManagementAuthorizationEvaluator
    {
        public ValueTask<ManagementAuthorizationDecision> EvaluateAsync(
            ClaimsPrincipal principal,
            string capability,
            ManagementResource resource,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult(
                ManagementAuthorizationDecision.Allowed());
        }
    }

    private sealed class DictionarySecretStore(
        IReadOnlyDictionary<string, string?> values) : ISecretStore
    {
        public List<string> RequestedNames { get; } = [];

        public Task<string?> GetSecretAsync(
            string name,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            RequestedNames.Add(name);
            values.TryGetValue(name, out var value);
            return Task.FromResult(value);
        }
    }
}
